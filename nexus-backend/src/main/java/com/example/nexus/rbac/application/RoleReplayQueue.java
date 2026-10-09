package com.example.nexus.rbac.application;

import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Bounded, coalescing queue of roles whose post-commit holder read failed twice (US-018 M7 part 2
 * review M-2). Package-private collaborator of {@link PermissionFreshnessService}: the scheduler
 * tick re-reads the holders of a queued role and bumps them, so a detach whose request thread
 * could not read its holders is not lost.
 *
 * <ul>
 *   <li>Keyed by {@code (tenantId, roleId)}: a role queued repeatedly takes one slot. The slot
 *       keeps the oldest and the newest failure time; expiry compares the newest, the same rule as
 *       {@link EpochReplayQueue}.
 *   <li>Bounded by {@code capacity} distinct roles. {@link #offer} refuses a new role beyond it.
 *   <li>Thread-safe: request threads {@link #offer}, the scheduler {@link #poll}s. A polled entry
 *       is out of the queue, so it is {@link #requeue}d if its replay fails.
 * </ul>
 */
final class RoleReplayQueue {

  private final int capacity;
  // Guarded by `this`; insertion-ordered, so the oldest role is polled first.
  private final Map<RoleKey, Times> roles = new LinkedHashMap<>();

  /**
   * Creates the queue.
   *
   * @param capacity the most distinct roles held at once
   * @throws IllegalArgumentException if {@code capacity} is below 1
   */
  RoleReplayQueue(int capacity) {
    if (capacity < 1) {
      throw new IllegalArgumentException("role replay capacity must be positive");
    }
    this.capacity = capacity;
  }

  /**
   * Queues a role whose holders could not be read, coalescing with an entry already queued.
   *
   * @param tenantId the role's tenant
   * @param roleId the role
   * @param failedAt when the read failed
   * @return {@code false} if the role is new and the queue is full (the role is not queued)
   */
  synchronized boolean offer(UUID tenantId, UUID roleId, Instant failedAt) {
    RoleKey key = new RoleKey(tenantId, roleId);
    Times queued = roles.get(key);
    if (queued != null) {
      roles.put(key, queued.merge(failedAt, failedAt));
      return true;
    }
    if (roles.size() >= capacity) {
      return false;
    }
    roles.put(key, new Times(failedAt, failedAt));
    return true;
  }

  /**
   * Removes the oldest queued role. Roles whose <b>newest</b> failure is at or before {@code
   * expiredAtOrBefore} are discarded on the way: every token and cache entry that the lost
   * revocation could have outlived has expired.
   *
   * @param expiredAtOrBefore entries with {@code newestFailedAt} not after this are discarded
   * @return the entry, or empty when nothing live is queued
   */
  synchronized Optional<Entry> poll(Instant expiredAtOrBefore) {
    Iterator<Map.Entry<RoleKey, Times>> it = roles.entrySet().iterator();
    while (it.hasNext()) {
      Map.Entry<RoleKey, Times> next = it.next();
      it.remove();
      if (next.getValue().newest().isAfter(expiredAtOrBefore)) {
        RoleKey key = next.getKey();
        return Optional.of(new Entry(
            key.tenantId(), key.roleId(), next.getValue().oldest(), next.getValue().newest()));
      }
    }
    return Optional.empty();
  }

  /**
   * Puts a polled entry back after its replay failed, keeping its failure times. It ignores the
   * capacity: the role held a slot until a moment ago, and losing it here would lose a revocation.
   * It goes to the back, so one role that keeps failing cannot starve the others.
   *
   * @param entry the entry returned by {@link #poll}
   */
  synchronized void requeue(Entry entry) {
    RoleKey key = new RoleKey(entry.tenantId(), entry.roleId());
    Times queued = roles.get(key);
    roles.put(
        key,
        queued == null
            ? new Times(entry.oldestFailedAt(), entry.newestFailedAt())
            : queued.merge(entry.oldestFailedAt(), entry.newestFailedAt()));
  }

  /** Returns the number of distinct roles queued. */
  synchronized int size() {
    return roles.size();
  }

  /** Returns whether nothing is queued. */
  synchronized boolean isEmpty() {
    return roles.isEmpty();
  }

  private record RoleKey(UUID tenantId, UUID roleId) {}

  private record Times(Instant oldest, Instant newest) {

    Times merge(Instant otherOldest, Instant otherNewest) {
      return new Times(
          otherOldest.isBefore(oldest) ? otherOldest : oldest,
          otherNewest.isAfter(newest) ? otherNewest : newest);
    }
  }

  /** One queued role: when its first and its latest holder read failed. */
  record Entry(UUID tenantId, UUID roleId, Instant oldestFailedAt, Instant newestFailedAt) {}
}
