package com.example.nexus.rbac.application;

import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
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

  private static final Duration DEFAULT_MAX_RETENTION = Duration.ofHours(1);

  private final int capacity;
  private final int tenantCapacity;
  private final int borrowLimit;
  private final Duration maxRetention;
  private final RoleReplayStore store;
  // Guarded by `this`; insertion-ordered, so the oldest role is polled first.
  private final Map<RoleKey, Times> roles = new LinkedHashMap<>();

  /**
   * Creates the queue.
   *
   * @param capacity the most distinct roles held at once
   * @throws IllegalArgumentException if {@code capacity} is below 1
   */
  RoleReplayQueue(int capacity) {
    this(capacity, capacity, DEFAULT_MAX_RETENTION, null);
  }

  RoleReplayQueue(int capacity, int tenantCapacity) {
    this(capacity, tenantCapacity, DEFAULT_MAX_RETENTION, null);
  }

  RoleReplayQueue(int capacity, int tenantCapacity, Duration maxRetention) {
    this(capacity, tenantCapacity, maxRetention, null);
  }

  /**
   * Creates the queue with a share per tenant, a maximum retention TTL, and optional persistence store.
   *
   * @param capacity the most distinct roles held at once
   * @param tenantCapacity the most distinct roles of one tenant held at once
   * @param maxRetention maximum duration an entry may remain queued before eviction
   * @param store optional persistence store backing the queue across restarts
   * @throws IllegalArgumentException if either capacity is below 1 or maxRetention is not positive
   */
  RoleReplayQueue(
      int capacity,
      int tenantCapacity,
      Duration maxRetention,
      RoleReplayStore store) {
    if (capacity < 1 || tenantCapacity < 1) {
      throw new IllegalArgumentException("role replay capacity must be positive");
    }
    if (maxRetention == null || !maxRetention.isPositive()) {
      throw new IllegalArgumentException("max retention must be positive");
    }
    this.capacity = capacity;
    this.tenantCapacity = tenantCapacity;
    this.borrowLimit = Math.max(tenantCapacity, capacity / 2);
    this.maxRetention = maxRetention;
    this.store = store;
    if (store != null) {
      List<Entry> loaded = store.loadAll();
      if (loaded != null) {
        for (Entry e : loaded) {
          roles.put(
              new RoleKey(e.tenantId(), e.roleId()),
              new Times(e.oldestFailedAt(), e.newestFailedAt(), e.attempts(), e.lastAttemptAt()));
        }
      }
    }
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
    evictStale(failedAt.minus(maxRetention));
    RoleKey key = new RoleKey(tenantId, roleId);
    Times queued = roles.get(key);
    if (queued != null) {
      Times merged = queued.merge(failedAt, failedAt);
      roles.put(key, merged);
      if (store != null) {
        store.save(tenantId, roleId, merged.oldest(), merged.newest());
      }
      return true;
    }
    if (roles.size() >= capacity) {
      return false;
    }
    // Over its share, a tenant may borrow only while the queue is under half full.
    if (roles.size() >= borrowLimit && queuedFor(tenantId) >= tenantCapacity) {
      return false;
    }
    Times created = new Times(failedAt, failedAt, 0, null);
    roles.put(key, created);
    if (store != null) {
      store.save(tenantId, roleId, created.oldest(), created.newest());
    }
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
    return poll(Instant.MAX, expiredAtOrBefore);
  }

  /**
   * Removes the oldest queued role eligible for retry under backoff.
   *
   * @param now current time for evaluating retry backoff
   * @param expiredAtOrBefore entries with {@code newestFailedAt} not after this are discarded
   * @return the entry, or empty when nothing live and eligible is queued
   */
  synchronized Optional<Entry> poll(Instant now, Instant expiredAtOrBefore) {
    Iterator<Map.Entry<RoleKey, Times>> it = roles.entrySet().iterator();
    while (it.hasNext()) {
      Map.Entry<RoleKey, Times> next = it.next();
      if (!next.getValue().newest().isAfter(expiredAtOrBefore)) {
        if (store != null) {
          store.remove(next.getKey().tenantId(), next.getKey().roleId());
        }
        it.remove();
        continue;
      }
      RoleKey key = next.getKey();
      Entry entry = new Entry(
          key.tenantId(),
          key.roleId(),
          next.getValue().oldest(),
          next.getValue().newest(),
          next.getValue().attempts(),
          next.getValue().lastAttemptAt());
      if (entry.isEligibleForRetry(now)) {
        if (store != null) {
          store.remove(key.tenantId(), key.roleId());
        }
        it.remove();
        return Optional.of(entry);
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
    requeue(entry, entry.newestFailedAt());
  }

  /**
   * Puts a polled entry back after its replay failed, recording the attempt timestamp.
   *
   * @param entry the entry returned by {@link #poll}
   * @param attemptedAt timestamp when the replay attempt failed
   */
  synchronized void requeue(Entry entry, Instant attemptedAt) {
    RoleKey key = new RoleKey(entry.tenantId(), entry.roleId());
    Times queued = roles.get(key);
    int newAttempts = entry.attempts() + 1;
    Times updated;
    if (queued == null) {
      updated = new Times(
          entry.oldestFailedAt(), entry.newestFailedAt(), newAttempts, attemptedAt);
      roles.put(key, updated);
    } else {
      updated = new Times(
          entry.oldestFailedAt().isBefore(queued.oldest())
              ? entry.oldestFailedAt() : queued.oldest(),
          entry.newestFailedAt().isAfter(queued.newest())
              ? entry.newestFailedAt() : queued.newest(),
          Math.max(queued.attempts(), newAttempts),
          attemptedAt);
      roles.put(key, updated);
    }
    if (store != null) {
      store.save(entry.tenantId(), entry.roleId(), updated.oldest(), updated.newest());
    }
  }

  /** Bounded by the capacity, at most 1,000 in practice, and only reached for a new role. */
  private int queuedFor(UUID tenantId) {
    int count = 0;
    for (RoleKey key : roles.keySet()) {
      if (key.tenantId().equals(tenantId)) {
        count++;
      }
    }
    return count;
  }

  /** Returns the number of distinct roles queued. */
  synchronized int size() {
    return roles.size();
  }

  /** Evicts entries whose newest failure is at or before {@code expiredAtOrBefore}. */
  synchronized int evictStale(Instant expiredAtOrBefore) {
    int evicted = 0;
    Iterator<Map.Entry<RoleKey, Times>> it = roles.entrySet().iterator();
    while (it.hasNext()) {
      Map.Entry<RoleKey, Times> next = it.next();
      if (!next.getValue().newest().isAfter(expiredAtOrBefore)) {
        if (store != null) {
          store.remove(next.getKey().tenantId(), next.getKey().roleId());
        }
        it.remove();
        evicted++;
      }
    }
    return evicted;
  }

  /** Returns whether nothing is queued. */
  synchronized boolean isEmpty() {
    return roles.isEmpty();
  }

  private record RoleKey(UUID tenantId, UUID roleId) {}

  private record Times(
      Instant oldest, Instant newest, int attempts, Instant lastAttemptAt) {

    Times merge(Instant otherOldest, Instant otherNewest) {
      return new Times(
          otherOldest.isBefore(oldest) ? otherOldest : oldest,
          otherNewest.isAfter(newest) ? otherNewest : newest,
          this.attempts,
          this.lastAttemptAt);
    }
  }

  /** One queued role: failure window and backoff state. */
  record Entry(
      UUID tenantId,
      UUID roleId,
      Instant oldestFailedAt,
      Instant newestFailedAt,
      int attempts,
      Instant lastAttemptAt) {

    Entry(UUID tenantId, UUID roleId, Instant oldestFailedAt, Instant newestFailedAt) {
      this(tenantId, roleId, oldestFailedAt, newestFailedAt, 0, null);
    }

    Duration backoffDuration() {
      long seconds = Math.min(60, (long) Math.pow(2, attempts));
      return Duration.ofSeconds(seconds);
    }

    boolean isEligibleForRetry(Instant now) {
      if (lastAttemptAt == null || attempts == 0) {
        return true;
      }
      return !now.isBefore(lastAttemptAt.plus(backoffDuration()));
    }
  }

  /** Persistence store contract for backing RoleReplayQueue entries across restarts (OR-15). */
  interface RoleReplayStore {
    void save(UUID tenantId, UUID roleId, Instant oldestFailedAt, Instant newestFailedAt);
    void remove(UUID tenantId, UUID roleId);
    List<Entry> loadAll();
  }
}
