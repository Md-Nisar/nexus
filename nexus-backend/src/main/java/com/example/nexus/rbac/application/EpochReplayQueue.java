package com.example.nexus.rbac.application;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Bounded, coalescing queue of permission-epoch bumps that Redis refused (US-018 T-012, design
 * §9.3). Package-private collaborator of {@link PermissionFreshnessService}.
 *
 * <ul>
 *   <li>Keyed by {@code (tenantId, userId)}: a user queued repeatedly takes one slot and keeps the
 *       <b>oldest</b> {@code failedAt}, so capacity counts distinct users and drop-by-age never
 *       discards an entry whose earliest lost bump may still matter.
 *   <li>Bounded by {@code capacity} distinct users. {@link #offer} drops the <b>newest</b> arrivals
 *       beyond it and reports how many.
 *   <li>Thread-safe: request threads {@link #offer}, the scheduler {@link #poll}s. A polled batch
 *       is out of the queue, so it is {@link #requeue}d if its replay fails; an entry enqueued for
 *       the same user meanwhile coalesces with it.
 * </ul>
 *
 * <p>Entries are grouped per tenant, in first-insertion order, so one {@link #poll} costs
 * O(batch) however many tenants are queued.
 */
final class EpochReplayQueue {

  private final int capacity;
  // Guarded by `this`. Outer key: tenant; inner key: user -> oldest failedAt.
  private final Map<UUID, Map<UUID, Instant>> byTenant = new LinkedHashMap<>();
  private int size;

  /**
   * Creates the queue.
   *
   * @param capacity the most distinct users held at once
   * @throws IllegalArgumentException if {@code capacity} is below 1
   */
  EpochReplayQueue(int capacity) {
    if (capacity < 1) {
      throw new IllegalArgumentException("replay capacity must be positive");
    }
    this.capacity = capacity;
  }

  /**
   * Queues users whose bump failed, coalescing with entries already queued.
   *
   * @param tenantId the users' tenant
   * @param userIds the users
   * @param failedAt when the bump failed
   * @return the number of users dropped because the queue was full (the newest arrivals)
   */
  synchronized int offer(UUID tenantId, Collection<UUID> userIds, Instant failedAt) {
    Map<UUID, Instant> users = byTenant.computeIfAbsent(tenantId, id -> new LinkedHashMap<>());
    int dropped = 0;
    for (UUID userId : userIds) {
      Instant queued = users.get(userId);
      if (queued != null) {
        if (failedAt.isBefore(queued)) {
          users.put(userId, failedAt);
        }
      } else if (size < capacity) {
        users.put(userId, failedAt);
        size++;
      } else {
        dropped++;
      }
    }
    if (users.isEmpty()) {
      byTenant.remove(tenantId);
    }
    return dropped;
  }

  /**
   * Removes up to {@code max} users of one tenant. Entries that failed at or before
   * {@code expiredAtOrBefore} are removed and discarded on the way: their tokens and cache entries
   * have expired.
   *
   * @param max the most users in the batch
   * @param expiredAtOrBefore entries with {@code failedAt} not after this are discarded
   * @return the batch, or empty when nothing live is queued
   */
  synchronized Optional<Batch> poll(int max, Instant expiredAtOrBefore) {
    while (!byTenant.isEmpty()) {
      Map.Entry<UUID, Map<UUID, Instant>> first = byTenant.entrySet().iterator().next();
      List<Entry> taken = new ArrayList<>();
      Iterator<Map.Entry<UUID, Instant>> it = first.getValue().entrySet().iterator();
      while (it.hasNext() && taken.size() < max) {
        Map.Entry<UUID, Instant> user = it.next();
        it.remove();
        size--;
        if (user.getValue().isAfter(expiredAtOrBefore)) {
          taken.add(new Entry(first.getKey(), user.getKey(), user.getValue()));
        }
      }
      if (first.getValue().isEmpty()) {
        byTenant.remove(first.getKey());
      }
      if (!taken.isEmpty()) {
        return Optional.of(new Batch(first.getKey(), List.copyOf(taken)));
      }
    }
    return Optional.empty();
  }

  /**
   * Puts a polled batch back after its replay failed, keeping each original {@code failedAt}. It
   * ignores the capacity: these users held slots until a moment ago, and losing one here would
   * lose a bump for good. The queue can therefore exceed its capacity by one batch until the next
   * drain; {@link #offer} refuses new users meanwhile.
   *
   * @param batch the batch returned by {@link #poll}
   */
  synchronized void requeue(Batch batch) {
    Map<UUID, Instant> users =
        byTenant.computeIfAbsent(batch.tenantId(), id -> new LinkedHashMap<>());
    for (Entry entry : batch.entries()) {
      Instant queued = users.get(entry.userId());
      if (queued == null) {
        users.put(entry.userId(), entry.failedAt());
        size++;
      } else if (entry.failedAt().isBefore(queued)) {
        users.put(entry.userId(), entry.failedAt());
      }
    }
  }

  /** Returns the number of distinct users queued. */
  synchronized int size() {
    return size;
  }

  /** Returns whether nothing is queued. */
  synchronized boolean isEmpty() {
    return size == 0;
  }

  /** One queued user. */
  record Entry(UUID tenantId, UUID userId, Instant failedAt) {}

  /**
   * Users of a single tenant, taken from the queue for one replay.
   *
   * @param tenantId the tenant
   * @param entries the users with their original {@code failedAt}; never empty
   */
  record Batch(UUID tenantId, List<Entry> entries) {

    /** Returns the users, in queue order. */
    List<UUID> userIds() {
      return entries.stream().map(Entry::userId).toList();
    }

    /** Returns the earliest {@code failedAt} in the batch. */
    Instant oldestFailedAt() {
      return entries.stream().map(Entry::failedAt).min(Instant::compareTo).orElseThrow();
    }
  }
}
