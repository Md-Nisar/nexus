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
 *   <li>Keyed by {@code (tenantId, userId)}: a user queued repeatedly takes one slot, so capacity
 *       counts distinct users. The slot keeps the <b>oldest</b> failure time (the replay's {@code
 *       ageMs}) and the <b>newest</b> one. Expiry compares the newest: a token minted just before
 *       the last lost bump is still valid for a full key TTL, so a coalesced user is dropped only
 *       once every one of their lost bumps is older than that.
 *   <li>Bounded by {@code capacity} distinct users, and by {@code tenantCapacity} per tenant.
 *       {@link #offer} drops the <b>newest</b> arrivals beyond either and reports how many.
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
  private final int tenantCapacity;
  // Guarded by `this`. Outer key: tenant; inner key: user -> oldest and newest failedAt.
  private final Map<UUID, Map<UUID, Times>> byTenant = new LinkedHashMap<>();
  private int size;

  /**
   * Creates the queue.
   *
   * @param capacity the most distinct users held at once
   * @throws IllegalArgumentException if {@code capacity} is below 1
   */
  EpochReplayQueue(int capacity) {
    this(capacity, capacity);
  }

  /**
   * Creates the queue with a share per tenant, so that one tenant's failed fan-out overflows
   * itself and not the others (pre-PR security review L-2).
   *
   * @param capacity the most distinct users held at once
   * @param tenantCapacity the most distinct users of one tenant held at once
   * @throws IllegalArgumentException if either is below 1
   */
  EpochReplayQueue(int capacity, int tenantCapacity) {
    if (capacity < 1 || tenantCapacity < 1) {
      throw new IllegalArgumentException("replay capacity must be positive");
    }
    this.capacity = capacity;
    this.tenantCapacity = tenantCapacity;
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
    Map<UUID, Times> users = byTenant.computeIfAbsent(tenantId, id -> new LinkedHashMap<>());
    int dropped = 0;
    for (UUID userId : userIds) {
      Times queued = users.get(userId);
      if (queued != null) {
        users.put(userId, queued.merge(failedAt, failedAt));
      } else if (size < capacity && users.size() < tenantCapacity) {
        users.put(userId, new Times(failedAt, failedAt));
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
   * Removes up to {@code max} users of one tenant. Entries whose <b>newest</b> failure is at or
   * before {@code expiredAtOrBefore} are removed and discarded on the way: every token and cache
   * entry that a lost bump could have outdated has expired.
   *
   * @param max the most users in the batch
   * @param expiredAtOrBefore entries with {@code newestFailedAt} not after this are discarded
   * @return the batch, or empty when nothing live is queued
   */
  synchronized Optional<Batch> poll(int max, Instant expiredAtOrBefore) {
    while (!byTenant.isEmpty()) {
      Map.Entry<UUID, Map<UUID, Times>> first = byTenant.entrySet().iterator().next();
      List<Entry> taken = new ArrayList<>();
      Iterator<Map.Entry<UUID, Times>> it = first.getValue().entrySet().iterator();
      while (it.hasNext() && taken.size() < max) {
        Map.Entry<UUID, Times> user = it.next();
        it.remove();
        size--;
        if (user.getValue().newest().isAfter(expiredAtOrBefore)) {
          taken.add(new Entry(
              first.getKey(), user.getKey(), user.getValue().oldest(), user.getValue().newest()));
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
   * Puts a polled batch back after its replay failed, keeping each entry's original failure times. It
   * ignores the capacity: these users held slots until a moment ago, and losing one here would
   * lose a bump for good. The queue can therefore exceed its capacity by one batch until the next
   * drain; {@link #offer} refuses new users meanwhile.
   *
   * @param batch the batch returned by {@link #poll}
   */
  synchronized void requeue(Batch batch) {
    Map<UUID, Times> users =
        byTenant.computeIfAbsent(batch.tenantId(), id -> new LinkedHashMap<>());
    for (Entry entry : batch.entries()) {
      Times queued = users.get(entry.userId());
      if (queued == null) {
        users.put(entry.userId(), new Times(entry.oldestFailedAt(), entry.newestFailedAt()));
        size++;
      } else {
        users.put(entry.userId(), queued.merge(entry.oldestFailedAt(), entry.newestFailedAt()));
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

  /** The oldest and newest failure time of one queued user. */
  private record Times(Instant oldest, Instant newest) {

    Times merge(Instant otherOldest, Instant otherNewest) {
      return new Times(
          otherOldest.isBefore(oldest) ? otherOldest : oldest,
          otherNewest.isAfter(newest) ? otherNewest : newest);
    }
  }

  /** One queued user: when their first and their latest lost bump failed. */
  record Entry(UUID tenantId, UUID userId, Instant oldestFailedAt, Instant newestFailedAt) {}

  /**
   * Users of a single tenant, taken from the queue for one replay.
   *
   * @param tenantId the tenant
   * @param entries the users with their original failure times; never empty
   */
  record Batch(UUID tenantId, List<Entry> entries) {

    /** Returns the users, in queue order. */
    List<UUID> userIds() {
      return entries.stream().map(Entry::userId).toList();
    }

    /** Returns the earliest first-failure time in the batch. */
    Instant oldestFailedAt() {
      return entries.stream().map(Entry::oldestFailedAt).min(Instant::compareTo).orElseThrow();
    }
  }
}
