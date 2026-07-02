package com.example.nexus.identity.infrastructure.audit;

import com.example.nexus.identity.domain.AuthEvent;
import java.time.Instant;

/**
 * US-008 T-08-15 (design §4.2) — retry state for a single {@link AuthEvent} sitting in one of
 * {@link AuthEventRetryBuffer}'s two lanes. Immutable: retry state is carried in the record
 * itself, in the queue, rather than in a separate side-table keyed by event id — a failed attempt
 * produces a new instance via {@link #withAttemptFailed(Instant)} rather than mutating in place.
 *
 * <p>{@code enqueuedAt} is tracked explicitly here rather than read from {@code
 * AuthEvent.createdAt}: that JPA column is {@code insertable = false, updatable = false} (design
 * §3.1) and is only populated by the database after a successful insert — an event sitting in
 * this buffer has, by definition, not yet had a successful insert, so {@code getCreatedAt()}
 * would be {@code null} for every buffered event. {@code enqueuedAt} is this buffer's own
 * age-tracking clock reading, taken once at {@link AuthEventRetryBuffer#enqueue} time.
 *
 * @param event the underlying audit event, unchanged across retries (same UUIDv7 id — design
 *     §10.1 idempotency)
 * @param attempts number of retry attempts already made (0 = never yet retried)
 * @param nextRetryAt the earliest instant at which {@link AuthEventRetryBuffer#drain()} should
 *     next attempt this event; {@code null} means "due immediately" (first enqueue)
 * @param enqueuedAt the instant this event first entered the buffer — used for the {@code
 *     oldest.age.seconds} gauge; never changed across retries
 */
record BufferedAuthEvent(AuthEvent event, int attempts, Instant nextRetryAt, Instant enqueuedAt) {

  /**
   * Returns a new {@link BufferedAuthEvent} for the same underlying event with {@code attempts}
   * incremented and the next-retry instant advanced per the configured backoff schedule.
   * {@code enqueuedAt} is preserved unchanged — age is measured from first entry, not from the
   * most recent retry.
   */
  BufferedAuthEvent withAttemptFailed(Instant nextRetryAt) {
    return new BufferedAuthEvent(event, attempts + 1, nextRetryAt, enqueuedAt);
  }

  /** {@code true} when this event has not yet reached its next scheduled retry instant. */
  boolean isNotYetDue(Instant now) {
    return nextRetryAt != null && nextRetryAt.isAfter(now);
  }
}
