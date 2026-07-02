package com.example.nexus.identity.infrastructure.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.AuthEventType;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * US-008 T-08-15 — basic correctness of the {@link BufferedAuthEvent} retry-state carrier.
 * Adversarial backoff-schedule-honoured-across-all-attempts scenarios belong to T-08-17.
 */
class BufferedAuthEventTest {

  private static final Instant ENQUEUED_AT = Instant.parse("2026-07-01T00:00:00Z");

  @Test
  void should_exposeAllComponents_when_constructed() {
    AuthEvent event = new AuthEvent(UUID.randomUUID(), AuthEventType.LOCKOUT, "FAILURE");
    Instant nextRetryAt = Instant.parse("2026-07-01T00:00:10Z");

    BufferedAuthEvent buffered = new BufferedAuthEvent(event, 2, nextRetryAt, ENQUEUED_AT);

    assertThat(buffered.event()).isSameAs(event);
    assertThat(buffered.attempts()).isEqualTo(2);
    assertThat(buffered.nextRetryAt()).isEqualTo(nextRetryAt);
    assertThat(buffered.enqueuedAt()).isEqualTo(ENQUEUED_AT);
  }

  @Test
  void should_incrementAttemptsAndAdvanceNextRetryAt_when_attemptFailed() {
    AuthEvent event = new AuthEvent(UUID.randomUUID(), AuthEventType.LOGIN_FAILURE, "FAILURE");
    BufferedAuthEvent original = new BufferedAuthEvent(event, 0, null, ENQUEUED_AT);
    Instant nextRetryAt = Instant.parse("2026-07-01T00:00:01Z");

    BufferedAuthEvent updated = original.withAttemptFailed(nextRetryAt);

    assertThat(updated.attempts()).isEqualTo(1);
    assertThat(updated.nextRetryAt()).isEqualTo(nextRetryAt);
    assertThat(updated.event()).isSameAs(event);
  }

  @Test
  void should_preserveEnqueuedAt_when_attemptFailedCalledRepeatedly() {
    AuthEvent event = new AuthEvent(UUID.randomUUID(), AuthEventType.LOGIN_FAILURE, "FAILURE");
    BufferedAuthEvent original = new BufferedAuthEvent(event, 0, null, ENQUEUED_AT);

    BufferedAuthEvent afterOneFailure =
        original.withAttemptFailed(Instant.parse("2026-07-01T00:00:01Z"));
    BufferedAuthEvent afterTwoFailures =
        afterOneFailure.withAttemptFailed(Instant.parse("2026-07-01T00:00:06Z"));

    assertThat(afterOneFailure.enqueuedAt()).isEqualTo(ENQUEUED_AT);
    assertThat(afterTwoFailures.enqueuedAt()).isEqualTo(ENQUEUED_AT);
  }

  @Test
  void should_leaveOriginalUnchanged_when_attemptFailedCalled() {
    AuthEvent event = new AuthEvent(UUID.randomUUID(), AuthEventType.LOGIN_FAILURE, "FAILURE");
    BufferedAuthEvent original = new BufferedAuthEvent(event, 3, Instant.EPOCH, ENQUEUED_AT);

    original.withAttemptFailed(Instant.parse("2026-07-01T00:01:00Z"));

    assertThat(original.attempts()).isEqualTo(3);
    assertThat(original.nextRetryAt()).isEqualTo(Instant.EPOCH);
  }

  @Test
  void should_returnFalse_when_nextRetryAtIsNull() {
    AuthEvent event = new AuthEvent(UUID.randomUUID(), AuthEventType.LOGIN_FAILURE, "FAILURE");
    BufferedAuthEvent buffered = new BufferedAuthEvent(event, 0, null, ENQUEUED_AT);

    assertThat(buffered.isNotYetDue(Instant.now())).isFalse();
  }

  @Test
  void should_returnTrue_when_nextRetryAtIsInTheFuture() {
    AuthEvent event = new AuthEvent(UUID.randomUUID(), AuthEventType.LOGIN_FAILURE, "FAILURE");
    Instant now = Instant.parse("2026-07-01T00:00:00Z");
    BufferedAuthEvent buffered = new BufferedAuthEvent(event, 1, now.plusSeconds(5), ENQUEUED_AT);

    assertThat(buffered.isNotYetDue(now)).isTrue();
  }

  @Test
  void should_returnFalse_when_nextRetryAtIsInThePastOrNow() {
    AuthEvent event = new AuthEvent(UUID.randomUUID(), AuthEventType.LOGIN_FAILURE, "FAILURE");
    Instant now = Instant.parse("2026-07-01T00:00:00Z");
    BufferedAuthEvent buffered = new BufferedAuthEvent(event, 1, now.minusSeconds(5), ENQUEUED_AT);

    assertThat(buffered.isNotYetDue(now)).isFalse();
  }

  @Test
  void should_produceEqualRecords_when_sameComponentsGiven() {
    UUID id = UUID.randomUUID();
    AuthEvent event = new AuthEvent(id, AuthEventType.LOCKOUT, "FAILURE");
    Instant nextRetryAt = Instant.parse("2026-07-01T00:00:00Z");

    BufferedAuthEvent first = new BufferedAuthEvent(event, 1, nextRetryAt, ENQUEUED_AT);
    BufferedAuthEvent second = new BufferedAuthEvent(event, 1, nextRetryAt, ENQUEUED_AT);

    assertThat(first).isEqualTo(second);
    assertThat(first.hashCode()).isEqualTo(second.hashCode());
  }

  @Test
  void should_includeAttempts_when_toStringCalled() {
    AuthEvent event = new AuthEvent(UUID.randomUUID(), AuthEventType.LOCKOUT, "FAILURE");
    BufferedAuthEvent buffered = new BufferedAuthEvent(event, 4, Instant.EPOCH, ENQUEUED_AT);

    String text = buffered.toString();

    assertThat(text).contains("4");
  }
}
