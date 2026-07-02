package com.example.nexus.identity.infrastructure.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.application.port.out.AuditAlertPort;
import com.example.nexus.identity.domain.AuditAlert;
import com.example.nexus.identity.domain.AuditAlertType;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.AuthEventType;
import com.example.nexus.identity.infrastructure.persistence.JpaAuthEventRepository;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.dao.DataAccessResourceFailureException;

/**
 * US-008 T-08-17 — adversarial/concurrency-adjacent unit tests for {@link AuthEventRetryBuffer},
 * split out from {@link AuthEventRetryBufferTest} (T-08-15's basic-wiring suite) per this repo's
 * "basic vs adversarial" test-file convention (see {@code SecureEventServiceTest} /
 * {@code SecureEventServiceConcurrencyTest}).
 *
 * <p>Covers the threat-model rows this buffer's design was explicitly reviewed against
 * (`docs/features/US-008/03b-threat-model.md`):
 *
 * <ul>
 *   <li><b>T-D1</b> — a sustained standard-lane-only flood never reduces the priority lane's
 *       available capacity and never evicts a priority-lane entry.
 *   <li><b>T-D2</b> — bounded overflow is drop-newest (not drop-oldest), with exact per-lane
 *       accounting and no unbounded growth under a sustained flood.
 *   <li><b>T-D4</b> — a {@code drain()} iteration (or a single lane's item) that throws does not
 *       propagate and does not stop the scheduler from processing normally on a later tick.
 *   <li>Backoff-schedule honoured across all 5 attempts (1s → 5s → 30s → 2m → 10m).
 *   <li>{@code RETRY_EXHAUSTED} alert fires at attempt 5 exactly, never before.
 *   <li>Idempotency (design §10.1, buffer-side half): the same {@code AuthEvent} id/instance is
 *       what gets re-{@code save()}d on retry — no new identity is minted.
 * </ul>
 *
 * <p><b>Concurrency-testing technique (deliberate choice, not an oversight):</b> all "flood" and
 * "sustained" scenarios below use single-threaded, sequential {@code enqueue()}/{@code drain()}
 * calls. {@link java.util.concurrent.ArrayBlockingQueue#offer} is already thread-safe by JDK
 * contract; what T-D1/T-D2 actually require proving is this class's own lane-routing and
 * accounting logic, which is fully observable deterministically without a real race. This mirrors
 * the existing {@code SecureEventServiceConcurrencyTest} precedent, which is itself single-
 * threaded despite its name. The one genuinely concurrent race noted in {@code
 * AuthEventRetryBuffer#requeueOrDrop}'s Javadoc (a concurrent {@code enqueue} racing a drain-time
 * requeue for the same freed slot) is deliberately not exercised with a real {@code
 * ExecutorService} here — it would only re-prove the JDK's own {@code offer()} guarantee under
 * contention, not additional logic of ours, and was explicitly scoped out as not worth the added
 * flakiness risk.
 */
@ExtendWith(MockitoExtension.class)
class AuthEventRetryBufferAdversarialTest {

  private static final Instant FIXED_NOW = Instant.parse("2026-07-01T00:00:00Z");

  @Mock private JpaAuthEventRepository repository;
  @Mock private AuditAlertPort alertPort;

  @BeforeEach
  void setUp() {
    // Each test constructs its own buffer with the exact capacity/backoff shape it needs —
    // no shared mutable fixture, since these tests deliberately vary capacity and clock.
  }

  // ==== T-D1: standard-lane-only flood never touches priority-lane capacity =================

  @Test
  void should_neverReducePriorityLaneAvailableCapacity_when_standardLaneFloodedPastCapacity() {
    AuditRetryProperties props = capacityProperties(3, 3);
    AuthEventRetryBuffer buffer = newBuffer(props, fixedClock());

    // Flood the standard lane well past its capacity of 3.
    for (int i = 0; i < 10; i++) {
      buffer.enqueue(standardEvent());
    }
    assertThat(buffer.depth(AuditLane.STANDARD)).isEqualTo(3);

    // Priority lane, having never been touched by the flood, still has its full capacity free.
    assertThat(buffer.enqueue(priorityEvent())).isTrue();
    assertThat(buffer.enqueue(priorityEvent())).isTrue();
    assertThat(buffer.enqueue(priorityEvent())).isTrue();
    assertThat(buffer.depth(AuditLane.PRIORITY)).isEqualTo(3);
  }

  @Test
  void should_stillEnqueuePriorityEvent_when_standardLaneSaturatedDuringSustainedFlood() {
    AuditRetryProperties props = capacityProperties(2, 2);
    AuthEventRetryBuffer buffer = newBuffer(props, fixedClock());

    // Saturate the standard lane first.
    buffer.enqueue(standardEvent());
    buffer.enqueue(standardEvent());
    assertThat(buffer.depth(AuditLane.STANDARD)).isEqualTo(2);

    // Interleave further standard-lane flood attempts with priority enqueues: every extra
    // standard attempt is rejected, every priority attempt (up to its own capacity) succeeds.
    assertThat(buffer.enqueue(standardEvent())).isFalse();
    assertThat(buffer.enqueue(priorityEvent())).isTrue();
    assertThat(buffer.enqueue(standardEvent())).isFalse();
    assertThat(buffer.enqueue(priorityEvent())).isTrue();
    assertThat(buffer.enqueue(standardEvent())).isFalse();

    assertThat(buffer.depth(AuditLane.PRIORITY)).isEqualTo(2);
    assertThat(buffer.depth(AuditLane.STANDARD)).isEqualTo(2);
  }

  @Test
  void should_neverEvictExistingPriorityEntry_when_standardFloodOccursWithPriorityLaneAtCapacity() {
    AuditRetryProperties props = capacityProperties(2, 2);
    AuthEventRetryBuffer buffer = newBuffer(props, fixedClock());

    // Fill the priority lane to its own capacity first.
    buffer.enqueue(priorityEvent());
    buffer.enqueue(priorityEvent());
    assertThat(buffer.depth(AuditLane.PRIORITY)).isEqualTo(2);

    // Heavily flood the standard lane afterward — this must not disturb the priority lane at all.
    for (int i = 0; i < 20; i++) {
      buffer.enqueue(standardEvent());
    }
    assertThat(buffer.depth(AuditLane.PRIORITY)).isEqualTo(2);

    // Prove the original 2 priority entries are still exactly what's there (not silently
    // replaced) by draining and asserting the repository sees exactly 2 priority saves.
    when(repository.save(any(AuthEvent.class))).thenReturn(null);
    buffer.drain();

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(repository, times(2 + 2)).save(captor.capture()); // 2 priority + 2 standard saved
    long priorityWireName = captor.getAllValues().stream()
        .filter(e -> AuthEventType.LOCKOUT.wireName().equals(e.getEventType()))
        .count();
    assertThat(priorityWireName).isEqualTo(2);
    assertThat(buffer.depth(AuditLane.PRIORITY)).isZero();
  }

  // ==== T-D2: bounded overflow — drop-newest, exact accounting, no unbounded growth =========

  @Test
  void should_dropNewestNotOldest_when_lanePersistentlyOverCapacity() {
    AuditRetryProperties props = capacityProperties(200, 3);
    AuthEventRetryBuffer buffer = newBuffer(props, fixedClock());

    AuthEvent first = standardEvent();
    AuthEvent second = standardEvent();
    AuthEvent third = standardEvent();
    AuthEvent rejected = standardEvent();

    assertThat(buffer.enqueue(first)).isTrue();
    assertThat(buffer.enqueue(second)).isTrue();
    assertThat(buffer.enqueue(third)).isTrue();
    assertThat(buffer.enqueue(rejected)).isFalse(); // the lane is full — this one is dropped

    when(repository.save(any(AuthEvent.class))).thenReturn(null);
    buffer.drain();

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(repository, times(3)).save(captor.capture());
    List<UUID> savedIds = captor.getAllValues().stream().map(AuthEvent::getId).toList();

    assertThat(savedIds)
        .contains(first.getId(), second.getId(), third.getId())
        .doesNotContain(rejected.getId());
  }

  @Test
  void should_neverExceedConfiguredCapacity_when_enqueueCalledManyTimesPastLimit() {
    AuditRetryProperties props = capacityProperties(5, 5);
    AuthEventRetryBuffer buffer = newBuffer(props, fixedClock());

    for (int i = 0; i < 50; i++) {
      buffer.enqueue(standardEvent());
      // Depth must never exceed capacity at any point during the flood, not just at the end.
      assertThat(buffer.depth(AuditLane.STANDARD)).isLessThanOrEqualTo(5);
    }
    assertThat(buffer.depth(AuditLane.STANDARD)).isEqualTo(5);
  }

  @Test
  void should_incrementDroppedCounterOncePerRejectedEnqueue_when_floodedPastCapacity() {
    AuditRetryProperties props = capacityProperties(200, 4);
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    AuthEventRetryBuffer buffer = newBuffer(props, fixedClock(), registry);

    int totalAttempts = 30;
    int excess = totalAttempts - 4; // capacity 4, so 26 of the 30 attempts must be rejected
    for (int i = 0; i < totalAttempts; i++) {
      buffer.enqueue(standardEvent());
    }

    double dropped =
        registry.get("nexus.audit.buffer.dropped")
            .tag("lane", "standard")
            .tag("reason", "overflow")
            .counter()
            .count();
    assertThat(dropped).isEqualTo((double) excess);
  }

  @Test
  void should_rejectOnlyIncomingEvent_when_enqueueRejected() {
    AuditRetryProperties props = capacityProperties(200, 1);
    AuthEventRetryBuffer buffer = newBuffer(props, fixedClock());

    assertThat(buffer.enqueue(standardEvent())).isTrue();
    assertThat(buffer.depth(AuditLane.STANDARD)).isEqualTo(1);

    boolean secondResult = buffer.enqueue(standardEvent());

    assertThat(secondResult).isFalse();
    // Depth stays exactly at capacity — the already-queued item was not evicted to make room.
    assertThat(buffer.depth(AuditLane.STANDARD)).isEqualTo(1);
  }

  // ==== T-D4: drainer survives exceptions across ticks and within a tick =====================

  @Test
  void should_processNormally_when_secondDrainTickRunsAfterFirstTickThrew() {
    MutableClock clock = new MutableClock(FIXED_NOW);
    AuditRetryProperties props = defaultCapacityProperties();
    AuthEventRetryBuffer buffer = newBuffer(props, clock);

    buffer.enqueue(standardEvent());
    when(repository.save(any(AuthEvent.class)))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    assertThatCode(buffer::drain).doesNotThrowAnyException();
    assertThat(buffer.depth(AuditLane.STANDARD)).isEqualTo(1); // requeued, not lost

    // Second tick: DB has recovered and the backoff window has elapsed.
    clock.advanceSeconds(2); // past the 1s first-attempt backoff
    when(repository.save(any(AuthEvent.class))).thenReturn(null);

    buffer.drain();

    assertThat(buffer.depth(AuditLane.STANDARD)).isZero();
    verify(repository, times(2)).save(any(AuthEvent.class));
  }

  @Test
  void should_continueDrainingStandardLane_when_priorityLaneItemThrowsDuringSameTick() {
    AuditRetryProperties props = defaultCapacityProperties();
    AuthEventRetryBuffer buffer = newBuffer(props, fixedClock());

    AuthEvent priority = priorityEvent();
    AuthEvent standard = standardEvent();
    buffer.enqueue(priority);
    buffer.enqueue(standard);

    when(repository.save(priority)).thenThrow(new DataAccessResourceFailureException("db down"));
    when(repository.save(standard)).thenReturn(null);

    assertThatCode(buffer::drain).doesNotThrowAnyException();

    // Priority item's failure requeues it; standard lane still drained in the same tick.
    assertThat(buffer.depth(AuditLane.PRIORITY)).isEqualTo(1);
    assertThat(buffer.depth(AuditLane.STANDARD)).isZero();
    verify(repository).save(standard);
  }

  @Test
  void should_repeatedlySurviveExceptions_when_multipleConsecutiveTicksEachThrow() {
    MutableClock clock = new MutableClock(FIXED_NOW);
    AuditRetryProperties props = defaultCapacityProperties();
    AuthEventRetryBuffer buffer = newBuffer(props, clock);

    buffer.enqueue(standardEvent());
    when(repository.save(any(AuthEvent.class)))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    assertThatCode(buffer::drain).doesNotThrowAnyException();
    clock.advanceSeconds(2); // past 1s backoff — attempt 2
    assertThatCode(buffer::drain).doesNotThrowAnyException();
    clock.advanceSeconds(6); // past 5s backoff — attempt 3
    assertThatCode(buffer::drain).doesNotThrowAnyException();

    // Event survives all three thrown ticks — not lost, attempts have advanced, no alert yet
    // (max-attempts is 5 by default in defaultCapacityProperties()).
    assertThat(buffer.depth(AuditLane.STANDARD)).isEqualTo(1);
    verify(alertPort, never()).raise(any(AuditAlert.class));
  }

  // ==== Backoff schedule honoured across all 5 attempts ======================================

  @Test
  void should_honorFullBackoffSchedule_when_retryingAcrossAllFiveAttempts() {
    MutableClock clock = new MutableClock(FIXED_NOW);
    AuditRetryProperties props = fiveAttemptProperties();
    AuthEventRetryBuffer buffer = newBuffer(props, clock);

    buffer.enqueue(standardEvent());
    when(repository.save(any(AuthEvent.class)))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    // Attempt 1 fires immediately (nextRetryAt == null at first enqueue).
    buffer.drain();
    verify(repository, times(1)).save(any(AuthEvent.class));

    // Not yet due at +4s (schedule requires +1s for attempt 2, but retry already consumed
    // attempt 1's window — re-check by staying just under each subsequent boundary first).
    clock.advanceSeconds(1); // now exactly at the 1s backoff for attempt 2
    buffer.drain();
    verify(repository, times(2)).save(any(AuthEvent.class));

    clock.advanceSeconds(4); // under the 5s backoff for attempt 3 (only 4s elapsed)
    buffer.drain();
    verify(repository, times(2)).save(any(AuthEvent.class)); // not retried yet

    clock.advanceSeconds(1); // now exactly at the 5s backoff for attempt 3
    buffer.drain();
    verify(repository, times(3)).save(any(AuthEvent.class));

    clock.advanceSeconds(30); // exactly at the 30s backoff for attempt 4
    buffer.drain();
    verify(repository, times(4)).save(any(AuthEvent.class));

    clock.advanceSeconds(120); // exactly at the 2m backoff for attempt 5
    buffer.drain();
    verify(repository, times(5)).save(any(AuthEvent.class));

    // Attempt 5 (the last configured entry, 10m) was consumed above; exhaustion fires on the
    // *next* failed attempt beyond maxAttempts. fiveAttemptProperties() sets maxAttempts=5, so
    // the 5th failed attempt itself is the exhausting one.
    verify(alertPort).raise(any(AuditAlert.class));
    assertThat(buffer.depth(AuditLane.STANDARD)).isZero();
  }

  @Test
  void should_notRetryBeforeScheduledBackoffInstant_when_clockHasNotAdvancedEnough() {
    MutableClock clock = new MutableClock(FIXED_NOW);
    AuditRetryProperties props = defaultCapacityProperties();
    AuthEventRetryBuffer buffer = newBuffer(props, clock);

    buffer.enqueue(standardEvent());
    when(repository.save(any(AuthEvent.class)))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    buffer.drain(); // attempt 1, schedules next retry at +1s
    verify(repository, times(1)).save(any(AuthEvent.class));

    clock.advanceSeconds(0); // clock has not advanced at all (still < 1s backoff)
    buffer.drain();

    // No second attempt yet — depth unchanged, save() not called again.
    verify(repository, times(1)).save(any(AuthEvent.class));
    assertThat(buffer.depth(AuditLane.STANDARD)).isEqualTo(1);
  }

  // ==== Exhaustion alert fires at attempt 5, not before ======================================

  @Test
  void should_notRaiseExhaustedAlert_when_onlyFourAttemptsFailed() {
    MutableClock clock = new MutableClock(FIXED_NOW);
    AuditRetryProperties props = fiveAttemptProperties();
    AuthEventRetryBuffer buffer = newBuffer(props, clock);

    buffer.enqueue(standardEvent());
    when(repository.save(any(AuthEvent.class)))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    buffer.drain(); // attempt 1
    clock.advanceSeconds(1);
    buffer.drain(); // attempt 2
    clock.advanceSeconds(5);
    buffer.drain(); // attempt 3
    clock.advanceSeconds(30);
    buffer.drain(); // attempt 4

    verify(alertPort, never()).raise(any(AuditAlert.class));
    assertThat(buffer.depth(AuditLane.STANDARD)).isEqualTo(1); // event still buffered
  }

  @Test
  void should_raiseExhaustedAlertExactlyOnce_when_fifthAttemptFails() {
    MutableClock clock = new MutableClock(FIXED_NOW);
    AuditRetryProperties props = fiveAttemptProperties();
    AuthEventRetryBuffer buffer = newBuffer(props, clock);

    buffer.enqueue(standardEvent());
    when(repository.save(any(AuthEvent.class)))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    buffer.drain(); // attempt 1
    clock.advanceSeconds(1);
    buffer.drain(); // attempt 2
    clock.advanceSeconds(5);
    buffer.drain(); // attempt 3
    clock.advanceSeconds(30);
    buffer.drain(); // attempt 4
    clock.advanceSeconds(120);
    buffer.drain(); // attempt 5 — exhausts

    verify(alertPort).raise(any(AuditAlert.class));
    assertThat(buffer.depth(AuditLane.STANDARD)).isZero();
  }

  @Test
  void should_captureCorrectLaneAndDepth_when_exhaustedAlertRaised() {
    MutableClock clock = new MutableClock(FIXED_NOW);
    AuditRetryProperties props = fiveAttemptProperties();
    AuthEventRetryBuffer buffer = newBuffer(props, clock);

    buffer.enqueue(priorityEvent());
    when(repository.save(any(AuthEvent.class)))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    buffer.drain();
    clock.advanceSeconds(1);
    buffer.drain();
    clock.advanceSeconds(5);
    buffer.drain();
    clock.advanceSeconds(30);
    buffer.drain();
    clock.advanceSeconds(120);
    buffer.drain(); // attempt 5 — exhausts, priority lane now empty

    ArgumentCaptor<AuditAlert> captor = ArgumentCaptor.forClass(AuditAlert.class);
    verify(alertPort).raise(captor.capture());

    AuditAlert alert = captor.getValue();
    assertThat(alert.type()).isEqualTo(AuditAlertType.RETRY_EXHAUSTED);
    assertThat(alert.message()).contains("PRIORITY");
    assertThat(alert.bufferDepth()).isZero(); // depth read after this event was removed
  }

  // ==== Idempotency (buffer-side half — design §10.1) ========================================

  @Test
  void should_saveSameEventIdOnRetry_when_earlierAttemptPartiallyFailed() {
    MutableClock clock = new MutableClock(FIXED_NOW);
    AuditRetryProperties props = defaultCapacityProperties();
    AuthEventRetryBuffer buffer = newBuffer(props, clock);

    AuthEvent original = standardEvent();
    UUID originalId = original.getId();
    buffer.enqueue(original);

    when(repository.save(any(AuthEvent.class)))
        .thenThrow(new DataAccessResourceFailureException("db down"))
        .thenReturn(null);

    buffer.drain(); // attempt 1 fails
    clock.advanceSeconds(2); // past the 1s backoff
    buffer.drain(); // attempt 2 succeeds

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(repository, times(2)).save(captor.capture());

    // Every save() invocation — the failed first attempt and the successful retry — carries
    // the exact same event id. No new identity was minted for the retry.
    assertThat(captor.getAllValues())
        .extracting(AuthEvent::getId)
        .containsExactly(originalId, originalId);
  }

  @Test
  void should_preserveEventInstanceIdentity_when_drainRequeuesNotYetDueEvent() {
    MutableClock clock = new MutableClock(FIXED_NOW);
    AuditRetryProperties props = defaultCapacityProperties();
    AuthEventRetryBuffer buffer = newBuffer(props, clock);

    AuthEvent original = standardEvent();
    UUID originalId = original.getId();
    buffer.enqueue(original);

    when(repository.save(any(AuthEvent.class)))
        .thenThrow(new DataAccessResourceFailureException("db down"))
        .thenReturn(null);

    buffer.drain(); // attempt 1 fails, requeues with a future nextRetryAt (+1s)

    clock.advanceSeconds(0); // still not due — this drain() call requeues without retrying
    buffer.drain();

    // The item sitting back in the lane after a not-yet-due requeue is still the same event —
    // no re-creation, no id drift — proven by draining once more, past backoff, and checking
    // the id that finally gets saved.
    clock.advanceSeconds(2);
    buffer.drain();

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(repository, times(2)).save(captor.capture()); // attempt 1 (failed) + attempt 2 (ok)
    assertThat(captor.getAllValues())
        .extracting(AuthEvent::getId)
        .containsOnly(originalId);
  }

  // ==== helpers ===============================================================================

  private AuthEvent priorityEvent() {
    return new AuthEvent(UUID.randomUUID(), AuthEventType.LOCKOUT, "FAILURE");
  }

  private AuthEvent standardEvent() {
    return new AuthEvent(UUID.randomUUID(), AuthEventType.LOGIN_FAILURE, "FAILURE");
  }

  private Clock fixedClock() {
    return Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
  }

  private AuthEventRetryBuffer newBuffer(AuditRetryProperties props, Clock clock) {
    return newBuffer(props, clock, new SimpleMeterRegistry());
  }

  private AuthEventRetryBuffer newBuffer(
      AuditRetryProperties props, Clock clock, SimpleMeterRegistry registry) {
    return new AuthEventRetryBuffer(repository, alertPort, registry, clock, props);
  }

  private AuditRetryProperties capacityProperties(int priorityCapacity, int standardCapacity) {
    return new AuditRetryProperties(
        true, priorityCapacity, standardCapacity, 10_000L, 5,
        List.of(
            Duration.ofSeconds(1),
            Duration.ofSeconds(5),
            Duration.ofSeconds(30),
            Duration.ofMinutes(2),
            Duration.ofMinutes(10)),
        null,
        null);
  }

  private AuditRetryProperties defaultCapacityProperties() {
    return capacityProperties(200, 800);
  }

  private AuditRetryProperties fiveAttemptProperties() {
    return new AuditRetryProperties(
        true, 200, 800, 10_000L, 5,
        List.of(
            Duration.ofSeconds(1),
            Duration.ofSeconds(5),
            Duration.ofSeconds(30),
            Duration.ofMinutes(2),
            Duration.ofMinutes(10)),
        null,
        null);
  }

  /** A {@link Clock} whose {@code instant()} can be advanced mid-test, for backoff assertions. */
  private static final class MutableClock extends Clock {
    private Instant now;

    MutableClock(Instant initial) {
      this.now = initial;
    }

    void advanceSeconds(long seconds) {
      now = now.plusSeconds(seconds);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }
}
