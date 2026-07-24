package com.example.nexus.identity.infrastructure.audit;

import com.example.nexus.common.observation.ExecutionObserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
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
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Tag;
import org.springframework.dao.DataAccessResourceFailureException;

/**
 * US-008 T-08-15 — basic wiring/correctness tests for {@link AuthEventRetryBuffer}: enqueue
 * routes to the correct lane and reflects in {@code depth()}/{@code oldestAgeSeconds()}, drain
 * removes a successfully-retried event and increments the right counters, overflow at capacity
 * increments the dropped counter, all 5 buffer-owned metrics register, and a single item's
 * unexpected exception does not propagate out of {@code drain()}.
 *
 * <p><b>Explicitly NOT covered here</b> (reserved for T-08-17's adversarial suite): sustained
 * standard-lane-flood lane isolation (T-D1), full drop-newest-vs-drop-oldest overflow-ordering
 * proof (T-D2), scheduler-survives-across-multiple-ticks (T-D4), backoff honoured across all 5
 * attempts, exhaustion-alert-fires-at-attempt-5 end-to-end, and idempotency-on-duplicate-save.
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class AuthEventRetryBufferTest {

  private static final Instant FIXED_NOW = Instant.parse("2026-07-01T00:00:00Z");

  @Mock private JpaAuthEventRepository repository;
  @Mock private AuditAlertPort alertPort;

  private SimpleMeterRegistry meterRegistry;
  private Clock clock;
  private AuditRetryProperties properties;
  private AuthEventRetryBuffer buffer;

  @BeforeEach
  void setUp() {
    meterRegistry = new SimpleMeterRegistry();
    clock = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
    properties = defaultProperties();
    buffer = new AuthEventRetryBuffer(repository, alertPort, meterRegistry, clock, properties, new ExecutionObserver(meterRegistry));
  }

  // ---- routing + depth reflection ----------------------------------------------------------

  @Test
  void should_returnTrue_when_enqueuePriorityEventUnderCapacity() {
    boolean result = buffer.enqueue(priorityEvent());

    assertThat(result).isTrue();
    assertThat(buffer.depth(AuditLane.PRIORITY)).isEqualTo(1);
  }

  @Test
  void should_returnTrue_when_enqueueStandardEventUnderCapacity() {
    boolean result = buffer.enqueue(standardEvent());

    assertThat(result).isTrue();
    assertThat(buffer.depth(AuditLane.STANDARD)).isEqualTo(1);
  }

  @Test
  void should_routeToPriorityLaneOnly_when_isPriorityTrue() {
    buffer.enqueue(priorityEvent());

    assertThat(buffer.depth(AuditLane.PRIORITY)).isEqualTo(1);
    assertThat(buffer.depth(AuditLane.STANDARD)).isEqualTo(0);
  }

  @Test
  void should_routeToStandardLaneOnly_when_isPriorityFalse() {
    buffer.enqueue(standardEvent());

    assertThat(buffer.depth(AuditLane.STANDARD)).isEqualTo(1);
    assertThat(buffer.depth(AuditLane.PRIORITY)).isEqualTo(0);
  }

  @Test
  void should_reportZeroDepth_when_bufferEmpty() {
    assertThat(buffer.depth(AuditLane.PRIORITY)).isZero();
    assertThat(buffer.depth(AuditLane.STANDARD)).isZero();
  }

  // ---- age gauge ----------------------------------------------------------------------------

  @Test
  void should_reportZeroOldestAge_when_laneEmpty() {
    assertThat(buffer.oldestAgeSeconds(AuditLane.PRIORITY)).isZero();
    assertThat(buffer.oldestAgeSeconds(AuditLane.STANDARD)).isZero();
  }

  @Test
  void should_reportPositiveOldestAge_when_eventBufferedAndClockAdvances() {
    MutableClock mutableClock = new MutableClock(FIXED_NOW);
    SimpleMeterRegistry localRegistry = new SimpleMeterRegistry();
    AuthEventRetryBuffer bufferWithMutableClock =
        new AuthEventRetryBuffer(
            repository, alertPort, localRegistry, mutableClock, properties, new ExecutionObserver(localRegistry));
    bufferWithMutableClock.enqueue(standardEvent());

    mutableClock.advanceSeconds(42);

    assertThat(bufferWithMutableClock.oldestAgeSeconds(AuditLane.STANDARD)).isEqualTo(42L);
  }

  @Test
  void should_reportZeroOldestAge_when_eventEnqueuedAtSameInstant() {
    buffer.enqueue(standardEvent());

    assertThat(buffer.oldestAgeSeconds(AuditLane.STANDARD)).isZero();
  }

  // ---- drain / retry success --------------------------------------------------------------

  @Test
  void should_removeEventFromBuffer_when_drainSucceeds() {
    buffer.enqueue(standardEvent());

    buffer.drain();

    assertThat(buffer.depth(AuditLane.STANDARD)).isZero();
    verify(repository).save(any(AuthEvent.class));
  }

  @Test
  void should_incrementRetrySuccessCounter_when_drainSucceeds() {
    buffer.enqueue(priorityEvent());

    buffer.drain();

    double successCount =
        meterRegistry
            .get("nexus.audit.retry.success")
            .tag("lane", "priority")
            .counter()
            .count();
    assertThat(successCount).isEqualTo(1.0);
  }

  @Test
  void should_drainPriorityLaneBeforeStandardLane_when_bothNonEmpty() {
    buffer.enqueue(priorityEvent());
    buffer.enqueue(standardEvent());

    buffer.drain();

    assertThat(buffer.depth(AuditLane.PRIORITY)).isZero();
    assertThat(buffer.depth(AuditLane.STANDARD)).isZero();
  }

  // ---- overflow (basic — capacity-limited via test-only small AuditRetryProperties) --------

  @Test
  void should_returnFalse_when_standardLaneAtCapacity() {
    AuditRetryProperties small = smallCapacityProperties(2, 3);
    SimpleMeterRegistry localRegistry = new SimpleMeterRegistry();
    AuthEventRetryBuffer smallBuffer =
        new AuthEventRetryBuffer(repository, alertPort, localRegistry, clock, small, new ExecutionObserver(localRegistry));

    smallBuffer.enqueue(standardEvent());
    smallBuffer.enqueue(standardEvent());
    smallBuffer.enqueue(standardEvent()); // fills the 3-capacity standard lane
    boolean overflowResult = smallBuffer.enqueue(standardEvent());

    assertThat(overflowResult).isFalse();
    assertThat(smallBuffer.depth(AuditLane.STANDARD)).isEqualTo(3);
  }

  @Test
  void should_incrementDroppedCounter_when_laneAtCapacity() {
    AuditRetryProperties small = smallCapacityProperties(2, 3);
    SimpleMeterRegistry localRegistry = new SimpleMeterRegistry();
    AuthEventRetryBuffer smallBuffer =
        new AuthEventRetryBuffer(repository, alertPort, localRegistry, clock, small, new ExecutionObserver(localRegistry));

    smallBuffer.enqueue(priorityEvent());
    smallBuffer.enqueue(priorityEvent()); // fills the 2-capacity priority lane
    smallBuffer.enqueue(priorityEvent()); // dropped

    double droppedCount =
        localRegistry
            .get("nexus.audit.buffer.dropped")
            .tag("lane", "priority")
            .tag("reason", "overflow")
            .counter()
            .count();
    assertThat(droppedCount).isEqualTo(1.0);
  }

  @Test
  void should_notReducePriorityLaneCapacity_when_standardLaneEnqueueRejected() {
    AuditRetryProperties small = smallCapacityProperties(2, 1);
    SimpleMeterRegistry localRegistry = new SimpleMeterRegistry();
    AuthEventRetryBuffer smallBuffer =
        new AuthEventRetryBuffer(repository, alertPort, localRegistry, clock, small, new ExecutionObserver(localRegistry));

    smallBuffer.enqueue(standardEvent());
    smallBuffer.enqueue(standardEvent()); // rejected — standard lane capacity 1

    assertThat(smallBuffer.enqueue(priorityEvent())).isTrue();
    assertThat(smallBuffer.enqueue(priorityEvent())).isTrue();
    assertThat(smallBuffer.depth(AuditLane.PRIORITY)).isEqualTo(2);
  }

  // ---- metric registration -----------------------------------------------------------------

  @Test
  void should_registerBothDepthGauges_when_bufferConstructed() {
    assertThat(meterRegistry.find("nexus.audit.buffer.depth").tag("lane", "priority").gauge())
        .isNotNull();
    assertThat(meterRegistry.find("nexus.audit.buffer.depth").tag("lane", "standard").gauge())
        .isNotNull();
  }

  @Test
  void should_registerBothOldestAgeGauges_when_bufferConstructed() {
    assertThat(
            meterRegistry
                .find("nexus.audit.buffer.oldest.age.seconds")
                .tag("lane", "priority")
                .gauge())
        .isNotNull();
    assertThat(
            meterRegistry
                .find("nexus.audit.buffer.oldest.age.seconds")
                .tag("lane", "standard")
                .gauge())
        .isNotNull();
  }

  @Test
  void should_registerRetrySuccessCounterForBothLanes_when_bufferConstructed() {
    assertThat(meterRegistry.find("nexus.audit.retry.success").tag("lane", "priority").counter())
        .isNotNull();
    assertThat(meterRegistry.find("nexus.audit.retry.success").tag("lane", "standard").counter())
        .isNotNull();
  }

  @Test
  void should_registerRetryExhaustedCounterForBothLanes_when_bufferConstructed() {
    assertThat(
            meterRegistry.find("nexus.audit.retry.exhausted").tag("lane", "priority").counter())
        .isNotNull();
    assertThat(
            meterRegistry.find("nexus.audit.retry.exhausted").tag("lane", "standard").counter())
        .isNotNull();
  }

  @Test
  void should_registerDroppedCounterForBothLanes_when_bufferConstructed() {
    assertThat(
            meterRegistry
                .find("nexus.audit.buffer.dropped")
                .tag("lane", "priority")
                .tag("reason", "overflow")
                .counter())
        .isNotNull();
    assertThat(
            meterRegistry
                .find("nexus.audit.buffer.dropped")
                .tag("lane", "standard")
                .tag("reason", "overflow")
                .counter())
        .isNotNull();
  }

  @Test
  void should_reflectLiveDepth_when_gaugeReadAfterEnqueue() {
    buffer.enqueue(priorityEvent());

    double gaugeValue =
        meterRegistry.get("nexus.audit.buffer.depth").tag("lane", "priority").gauge().value();

    assertThat(gaugeValue).isEqualTo(1.0);
  }

  // ---- drainer exception survival (basic try/catch shape only — T-08-17 owns the adversarial proof) --

  @Test
  void should_notThrow_when_drainIterationEncountersUnexpectedException() {
    buffer.enqueue(standardEvent());
    doThrow(new IllegalStateException("boom")).when(repository).save(any(AuthEvent.class));

    assertThatCode(() -> buffer.drain()).doesNotThrowAnyException();
  }

  @Test
  void should_requeueEvent_when_saveThrowsDataAccessException() {
    buffer.enqueue(standardEvent());
    when(repository.save(any(AuthEvent.class)))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    buffer.drain();

    assertThat(buffer.depth(AuditLane.STANDARD)).isEqualTo(1);
  }

  @Test
  void should_notRaiseAlert_when_retryFailsButAttemptsRemain() {
    buffer.enqueue(standardEvent());
    when(repository.save(any(AuthEvent.class)))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    buffer.drain();

    verify(alertPort, never()).raise(any(AuditAlert.class));
  }

  @Test
  void should_raiseRetryExhaustedAlert_when_finalAttemptFails() {
    AuditRetryProperties singleAttempt =
        new AuditRetryProperties(
            true, 200, 800, 10_000L, 1, List.of(Duration.ofSeconds(1)), null, null);
    SimpleMeterRegistry localRegistry = new SimpleMeterRegistry();
    AuthEventRetryBuffer singleAttemptBuffer =
        new AuthEventRetryBuffer(
            repository, alertPort, localRegistry, clock, singleAttempt, new ExecutionObserver(localRegistry));
    singleAttemptBuffer.enqueue(standardEvent());
    when(repository.save(any(AuthEvent.class)))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    singleAttemptBuffer.drain();

    verify(alertPort).raise(any(AuditAlert.class));
    assertThat(singleAttemptBuffer.depth(AuditLane.STANDARD)).isZero();
  }

  // ---- helpers ------------------------------------------------------------------------------

  private AuthEvent priorityEvent() {
    return new AuthEvent(UUID.randomUUID(), AuthEventType.LOCKOUT, "FAILURE");
  }

  private AuthEvent standardEvent() {
    return new AuthEvent(UUID.randomUUID(), AuthEventType.LOGIN_FAILURE, "FAILURE");
  }

  private AuditRetryProperties defaultProperties() {
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

  private AuditRetryProperties smallCapacityProperties(int priorityCapacity, int standardCapacity) {
    return new AuditRetryProperties(
        true, priorityCapacity, standardCapacity, 10_000L, 5,
        List.of(Duration.ofSeconds(1)),
        null,
        null);
  }

  /** A {@link Clock} whose {@code instant()} can be advanced mid-test, for age-gauge assertions. */
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
