package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.rbac.application.port.out.EpochUnparseableException;
import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.InOrder;
import org.slf4j.LoggerFactory;
import org.springframework.dao.QueryTimeoutException;

/**
 * Unit tests for {@link PermissionFreshnessService} (US-018 T-009, T-010; design §9.2, §9.4, §9.9).
 */
@Tag("UnitTest")
class PermissionFreshnessServiceTest {

  private static final UUID TENANT = UUID.fromString("00000000-0000-7000-8000-0000000000aa");
  private static final UUID USER = UUID.fromString("00000000-0000-7000-8000-0000000000bb");
  private static final long EPOCH = 1_796_000_000_000L;

  private static final Instant T = Instant.parse("2026-10-08T10:00:00Z");
  private static final Duration WINDOW = Duration.ofMinutes(15);
  private static final long KEY_TTL_SECONDS = 960;
  private static final int REPLAY_CAPACITY = 100_000;
  private static final int ROLE_REPLAY_CAPACITY = 1000;
  private static final int TENANT_PERCENT = 10;
  private static final int TENANT_CAP =
      PermissionFreshnessService.LAST_SEEN_CAPACITY * TENANT_PERCENT / 100;
  private static final UUID ROLE = UUID.fromString("00000000-0000-7000-8000-0000000000c1");

  private PermissionEpochPort port;
  private UserRoleAssignmentPort userRoles;
  private SimpleMeterRegistry registry;
  private MutableClock clock;
  private PermissionFreshnessService service;

  @BeforeEach
  void setUp() {
    port = mock(PermissionEpochPort.class);
    userRoles = mock(UserRoleAssignmentPort.class);
    registry = new SimpleMeterRegistry();
    clock = new MutableClock(T);
    service = newService(registry);
  }

  private PermissionFreshnessService newService(SimpleMeterRegistry meters) {
    return newService(meters, REPLAY_CAPACITY);
  }

  private PermissionFreshnessService newService(SimpleMeterRegistry meters, int replayCapacity) {
    return newService(meters, replayCapacity, ROLE_REPLAY_CAPACITY, TENANT_PERCENT);
  }

  private PermissionFreshnessService newService(
      SimpleMeterRegistry meters, int replayCapacity, int roleCapacity, int tenantPercent) {
    return new PermissionFreshnessService(
        port, userRoles, meters, clock, WINDOW, 3, Duration.ofSeconds(10), Duration.ofSeconds(60),
        KEY_TTL_SECONDS, replayCapacity, roleCapacity, tenantPercent);
  }

  // --- check: verdicts ---

  @Test
  void should_returnFresh_when_tokenEpochEqualsCurrent() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));

    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.FRESH);
  }

  @Test
  void should_returnFresh_when_tokenEpochAboveCurrent() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));

    assertThat(service.check(TENANT, USER, EPOCH + 1)).isEqualTo(FreshnessVerdict.FRESH);
  }

  @Test
  void should_returnStale_when_tokenEpochOneBelowCurrent() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));

    assertThat(service.check(TENANT, USER, EPOCH - 1)).isEqualTo(FreshnessVerdict.STALE);
  }

  @Test
  void should_returnFresh_when_keyAbsent() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(0L));

    assertThat(service.check(TENANT, USER, 0L)).isEqualTo(FreshnessVerdict.FRESH);
  }

  @Test
  void should_returnStale_when_v2EpochZeroAndKeyPresent() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));

    assertThat(service.check(TENANT, USER, 0L)).isEqualTo(FreshnessVerdict.STALE);
  }

  // --- check: single-request fail-open ---

  @Test
  void should_returnSkippedError_when_portEmpty() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.empty());

    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);
  }

  @Test
  void should_returnStaleOnNextRequest_after_singleSkippedError() {
    when(port.current(TENANT, USER))
        .thenReturn(OptionalLong.empty())
        .thenReturn(OptionalLong.of(EPOCH));

    service.check(TENANT, USER, 0L);

    assertThat(service.check(TENANT, USER, 0L)).isEqualTo(FreshnessVerdict.STALE);
  }

  // --- check: observability ---

  @Test
  void should_countOutcome_per_verdict() {
    when(port.current(TENANT, USER))
        .thenReturn(OptionalLong.of(EPOCH))
        .thenReturn(OptionalLong.of(EPOCH))
        .thenReturn(OptionalLong.empty());

    service.check(TENANT, USER, EPOCH);
    service.check(TENANT, USER, EPOCH - 1);
    service.check(TENANT, USER, EPOCH);

    assertThat(outcomeCount("fresh")).isEqualTo(1.0);
    assertThat(outcomeCount("stale")).isEqualTo(1.0);
    assertThat(outcomeCount("skipped_error")).isEqualTo(1.0);
  }

  @Test
  void should_registerEveryOutcomeAtZero_when_constructed() {
    assertThat(outcomeCount("fresh")).isZero();
    assertThat(outcomeCount("stale")).isZero();
    assertThat(outcomeCount("skipped_error")).isZero();
  }

  @Test
  void should_recordLatency_for_everyCheckIncludingSkippedError() {
    when(port.current(TENANT, USER))
        .thenReturn(OptionalLong.of(EPOCH))
        .thenReturn(OptionalLong.empty());

    service.check(TENANT, USER, EPOCH);
    service.check(TENANT, USER, EPOCH);

    assertThat(registry.get("nexus.rbac.epoch.check.latency").timer().count()).isEqualTo(2);
  }

  @Test
  void should_publishP50P95P99_on_latencyTimer() {
    assertThat(
            registry.get("nexus.rbac.epoch.check.latency").timer().takeSnapshot().percentileValues())
        .extracting(value -> value.percentile())
        .containsExactly(0.5, 0.95, 0.99);
  }

  // --- epochForMint ---

  @Test
  void should_returnCurrentEpoch_when_epochForMintReadSucceeds() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));

    assertThat(service.epochForMint(TENANT, USER)).isEqualTo(EPOCH);
  }

  @Test
  void should_returnZero_when_epochForMintKeyAbsent() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(0L));

    assertThat(service.epochForMint(TENANT, USER)).isZero();
  }

  @Test
  void should_returnZero_when_epochForMintReadFailsTwice() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.empty());

    assertThat(service.epochForMint(TENANT, USER)).isZero();
  }

  @Test
  void should_returnCurrentEpoch_when_epochForMintReadFailsThenSucceeds() {
    when(port.current(TENANT, USER))
        .thenReturn(OptionalLong.empty())
        .thenReturn(OptionalLong.of(EPOCH));

    assertThat(service.epochForMint(TENANT, USER)).isEqualTo(EPOCH);
  }

  @Test
  void should_readOnce_when_epochForMintFirstReadSucceeds() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));

    service.epochForMint(TENANT, USER);

    verify(port, times(1)).current(TENANT, USER);
  }

  @Test
  void should_notCountAsCheck_when_epochForMintReads() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.empty());

    service.epochForMint(TENANT, USER);

    assertThat(outcomeCount("skipped_error")).isZero();
  }

  // --- invalidateUser ---

  @Test
  void should_bumpOnlyTargetUser_when_invalidateUser() {
    service.invalidateUser(TENANT, USER, "revoke");

    verify(port).bump(TENANT, List.of(USER));
  }

  @Test
  void should_notPropagate_when_bumpFails() {
    doThrow(new QueryTimeoutException("timeout")).when(port).bump(any(), anyCollection());

    assertThatCode(() -> service.invalidateUser(TENANT, USER, "revoke"))
        .doesNotThrowAnyException();
  }

  @Test
  void should_logBumpFailedWithOperation_when_bumpFailsWithNonDataAccessException() {
    Logger logger = (Logger) LoggerFactory.getLogger(PermissionFreshnessService.class);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    doThrow(new IllegalStateException("factory stopped")).when(port).bump(any(), anyCollection());
    try {
      assertThatCode(() -> service.invalidateUser(TENANT, USER, "detach"))
          .doesNotThrowAnyException();
    } finally {
      logger.detachAppender(appender);
    }

    assertThat(appender.list).singleElement().satisfies(event -> {
      assertThat(event.getLevel()).isEqualTo(Level.ERROR);
      assertThat(event.getKeyValuePairs())
          .anySatisfy(kv -> assertThat(kv.value).isEqualTo("RBAC_EPOCH_BUMP_FAILED"))
          .anySatisfy(kv -> assertThat(kv.value).isEqualTo("detach"));
    });
  }

  // --- invalidateHolders (T-010, design §9.4) ---

  @Test
  void should_bumpInBatchesOf500_when_invalidatingHolders() {
    List<UUID> holders = users(1001);

    service.invalidateHolders(TENANT, holders, "detach");

    InOrder order = inOrder(port);
    order.verify(port).bump(TENANT, holders.subList(0, 500));
    order.verify(port).bump(TENANT, holders.subList(500, 1000));
    order.verify(port).bump(TENANT, holders.subList(1000, 1001));
    verifyNoMoreInteractions(port);
  }

  @Test
  void should_bumpOnce_when_exactly500Holders() {
    List<UUID> holders = users(500);

    service.invalidateHolders(TENANT, holders, "detach");

    verify(port).bump(TENANT, holders);
    verifyNoMoreInteractions(port);
  }

  @Test
  void should_bumpTwice_when_501Holders() {
    List<UUID> holders = users(501);

    service.invalidateHolders(TENANT, holders, "detach");

    verify(port).bump(TENANT, holders.subList(0, 500));
    verify(port).bump(TENANT, holders.subList(500, 501));
    verifyNoMoreInteractions(port);
  }

  @Test
  void should_deduplicateUserIds_when_invalidatingHolders() {
    UUID other = UUID.fromString("00000000-0000-7000-8000-0000000000cc");

    service.invalidateHolders(TENANT, List.of(USER, other, USER), "detach");

    verify(port).bump(TENANT, List.of(USER, other));
    assertThat(fanoutCount("1-10")).isEqualTo(1.0);
  }

  @Test
  void should_notCallStore_when_noHolders() {
    service.invalidateHolders(TENANT, List.of(), "detach");

    verifyNoInteractions(port);
    assertThat(fanoutCount("0")).isEqualTo(1.0);
  }

  @Test
  void should_warnFanoutLarge_when_1001Holders() {
    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.invalidateHolders(TENANT, users(1001), "detach");
    } finally {
      stopLogCapture(appender);
    }

    assertThat(appender.list).singleElement().satisfies(event -> {
      assertThat(event.getLevel()).isEqualTo(Level.WARN);
      assertThat(keyValues(event))
          .containsEntry("event", "RBAC_EPOCH_FANOUT_LARGE")
          .containsEntry("tenantId", TENANT)
          .containsEntry("operation", "detach")
          .containsEntry("holderCount", 1001)
          .containsOnlyKeys("event", "tenantId", "operation", "holderCount");
    });
  }

  @Test
  void should_notWarnFanoutLarge_when_1000Holders() {
    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.invalidateHolders(TENANT, users(1000), "detach");
    } finally {
      stopLogCapture(appender);
    }

    assertThat(appender.list).isEmpty();
  }

  @ParameterizedTest
  @CsvSource({"0,0", "1,1-10", "10,1-10", "11,11-100", "100,11-100", "101,101-1000",
      "1000,101-1000", "1001,>1000"})
  void should_tagFanoutBucket_when_holderCountAtBoundary(int holders, String bucket) {
    service.invalidateHolders(TENANT, users(holders), "detach");

    assertThat(registry.get("nexus.rbac.epoch.fanout").counters())
        .allSatisfy(counter -> assertThat(counter.getId().getTags())
            .extracting(tag -> tag.getKey())
            .containsExactly("holders"))
        .filteredOn(counter -> counter.count() > 0)
        .singleElement()
        .satisfies(counter -> assertThat(counter.getId().getTag("holders")).isEqualTo(bucket));
  }

  @Test
  void should_registerEveryFanoutBucketAtZero_when_constructed() {
    assertThat(registry.get("nexus.rbac.epoch.fanout").counters())
        .extracting(counter -> counter.getId().getTag("holders"))
        .containsExactlyInAnyOrder("0", "1-10", "11-100", "101-1000", ">1000");
  }

  @Test
  void should_stopAtFailedBatchAndLogRemainder_when_secondBatchFails() {
    List<UUID> holders = users(1001);
    doReturn(Map.of())
        .doThrow(new QueryTimeoutException("timeout"))
        .when(port).bump(any(), anyCollection());
    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatCode(() -> service.invalidateHolders(TENANT, holders, "detach"))
          .doesNotThrowAnyException();
    } finally {
      stopLogCapture(appender);
    }

    verify(port, times(2)).bump(any(), anyCollection());
    verify(port, never()).bump(TENANT, holders.subList(1000, 1001));
    List<ILoggingEvent> errors =
        appender.list.stream().filter(event -> event.getLevel() == Level.ERROR).toList();
    assertThat(errors).singleElement().satisfies(event -> assertThat(keyValues(event))
        .containsEntry("event", "RBAC_EPOCH_BUMP_FAILED")
        .containsEntry("operation", "detach")
        .containsEntry("userCount", 501));
  }

  @Test
  void should_neverPropagate_when_holderBumpThrowsNonDataAccessException() {
    doThrow(new IllegalStateException("factory stopped")).when(port).bump(any(), anyCollection());

    assertThatCode(() -> service.invalidateHolders(TENANT, users(3), "detach"))
        .doesNotThrowAnyException();
  }

  /** RC-53 seam for T-011: fan-out bump failures never count as epoch-check outcomes. */
  @Test
  void should_notCountTowardsCheckOutcomes_when_fanoutFails() {
    doThrow(new QueryTimeoutException("timeout")).when(port).bump(any(), anyCollection());

    service.invalidateHolders(TENANT, users(3), "detach");

    assertThat(registry.get("nexus.rbac.epoch.check").counters())
        .allSatisfy(counter -> assertThat(counter.count()).isZero());
  }

  private static List<UUID> users(int count) {
    return IntStream.range(0, count).mapToObj(i -> UUID.randomUUID()).toList();
  }

  private double fanoutCount(String bucket) {
    return registry.get("nexus.rbac.epoch.fanout").tag("holders", bucket).counter().count();
  }

  private static ListAppender<ILoggingEvent> startLogCapture() {
    Logger logger = (Logger) LoggerFactory.getLogger(PermissionFreshnessService.class);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void stopLogCapture(ListAppender<ILoggingEvent> appender) {
    ((Logger) LoggerFactory.getLogger(PermissionFreshnessService.class)).detachAppender(appender);
    appender.stop();
  }

  private static Map<String, Object> keyValues(ILoggingEvent event) {
    Map<String, Object> map = new HashMap<>();
    event.getKeyValuePairs().forEach(kv -> map.put(kv.key, kv.value));
    return map;
  }

  private double outcomeCount(String outcome) {
    return registry.get("nexus.rbac.epoch.check").tag("outcome", outcome).counter().count();
  }

  // --- outage state machine (T-011, design §9.5) ---

  private void failRead() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.empty());
  }

  private FreshnessVerdict failedCheckAt(long secondsAfterT) {
    clock.set(T.plusSeconds(secondsAfterT));
    return service.check(TENANT, USER, EPOCH);
  }

  private void tripAtT() {
    failRead();
    failedCheckAt(0);
    failedCheckAt(1);
    failedCheckAt(2);
  }

  /** Moves from DegradedOpen to Recovering with a successful probe at the current time. */
  private void recoverNow() {
    when(port.probe()).thenReturn(true);
    service.probe();
  }

  @Test
  void should_stayHealthy_when_oneOrTwoReadsFail() {
    failRead();

    assertThat(failedCheckAt(0)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);
    assertThat(failedCheckAt(1)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);

    assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);
  }

  @Test
  void should_enterDegradedOpen_when_thirdReadFailsWithinWindow() {
    failRead();
    failedCheckAt(0);
    failedCheckAt(4);

    assertThat(failedCheckAt(9)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);

    assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_OPEN);
    assertThat(failedCheckAt(9)).isEqualTo(FreshnessVerdict.SKIPPED_DEGRADED);
  }

  @Test
  void should_notEnter_when_threeFailuresSpreadOverMoreThanWindow() {
    failRead();
    failedCheckAt(0);
    failedCheckAt(6);
    failedCheckAt(12);

    assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);
  }

  @Test
  void should_notEnter_when_firstFailureIsExactlyOneWindowOld() {
    failRead();
    failedCheckAt(0);
    failedCheckAt(5);
    failedCheckAt(10);

    assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);
  }

  @Test
  void should_enter_when_firstFailureIsJustInsideWindow() {
    failRead();
    failedCheckAt(0);
    failedCheckAt(5);
    clock.set(T.plusMillis(9_999));
    service.check(TENANT, USER, EPOCH);

    assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_OPEN);
  }

  @Test
  void should_setT0AtFirstFailureOfTrippingWindow() {
    failRead();
    failedCheckAt(0);
    failedCheckAt(4);
    failedCheckAt(8);

    clock.set(T.plus(WINDOW).minusMillis(1));
    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.SKIPPED_DEGRADED);
    clock.set(T.plus(WINDOW));
    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.UNAVAILABLE);
    assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_CLOSED);
  }

  @Test
  void should_enterThenClose_when_failSuccessPatternSustainsPastWindow() {
    // F F S F F S ...: a consecutive-failure counter never trips on this (T-E43, RC-41.3).
    for (int cycle = 0; cycle < 3; cycle++) {
      long base = cycle * 3L;
      failRead();
      failedCheckAt(base);
      failedCheckAt(base + 1);
      when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(0L));
      clock.set(T.plusSeconds(base + 2));
      service.check(TENANT, USER, EPOCH);
    }
    assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_OPEN);

    clock.set(T.plus(WINDOW));
    service.check(TENANT, USER, EPOCH);

    assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_CLOSED);
  }

  @Test
  void should_returnSkippedDegradedWithoutReading_when_open() {
    tripAtT();
    org.mockito.Mockito.clearInvocations(port);

    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.SKIPPED_DEGRADED);

    verify(port, never()).current(any(), any());
  }

  @Test
  void should_returnUnavailableWithoutReading_when_closed() {
    tripAtT();
    clock.set(T.plus(WINDOW));
    org.mockito.Mockito.clearInvocations(port);

    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.UNAVAILABLE);

    verify(port, never()).current(any(), any());
  }

  @Test
  void should_moveToRecoveringAndResumeChecks_when_probeSucceedsInOpen() {
    tripAtT();
    when(port.probe()).thenReturn(true);

    service.probe();

    assertThat(service.state()).isEqualTo(DegradedState.RECOVERING);
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));
    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.FRESH);
  }

  @Test
  void should_moveToRecovering_when_probeSucceedsInClosed() {
    tripAtT();
    clock.set(T.plus(WINDOW));
    service.check(TENANT, USER, EPOCH);
    when(port.probe()).thenReturn(true);

    service.probe();

    assertThat(service.state()).isEqualTo(DegradedState.RECOVERING);
  }

  @Test
  void should_stayDegraded_when_probeFails() {
    tripAtT();
    when(port.probe()).thenReturn(false);

    service.probe();

    assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_OPEN);
  }

  @Test
  void should_notProbe_when_healthy() {
    service.probe();

    verify(port, never()).probe();
  }

  @Test
  void should_returnHealthyAndClearT0_when_sixtySecondsOfSuccessesInRecovering() {
    tripAtT();
    clock.set(T.plusSeconds(100));
    recoverNow();
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));

    clock.set(T.plusSeconds(100).plusMillis(59_999));
    service.check(TENANT, USER, EPOCH);
    assertThat(service.state()).isEqualTo(DegradedState.RECOVERING);
    clock.set(T.plusSeconds(160));
    service.check(TENANT, USER, EPOCH);

    assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);
    // t0 is cleared: a new episode starts a new time box instead of inheriting the old one.
    failRead();
    failedCheckAt(500);
    failedCheckAt(501);
    failedCheckAt(502);
    clock.set(T.plusSeconds(500).plus(WINDOW).minusMillis(1));
    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.SKIPPED_DEGRADED);
  }

  @Test
  void should_returnHealthy_when_probeSuccessesSpanSustainInRecovering() {
    tripAtT();
    clock.set(T.plusSeconds(100));
    recoverNow();

    clock.set(T.plusSeconds(160));
    service.probe();

    assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);
  }

  @Test
  void should_restartSustain_when_singleFailureInRecovering() {
    tripAtT();
    clock.set(T.plusSeconds(100));
    recoverNow();
    failRead();
    clock.set(T.plusSeconds(130));
    service.check(TENANT, USER, EPOCH);
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));

    clock.set(T.plusSeconds(160));
    service.check(TENANT, USER, EPOCH);
    assertThat(service.state()).isEqualTo(DegradedState.RECOVERING);
    clock.set(T.plusSeconds(190));
    service.check(TENANT, USER, EPOCH);

    assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);
  }

  @Test
  void should_relapseToOpenKeepingT0_when_threeFailuresInRecoveringBeforeWindow() {
    tripAtT();
    clock.set(T.plusSeconds(100));
    recoverNow();
    failRead();
    failedCheckAt(110);
    failedCheckAt(111);
    failedCheckAt(112);

    assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_OPEN);
    clock.set(T.plus(WINDOW));
    service.check(TENANT, USER, EPOCH);
    assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_CLOSED);
  }

  @Test
  void should_relapseStraightToClosed_when_threeFailuresInRecoveringAfterWindow() {
    tripAtT();
    clock.set(T.plus(WINDOW).plusSeconds(10));
    service.check(TENANT, USER, EPOCH);
    recoverNow();
    failRead();
    long afterWindow = WINDOW.toSeconds() + 20;
    failedCheckAt(afterWindow);
    failedCheckAt(afterWindow + 1);
    failedCheckAt(afterWindow + 2);

    assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_CLOSED);
  }

  @Test
  void should_relapse_when_threeProbeFailuresInRecovering() {
    tripAtT();
    clock.set(T.plusSeconds(100));
    recoverNow();
    when(port.probe()).thenReturn(false);

    for (int i = 0; i < 3; i++) {
      clock.set(T.plusSeconds(110 + i));
      service.probe();
    }

    assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_OPEN);
  }

  @Test
  void should_countProbeFailuresTowardsEntryWindow_when_alreadyRecoveringMixedWithReads() {
    tripAtT();
    clock.set(T.plusSeconds(100));
    recoverNow();
    failRead();
    when(port.probe()).thenReturn(false);
    failedCheckAt(110);
    clock.set(T.plusSeconds(111));
    service.probe();
    failedCheckAt(112);

    assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_OPEN);
  }

  @Test
  void should_neverCountBumpFailures_when_healthy() {
    doThrow(new QueryTimeoutException("bump timeout")).when(port).bump(any(), anyCollection());

    for (int i = 0; i < 10; i++) {
      service.invalidateUser(TENANT, USER, "revoke");
      service.invalidateHolders(TENANT, List.of(USER), "detach");
    }

    assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);
  }

  @Test
  void should_notRestartSustain_when_bumpFailsInRecovering() {
    tripAtT();
    clock.set(T.plusSeconds(100));
    recoverNow();
    doThrow(new QueryTimeoutException("bump timeout")).when(port).bump(any(), anyCollection());
    clock.set(T.plusSeconds(150));
    service.invalidateUser(TENANT, USER, "revoke");
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));

    clock.set(T.plusSeconds(160));
    service.check(TENANT, USER, EPOCH);

    assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);
  }

  @Test
  void should_incrementEntriesAndNotFlap_when_twoEntriesWithinFifteenMinutes() {
    enterAndRecoverFully(0);
    enterAndRecoverFully(300);

    assertThat(registry.get("nexus.rbac.epoch.degraded_entries").counter().count()).isEqualTo(2.0);
    assertThat(registry.get("nexus.rbac.epoch.degraded_flap").counter().count()).isZero();
  }

  @Test
  void should_raiseFlapSignal_when_threeEntriesWithinFifteenMinutes() {
    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      enterAndRecoverFully(0);
      enterAndRecoverFully(200);
      enterAndRecoverFully(400);

      assertThat(registry.get("nexus.rbac.epoch.degraded_flap").counter().count()).isEqualTo(1.0);
      assertThat(appender.list)
          .filteredOn(e -> "RBAC_EPOCH_DEGRADED_FLAP".equals(keyValues(e).get("event")))
          .singleElement()
          .satisfies(e -> assertThat(e.getLevel()).isEqualTo(Level.WARN));
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_notFlap_when_threeEntriesSpreadOverMoreThanFifteenMinutes() {
    enterAndRecoverFully(0);
    enterAndRecoverFully(600);
    enterAndRecoverFully(1_200);

    assertThat(registry.get("nexus.rbac.epoch.degraded_flap").counter().count()).isZero();
  }

  /** Trips at {@code start}, recovers and returns to Healthy; takes 2 + 70 s of test time. */
  private void enterAndRecoverFully(long start) {
    failRead();
    failedCheckAt(start);
    failedCheckAt(start + 1);
    failedCheckAt(start + 2);
    when(port.probe()).thenReturn(true);
    clock.set(T.plusSeconds(start + 3));
    service.probe();
    clock.set(T.plusSeconds(start + 70));
    service.probe();
    assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);
  }

  @Test
  void should_logEnterWarnAndExitInfo_withInstanceAndCause_noUserIdentifiers() {
    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      tripAtT();
      clock.set(T.plusSeconds(10));
      recoverNow();
      clock.set(T.plusSeconds(70));
      service.probe();

      assertThat(appender.list)
          .filteredOn(e -> "RBAC_EPOCH_DEGRADED_ENTER".equals(keyValues(e).get("event")))
          .singleElement()
          .satisfies(e -> {
            assertThat(e.getLevel()).isEqualTo(Level.WARN);
            assertThat(keyValues(e)).containsKeys("instance", "cause")
                .containsEntry("state", "open");
          });
      assertThat(appender.list)
          .filteredOn(e -> "RBAC_EPOCH_DEGRADED_EXIT".equals(keyValues(e).get("event")))
          .singleElement()
          .satisfies(e -> {
            assertThat(e.getLevel()).isEqualTo(Level.INFO);
            assertThat(keyValues(e)).containsKeys("instance", "cause");
          });
      assertThat(appender.list)
          .noneMatch(e -> e.getFormattedMessage().contains(USER.toString())
              || keyValues(e).values().stream().anyMatch(v -> USER.toString().equals(v.toString())));
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_publishStateGaugeAndEntryCounter_withoutUserTags() {
    assertThat(stateGauge("open")).isZero();
    tripAtT();
    assertThat(stateGauge("open")).isEqualTo(1.0);
    clock.set(T.plus(WINDOW));
    service.check(TENANT, USER, EPOCH);
    assertThat(stateGauge("open")).isZero();
    assertThat(stateGauge("closed")).isEqualTo(1.0);
    recoverNow();
    assertThat(stateGauge("recovering")).isEqualTo(1.0);
    assertThat(registry.get("nexus.rbac.epoch.degraded_entries").counter().count()).isEqualTo(1.0);
    assertThat(registry.getMeters())
        .allSatisfy(m -> m.getId().getTags().forEach(
            tag -> assertThat(tag.getValue()).doesNotContain(USER.toString())));
  }

  @Test
  void should_countCheckOutcomes_forDegradedVerdicts() {
    tripAtT();
    service.check(TENANT, USER, EPOCH);
    clock.set(T.plus(WINDOW));
    service.check(TENANT, USER, EPOCH);

    assertThat(outcomeCount("skipped_degraded")).isEqualTo(1.0);
    assertThat(outcomeCount("unavailable")).isEqualTo(1.0);
  }

  @Test
  void should_enterExactlyOnce_when_requestThreadsFailConcurrently() throws Exception {
    failRead();
    int threads = 32;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CountDownLatch start = new CountDownLatch(1);
    try {
      for (int i = 0; i < threads; i++) {
        pool.submit(() -> {
          start.await();
          return service.check(TENANT, USER, EPOCH);
        });
      }
      start.countDown();
    } finally {
      pool.shutdown();
      assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
    }

    assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_OPEN);
    assertThat(registry.get("nexus.rbac.epoch.degraded_entries").counter().count()).isEqualTo(1.0);
  }

  @Test
  void should_rejectNonPositiveSettings_when_constructed() {
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> new PermissionFreshnessService(
            port, userRoles, registry, clock, WINDOW, 0, Duration.ofSeconds(10),
            Duration.ofSeconds(60), KEY_TTL_SECONDS, REPLAY_CAPACITY, ROLE_REPLAY_CAPACITY,
            TENANT_PERCENT))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void should_rejectNonPositiveReplayCapacity_when_constructed() {
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> newService(registry, 0))
        .isInstanceOf(IllegalArgumentException.class);
  }

  // --- locally-known bumps (security review M-1) ---

  @Test
  void should_returnStale_when_readFailsButInstanceSawHigherEpoch() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));
    service.check(TENANT, USER, EPOCH);
    failRead();

    assertThat(service.check(TENANT, USER, EPOCH - 1)).isEqualTo(FreshnessVerdict.STALE);
    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);
  }

  @Test
  void should_returnStale_when_degradedOpenAndInstanceSawHigherEpoch() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));
    service.check(TENANT, USER, EPOCH);
    tripAtT();

    assertThat(service.check(TENANT, USER, EPOCH - 1)).isEqualTo(FreshnessVerdict.STALE);
    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.SKIPPED_DEGRADED);
  }

  @Test
  void should_returnStale_when_localBumpSucceededAndThenReadsFail() {
    storeWrites(EPOCH);
    service.invalidateUser(TENANT, USER, "revoke");
    failRead();

    assertThat(service.check(TENANT, USER, EPOCH - 1)).isEqualTo(FreshnessVerdict.STALE);
  }

  /** H-2: a token minted with the store's value is not refused when the instance then falls back. */
  @Test
  void should_notReturnStale_when_tokenCarriesTheEpochTheStoreWrote() {
    storeWrites(EPOCH);
    service.invalidateUser(TENANT, USER, "revoke");
    failRead();

    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);
  }

  /** H-2: the instance clock is far ahead of the store; the recorded epoch is still the store's. */
  @Test
  void should_mintStoreEpoch_when_instanceClockAheadOfStore() {
    long storeEpoch = T.toEpochMilli() - 60_000;
    storeWrites(storeEpoch);
    service.invalidateUser(TENANT, USER, "revoke");
    failRead();

    assertThat(service.epochForMint(TENANT, USER)).isEqualTo(storeEpoch);
    assertThat(service.check(TENANT, USER, storeEpoch)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);
  }

  @Test
  void should_recordWhatTheStoreWrote_when_clockBehindStore() {
    long storeEpoch = T.toEpochMilli() + 60_000;
    storeWrites(storeEpoch);
    service.invalidateUser(TENANT, USER, "revoke");
    failRead();

    assertThat(service.check(TENANT, USER, storeEpoch - 1)).isEqualTo(FreshnessVerdict.STALE);
  }

  @Test
  void should_recordLocalBumpForEveryHolder_when_fanOutSucceeds() {
    UUID other = UUID.fromString("00000000-0000-7000-8000-0000000000cc");
    storeWrites(EPOCH);
    service.invalidateHolders(TENANT, List.of(USER, other), "detach");
    when(port.current(any(), any())).thenReturn(OptionalLong.empty());

    assertThat(service.check(TENANT, other, EPOCH - 1)).isEqualTo(FreshnessVerdict.STALE);
  }

  /** L-5: a failed bump still leaves the lower bound {@code seen + 1}. */
  @Test
  void should_recordLowerBound_when_bumpFailsForUnseenUser() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    failRead();

    assertThat(service.check(TENANT, USER, 0L)).isEqualTo(FreshnessVerdict.STALE);
  }

  @Test
  void should_recordSeenPlusOne_when_bumpFailsForSeenUser() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));
    service.check(TENANT, USER, EPOCH);
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    failRead();

    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.STALE);
    assertThat(service.check(TENANT, USER, EPOCH + 1)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);
  }

  @Test
  void should_neverRecordMoreThanSeenPlusOne_when_bumpFails() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    failRead();

    assertThat(service.check(TENANT, USER, 1L)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);
  }

  @Test
  void should_recordLowerBoundForEveryUserNotSent_when_fanoutBatchFails() {
    List<UUID> holders = users(1001);
    failBumps();
    service.invalidateHolders(TENANT, holders, "detach");
    when(port.current(any(), any())).thenReturn(OptionalLong.empty());

    assertThat(service.check(TENANT, holders.get(1000), 0L)).isEqualTo(FreshnessVerdict.STALE);
  }

  @Test
  void should_forgetSeenEpoch_when_keyTtlElapsed() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));
    service.check(TENANT, USER, EPOCH);
    failRead();

    clock.set(T.plusSeconds(KEY_TTL_SECONDS));

    assertThat(service.check(TENANT, USER, 0L)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);
  }

  @Test
  void should_notStoreEpochZero_when_keyAbsent() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(0L));
    service.check(TENANT, USER, 0L);
    failRead();

    assertThat(service.check(TENANT, USER, 0L)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);
  }

  @Test
  void should_keepHighestEpoch_when_olderReadArrivesLater() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));
    service.check(TENANT, USER, EPOCH);
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH - 5));
    service.check(TENANT, USER, EPOCH);
    failRead();

    assertThat(service.check(TENANT, USER, EPOCH - 1)).isEqualTo(FreshnessVerdict.STALE);
  }

  @Test
  void should_mintWithSeenEpoch_when_readFailsAfterEarlierSuccess() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));
    service.epochForMint(TENANT, USER);
    failRead();

    assertThat(service.epochForMint(TENANT, USER)).isEqualTo(EPOCH);
  }

  @Test
  void should_mintWithSeenEpochWithoutReading_when_degraded() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));
    service.check(TENANT, USER, EPOCH);
    tripAtT();
    org.mockito.Mockito.clearInvocations(port);

    assertThat(service.epochForMint(TENANT, USER)).isEqualTo(EPOCH);
    clock.set(T.plus(WINDOW));
    assertThat(service.epochForMint(TENANT, USER)).isEqualTo(EPOCH);

    verify(port, never()).current(any(), any());
  }

  @Test
  void should_mintZeroWithoutReading_when_degradedAndNothingSeen() {
    tripAtT();
    org.mockito.Mockito.clearInvocations(port);

    assertThat(service.epochForMint(TENANT, UUID.randomUUID())).isZero();

    verify(port, never()).current(any(), any());
  }

  @Test
  void should_notCountMintReadFailures_towardsEntryWindow() {
    failRead();

    for (int i = 0; i < 10; i++) {
      service.epochForMint(TENANT, USER);
    }

    assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);
  }

  /** Fills the locally-seen map with {@code LAST_SEEN_CAPACITY} users, each tenant at its cap. */
  private void fillSeenMapToCapacity() {
    for (int tenant = 0; tenant < 100 / TENANT_PERCENT; tenant++) {
      fillTenantToCap(new UUID(1, tenant));
    }
  }

  private void fillTenantToCap(UUID tenantId) {
    when(port.current(any(), any())).thenReturn(OptionalLong.of(EPOCH));
    for (int i = 0; i < TENANT_CAP; i++) {
      service.check(tenantId, new UUID(0, i), EPOCH);
    }
  }

  private double lastSeenDropped(String reason) {
    return registry.get("nexus.rbac.epoch.last_seen_dropped").tag("reason", reason)
        .counter().count();
  }

  @Test
  void should_dropNewUsersAndCount_when_seenMapFull() {
    when(port.current(any(), any())).thenReturn(OptionalLong.of(EPOCH));
    fillSeenMapToCapacity();
    service.check(TENANT, USER, EPOCH);
    failRead();

    assertThat(service.check(TENANT, USER, 0L)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);
    assertThat(lastSeenDropped("capacity")).isEqualTo(1.0);
  }

  @Test
  void should_reclaimExpiredSlots_when_seenMapFullOfExpiredEntries() {
    when(port.current(any(), any())).thenReturn(OptionalLong.of(EPOCH));
    fillSeenMapToCapacity();
    clock.set(T.plusSeconds(KEY_TTL_SECONDS));
    service.probe();
    service.check(TENANT, USER, EPOCH);
    failRead();

    assertThat(service.check(TENANT, USER, 0L)).isEqualTo(FreshnessVerdict.STALE);
  }

  /** H-1: a full map is never scanned on a request thread; only the tick frees expired slots. */
  @Test
  void should_notScanOnRequestPath_when_seenMapFullOfExpiredEntries() {
    when(port.current(any(), any())).thenReturn(OptionalLong.of(EPOCH));
    fillSeenMapToCapacity();
    clock.set(T.plusSeconds(KEY_TTL_SECONDS));

    service.check(TENANT, USER, EPOCH);
    failRead();

    assertThat(service.check(TENANT, USER, 0L)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);
    assertThat(lastSeenDropped("capacity")).isEqualTo(1.0);
  }

  @Test
  void should_recordOwnBump_when_readCapacityFull() {
    when(port.current(any(), any())).thenReturn(OptionalLong.of(EPOCH));
    fillSeenMapToCapacity();
    storeWrites(EPOCH + 5);

    service.invalidateHolders(TENANT, List.of(USER), "detach");
    failRead();

    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.STALE);
    assertThat(lastSeenDropped("bump_dropped")).isZero();
    assertThat(seenCountersMatchMap()).isTrue();
  }

  @Test
  void should_dropNewUserAndCountTenantCap_when_oneTenantAtItsCap() {
    fillTenantToCap(TENANT);
    UUID newcomer = UUID.fromString("00000000-0000-7000-8000-0000000000cc");
    when(port.current(TENANT, newcomer)).thenReturn(OptionalLong.of(EPOCH));
    service.check(TENANT, newcomer, EPOCH);
    when(port.current(TENANT, newcomer)).thenReturn(OptionalLong.empty());

    assertThat(service.check(TENANT, newcomer, 0L)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);
    assertThat(lastSeenDropped("tenant_cap")).isEqualTo(1.0);
    assertThat(lastSeenDropped("capacity")).isZero();
  }

  @Test
  void should_stillRecordOtherTenant_when_oneTenantAtItsCap() {
    fillTenantToCap(TENANT);
    UUID otherTenant = UUID.fromString("00000000-0000-7000-8000-0000000000ad");
    when(port.current(otherTenant, USER)).thenReturn(OptionalLong.of(EPOCH));
    service.check(otherTenant, USER, EPOCH);
    when(port.current(otherTenant, USER)).thenReturn(OptionalLong.empty());

    assertThat(service.check(otherTenant, USER, 0L)).isEqualTo(FreshnessVerdict.STALE);
  }

  @Test
  void should_acceptLastSlotOfTenant_when_oneBelowCap() {
    when(port.current(any(), any())).thenReturn(OptionalLong.of(EPOCH));
    for (int i = 0; i < TENANT_CAP - 1; i++) {
      service.check(TENANT, new UUID(0, i), EPOCH);
    }

    service.check(TENANT, USER, EPOCH);

    assertThat(registry.get("nexus.rbac.epoch.last_seen_dropped").counters())
        .allSatisfy(counter -> assertThat(counter.count()).isZero());
  }

  @Test
  void should_raiseEpochOfKnownUser_when_tenantAtCap() {
    fillTenantToCap(TENANT);
    when(port.current(TENANT, new UUID(0, 0))).thenReturn(OptionalLong.of(EPOCH + 9));
    service.check(TENANT, new UUID(0, 0), EPOCH);
    when(port.current(TENANT, new UUID(0, 0))).thenReturn(OptionalLong.empty());

    assertThat(service.check(TENANT, new UUID(0, 0), EPOCH + 5)).isEqualTo(FreshnessVerdict.STALE);
    assertThat(lastSeenDropped("tenant_cap")).isZero();
  }

  @Test
  void should_freeTenantSlots_when_tickPurgesExpiredEntries() {
    fillTenantToCap(TENANT);
    clock.set(T.plusSeconds(KEY_TTL_SECONDS));
    service.probe();

    service.check(TENANT, USER, EPOCH);

    assertThat(registry.get("nexus.rbac.epoch.last_seen_dropped").counters())
        .allSatisfy(counter -> assertThat(counter.count()).isZero());
  }

  // --- own bumps are never dropped by the read bounds, and tenants do not share a pool ---

  @Test
  void should_recordOwnBump_when_tenantAtItsReadCap() {
    fillTenantToCap(TENANT);
    storeWrites(EPOCH + 5);

    service.invalidateHolders(TENANT, List.of(USER), "detach");
    failRead();

    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.STALE);
    assertThat(lastSeenDropped("tenant_cap")).isZero();
    assertThat(lastSeenDropped("bump_dropped")).isZero();
    assertThat(seenCountersMatchMap()).isTrue();
  }

  @Test
  void should_recordFailedBumpLowerBound_when_tenantAtItsReadCap() {
    fillTenantToCap(TENANT);
    failBumps();

    service.invalidateUser(TENANT, USER, "revoke");
    failRead();

    assertThat(service.check(TENANT, USER, 0L)).isEqualTo(FreshnessVerdict.STALE);
  }

  @Test
  void should_recordReplayedBump_when_tenantAtItsReadCap() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    clock.set(T.plusSeconds(1));
    fillTenantToCap(TENANT);
    storeWrites(EPOCH + 7);

    service.probe();
    failRead();

    assertThat(service.check(TENANT, USER, EPOCH + 6)).isEqualTo(FreshnessVerdict.STALE);
  }

  @Test
  void should_moveEntryToBumpPool_when_readDerivedUserIsBumped() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));
    service.check(TENANT, USER, EPOCH);
    storeWrites(EPOCH + 5);

    service.invalidateHolders(TENANT, List.of(USER), "detach");

    assertThat(seenCountersMatchMap()).isTrue();
    assertThat(service.lastSeenCountsFromCounters().bumps()).containsEntry(TENANT, 1);
    assertThat(service.lastSeenCountsFromCounters().reads()).doesNotContainKey(TENANT);
  }

  @Test
  void should_dropOnlyBeyondTenantCeilingAndCount_when_oneTenantDetachesHugeRole() {
    storeWrites(EPOCH + 5);
    int ceiling = TENANT_CAP * PermissionFreshnessService.LAST_SEEN_BUMP_CEILING_FACTOR;
    service.invalidateHolders(TENANT, users(ceiling), "detach");
    assertThat(lastSeenDropped("bump_dropped")).isZero();

    service.invalidateHolders(TENANT, List.of(USER), "detach");

    assertThat(lastSeenDropped("bump_dropped")).isEqualTo(1.0);
  }

  @Test
  void should_stillRecordOtherTenantRevocationAndReads_when_oneTenantFilledItsBumpCeiling() {
    UUID other = UUID.fromString("00000000-0000-7000-8000-0000000000ad");
    storeWrites(EPOCH + 5);
    int ceiling = TENANT_CAP * PermissionFreshnessService.LAST_SEEN_BUMP_CEILING_FACTOR;
    service.invalidateHolders(TENANT, users(ceiling + 10), "detach");

    service.invalidateHolders(other, List.of(USER), "detach");
    UUID reader = UUID.randomUUID();
    when(port.current(other, reader)).thenReturn(OptionalLong.of(EPOCH));
    service.check(other, reader, EPOCH);
    when(port.current(other, USER)).thenReturn(OptionalLong.empty());

    assertThat(service.check(other, USER, EPOCH)).isEqualTo(FreshnessVerdict.STALE);
    assertThat(lastSeenDropped("capacity")).isZero();
    assertThat(lastSeenDropped("tenant_cap")).isZero();
    assertThat(lastSeenDropped("bump_dropped")).isEqualTo(10.0);
    assertThat(seenCountersMatchMap()).isTrue();
  }

  @Test
  void should_notCountOtherTenantsBumpEntriesTowardsReadCapacity_when_readsArrive() {
    storeWrites(EPOCH + 5);
    int ceiling = TENANT_CAP * PermissionFreshnessService.LAST_SEEN_BUMP_CEILING_FACTOR;
    for (int tenant = 0; tenant < 3; tenant++) {
      service.invalidateHolders(new UUID(4, tenant), users(ceiling), "detach");
    }

    fillSeenMapToCapacity();

    assertThat(lastSeenDropped("capacity")).isZero();
    assertThat(lastSeenDropped("tenant_cap")).isZero();
  }

  @Test
  void should_notEvictBumpEntry_when_readsFillTenant() {
    storeWrites(EPOCH + 5);
    service.invalidateHolders(TENANT, users(TENANT_CAP), "detach");
    when(port.current(any(), any())).thenReturn(OptionalLong.of(EPOCH));

    service.check(TENANT, USER, EPOCH);

    assertThat(lastSeenDropped("tenant_cap")).isZero();
    assertThat(seenCountersMatchMap()).isTrue();
  }

  // --- global bound on the own-bump pool, and fail closed for a tenant that lost a bump ---

  private static final int BUMP_CEILING =
      TENANT_CAP * PermissionFreshnessService.LAST_SEEN_BUMP_CEILING_FACTOR;

  /** Fills the global own-bump bound with whole-ceiling tenants; returns how many were used. */
  private int fillGlobalBumpPool() {
    storeWrites(EPOCH + 5);
    int tenants = PermissionFreshnessService.LAST_SEEN_BUMP_GLOBAL_LIMIT / BUMP_CEILING;
    for (int i = 0; i < tenants; i++) {
      service.invalidateHolders(new UUID(5, i), users(BUMP_CEILING), "detach");
    }
    return tenants;
  }

  @Test
  void should_dropAndCount_when_manyTenantsFillTheGlobalBumpBound() {
    int tenants = fillGlobalBumpPool();
    assertThat(lastSeenDropped("bump_dropped")).isZero();

    service.invalidateHolders(new UUID(5, tenants), List.of(USER), "detach");

    assertThat(lastSeenDropped("bump_dropped")).isEqualTo(1.0);
    assertThat(seenCountersMatchMap()).isTrue();
    assertThat(service.lastSeenCountsFromCounters().bumpTotal())
        .isEqualTo(PermissionFreshnessService.LAST_SEEN_BUMP_GLOBAL_LIMIT);
  }

  @Test
  void should_releaseGlobalBumpSlots_when_entriesExpire() {
    int tenants = fillGlobalBumpPool();
    clock.set(T.plusSeconds(KEY_TTL_SECONDS));
    service.probe();

    service.invalidateHolders(new UUID(5, tenants), List.of(USER), "detach");

    assertThat(lastSeenDropped("bump_dropped")).isZero();
    assertThat(service.lastSeenCountsFromCounters().bumpTotal()).isEqualTo(1);
    assertThat(seenCountersMatchMap()).isTrue();
  }

  @Test
  void should_failClosedForTenant_when_ownBumpRefusedAndStoreDown() {
    UUID victim = UUID.fromString("00000000-0000-7000-8000-0000000000ad");
    storeWrites(EPOCH + 5);
    service.invalidateHolders(victim, users(BUMP_CEILING), "detach");
    service.invalidateHolders(victim, List.of(USER), "detach");
    when(port.current(any(), any())).thenReturn(OptionalLong.empty());

    assertThat(service.check(victim, UUID.randomUUID(), EPOCH))
        .isEqualTo(FreshnessVerdict.STALE);
    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);
  }

  @Test
  void should_failClosedForTenant_when_ownBumpRefusedAndInstanceDegradedOpen() {
    UUID victim = UUID.fromString("00000000-0000-7000-8000-0000000000ad");
    storeWrites(EPOCH + 5);
    service.invalidateHolders(victim, users(BUMP_CEILING + 1), "detach");
    tripAtT();

    assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_OPEN);
    assertThat(service.check(victim, UUID.randomUUID(), EPOCH))
        .isEqualTo(FreshnessVerdict.STALE);
    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.SKIPPED_DEGRADED);
  }

  @Test
  void should_notFailClosed_when_storeAnswersFresh() {
    UUID victim = UUID.fromString("00000000-0000-7000-8000-0000000000ad");
    storeWrites(EPOCH + 5);
    service.invalidateHolders(victim, users(BUMP_CEILING + 1), "detach");
    UUID reader = UUID.randomUUID();
    when(port.current(victim, reader)).thenReturn(OptionalLong.of(EPOCH));

    assertThat(service.check(victim, reader, EPOCH)).isEqualTo(FreshnessVerdict.FRESH);
  }

  @Test
  void should_stopFailingClosed_when_markerOlderThanKeyTtl() {
    UUID victim = UUID.fromString("00000000-0000-7000-8000-0000000000ad");
    storeWrites(EPOCH + 5);
    service.invalidateHolders(victim, users(BUMP_CEILING + 1), "detach");
    when(port.current(any(), any())).thenReturn(OptionalLong.empty());
    clock.set(T.plusSeconds(KEY_TTL_SECONDS - 1));
    assertThat(service.check(victim, UUID.randomUUID(), EPOCH)).isEqualTo(FreshnessVerdict.STALE);

    clock.set(T.plusSeconds(KEY_TTL_SECONDS));
    service.probe();

    assertThat(service.check(victim, UUID.randomUUID(), EPOCH))
        .isEqualTo(FreshnessVerdict.SKIPPED_ERROR);
  }

  @Test
  void should_failClosedForEveryTenant_when_lostTenantSetIsFull() {
    int tenants = fillGlobalBumpPool();
    for (int i = 0; i <= PermissionFreshnessService.LOST_TENANTS_MAX; i++) {
      service.invalidateHolders(new UUID(6, i), List.of(USER), "detach");
    }
    when(port.current(any(), any())).thenReturn(OptionalLong.empty());

    assertThat(service.check(new UUID(7, 1), UUID.randomUUID(), EPOCH))
        .isEqualTo(FreshnessVerdict.STALE);
    assertThat(tenants).isPositive();
  }

  @Test
  void should_countDroppedAndKeepEpoch_when_readToBumpMoveRefused() {
    storeWrites(EPOCH + 5);
    service.invalidateHolders(TENANT, users(BUMP_CEILING), "detach");
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));
    service.check(TENANT, USER, EPOCH);

    service.invalidateHolders(TENANT, List.of(USER), "detach");
    failRead();

    assertThat(lastSeenDropped("bump_dropped")).isEqualTo(1.0);
    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.STALE);
    assertThat(seenCountersMatchMap()).isTrue();
  }

  // --- role replay: the in-flight slot follows the thread, not the future ---

  @Test
  void should_readAgainOnNextTick_when_earlierReadWasCancelledBeforeItRan() throws Exception {
    CountDownLatch release = new CountDownLatch(1);
    java.util.concurrent.Future<?> blocker = service.runOnRoleReadThread(() -> {
      try {
        release.await(30, TimeUnit.SECONDS);
      } catch (InterruptedException ignored) {
        Thread.currentThread().interrupt();
      }
    });
    service.holderReadFailed(TENANT, ROLE, "detach");
    holdersOfRole(USER);
    storeWrites(EPOCH + 5);

    service.probe();

    assertThat(roleQueueSize()).isEqualTo(1.0);
    assertThat(service.roleReadInFlight()).isFalse();
    blocker.cancel(false);
    release.countDown();
    service.probe();
    assertThat(roleQueueSize()).isZero();
    verify(port).bump(TENANT, List.of(USER));
  }

  // --- tenant slot accounting under concurrency (coordinator review, finding 2) ---

  @Test
  void should_keepTenantCountersEqualToMap_when_purgeRacesReadsAndBumps() throws Exception {
    when(port.current(any(), any())).thenReturn(OptionalLong.of(EPOCH));
    storeWrites(EPOCH + 5);
    List<UUID> tenants = List.of(new UUID(3, 1), new UUID(3, 2));
    List<UUID> people = users(40);
    ExecutorService pool = Executors.newFixedThreadPool(4);
    CountDownLatch go = new CountDownLatch(1);
    List<java.util.concurrent.Future<?>> work = new java.util.ArrayList<>();
    for (int worker = 0; worker < 2; worker++) {
      work.add(pool.submit(() -> {
        go.await();
        for (int i = 0; i < 3000; i++) {
          service.check(tenants.get(i % 2), people.get(i % people.size()), EPOCH);
        }
        return null;
      }));
    }
    work.add(pool.submit(() -> {
      go.await();
      for (int i = 0; i < 3000; i++) {
        service.invalidateHolders(tenants.get(i % 2), List.of(people.get(i % people.size())), "x");
      }
      return null;
    }));
    work.add(pool.submit(() -> {
      go.await();
      for (int i = 0; i < 3000; i++) {
        clock.set(T.plusSeconds((i % 3) * KEY_TTL_SECONDS));
        service.probe();
      }
      return null;
    }));
    go.countDown();
    for (java.util.concurrent.Future<?> f : work) {
      f.get(60, TimeUnit.SECONDS);
    }
    pool.shutdownNow();

    assertThat(seenCountersMatchMap()).isTrue();
  }

  // --- role replay read is bounded (coordinator review, finding 3) ---

  @Test
  void should_requeueWithOriginalTimeAndKeepTickRunning_when_holderReadHangs() throws Exception {
    CountDownLatch release = new CountDownLatch(1);
    when(userRoles.findActiveUserIdsForRole(ROLE)).thenAnswer(invocation -> {
      // Like a JDBC call stuck in a socket read: an interrupt does not end it.
      long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
      while (release.getCount() > 0 && System.nanoTime() < deadline) {
        try {
          release.await(100, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ignored) {
          // keep waiting
        }
      }
      return List.of(USER);
    });
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    service.holderReadFailed(TENANT, ROLE, "detach");
    bumpsSucceed();
    org.mockito.Mockito.clearInvocations(port);
    long started = System.nanoTime();

    service.probe();

    assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(5));
    assertThat(roleQueueSize()).isEqualTo(1.0);
    assertThat(bumpFailed("role_replay", "holder_read")).isEqualTo(1.0);
    verify(port).bump(TENANT, List.of(USER));
    assertThat(replayQueueUsers()).isZero();

    service.probe();
    verify(userRoles, times(1)).findActiveUserIdsForRole(ROLE);

    release.countDown();
    clock.set(T.plusSeconds(KEY_TTL_SECONDS));
    awaitRoleReadIdle();
    service.probe();
    verify(userRoles, times(1)).findActiveUserIdsForRole(ROLE);
    assertThat(roleQueueSize()).isZero();
  }

  private void awaitRoleReadIdle() throws InterruptedException {
    long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
    while (service.roleReadInFlight() && System.nanoTime() < deadline) {
      Thread.sleep(20);
    }
    assertThat(service.roleReadInFlight()).isFalse();
  }

  private boolean seenCountersMatchMap() {
    return service.lastSeenCountsFromMap().equals(service.lastSeenCountsFromCounters());
  }

  @Test
  void should_capEachTenantSeparately_when_tenantPercentIsOne() {
    SimpleMeterRegistry meters = new SimpleMeterRegistry();
    PermissionFreshnessService small =
        newService(meters, REPLAY_CAPACITY, ROLE_REPLAY_CAPACITY, 1);
    when(port.current(any(), any())).thenReturn(OptionalLong.of(EPOCH));
    int cap = PermissionFreshnessService.LAST_SEEN_CAPACITY / 100;
    for (int i = 0; i <= cap; i++) {
      small.check(TENANT, new UUID(0, i), EPOCH);
    }

    assertThat(meters.get("nexus.rbac.epoch.last_seen_dropped").tag("reason", "tenant_cap")
            .counter().count())
        .isEqualTo(1.0);
  }

  @Test
  void should_rejectTenantPercentOutsideOneToHundred_when_constructed() {
    org.assertj.core.api.Assertions.assertThatThrownBy(
            () -> newService(new SimpleMeterRegistry(), REPLAY_CAPACITY, 10, 0))
        .isInstanceOf(IllegalArgumentException.class);
    org.assertj.core.api.Assertions.assertThatThrownBy(
            () -> newService(new SimpleMeterRegistry(), REPLAY_CAPACITY, 10, 101))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatCode(() -> newService(new SimpleMeterRegistry(), REPLAY_CAPACITY, 10, 100))
        .doesNotThrowAnyException();
    assertThatCode(() -> newService(new SimpleMeterRegistry(), REPLAY_CAPACITY, 10, 1))
        .doesNotThrowAnyException();
  }

  @Test
  void should_rejectNonPositiveRoleCapacity_when_constructed() {
    org.assertj.core.api.Assertions.assertThatThrownBy(
            () -> newService(new SimpleMeterRegistry(), REPLAY_CAPACITY, 0, TENANT_PERCENT))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void should_keepLiveEntries_when_tickPurgesExpired() {
    when(port.current(any(), any())).thenReturn(OptionalLong.of(EPOCH));
    service.check(TENANT, USER, EPOCH);
    clock.set(T.plusSeconds(KEY_TTL_SECONDS - 1));

    service.probe();
    failRead();

    assertThat(service.check(TENANT, USER, EPOCH - 1)).isEqualTo(FreshnessVerdict.STALE);
  }

  // --- lost-bump replay (T-012, design §9.3) ---

  private void failBumps() {
    doThrow(new QueryTimeoutException("bump timeout")).when(port).bump(any(), anyCollection());
  }

  private void bumpsSucceed() {
    doReturn(Map.of()).when(port).bump(any(), anyCollection());
  }

  /** The store writes {@code epoch} for every bumped user and reports it (H-2). */
  private void storeWrites(long epoch) {
    doAnswer(invocation -> {
      Map<UUID, Long> written = new HashMap<>();
      for (Object userId : (java.util.Collection<?>) invocation.getArgument(1)) {
        written.put((UUID) userId, epoch);
      }
      return written;
    }).when(port).bump(any(), anyCollection());
  }

  private double replayQueueUsers() {
    return registry.get("nexus.rbac.epoch.replay_queue_users").gauge().value();
  }

  private double bumpFailed(String operation, String reason) {
    return registry.get("nexus.rbac.epoch.bump_failed")
        .tags("operation", operation, "reason", reason).counter().count();
  }

  private double bumpReplayed() {
    return registry.get("nexus.rbac.epoch.bump_replayed").counter().count();
  }

  @Test
  void should_replayOnNextTick_when_healthyAndBumpFailedOnce() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    bumpsSucceed();
    org.mockito.Mockito.clearInvocations(port);
    clock.set(T.plusSeconds(1));

    service.probe();

    verify(port).bump(TENANT, List.of(USER));
    verify(port, never()).probe();
    assertThat(replayQueueUsers()).isZero();
    assertThat(bumpReplayed()).isEqualTo(1.0);
    assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);
  }

  @Test
  void should_notTouchStore_when_healthyAndQueueEmpty() {
    service.probe();

    verifyNoInteractions(port);
  }

  @Test
  void should_reportQueuedUsers_when_bumpFails() {
    failBumps();

    service.invalidateUser(TENANT, USER, "revoke");

    assertThat(replayQueueUsers()).isEqualTo(1.0);
  }

  @Test
  void should_enqueueFailedBatchAndEveryUnsentBatch_when_fanoutBatchFails() {
    List<UUID> holders = users(1001);
    doReturn(Map.of())
        .doThrow(new QueryTimeoutException("timeout"))
        .when(port).bump(any(), anyCollection());

    service.invalidateHolders(TENANT, holders, "detach");

    assertThat(replayQueueUsers()).isEqualTo(501.0);
    bumpsSucceed();
    org.mockito.Mockito.clearInvocations(port);
    service.probe();
    verify(port).bump(TENANT, holders.subList(500, 1000));
    verify(port).bump(TENANT, holders.subList(1000, 1001));
    verify(port, times(2)).bump(any(), anyCollection());
  }

  @Test
  void should_replayInBatchesOf500_when_queueLarge() {
    List<UUID> holders = users(1200);
    failBumps();
    service.invalidateHolders(TENANT, holders, "detach");
    bumpsSucceed();
    org.mockito.Mockito.clearInvocations(port);

    service.probe();

    InOrder order = inOrder(port);
    order.verify(port).bump(TENANT, holders.subList(0, 500));
    order.verify(port).bump(TENANT, holders.subList(500, 1000));
    order.verify(port).bump(TENANT, holders.subList(1000, 1200));
    assertThat(replayQueueUsers()).isZero();
    assertThat(bumpReplayed()).isEqualTo(1200.0);
  }

  @Test
  void should_requeueRemainderWithOriginalFailedAt_when_drainFailsPartway() {
    List<UUID> holders = users(1001);
    failBumps();
    service.invalidateHolders(TENANT, holders, "detach");
    clock.set(T.plusSeconds(5));
    doReturn(Map.of())
        .doThrow(new QueryTimeoutException("timeout"))
        .when(port).bump(any(), anyCollection());

    service.probe();

    assertThat(replayQueueUsers()).isEqualTo(501.0);
    bumpsSucceed();
    clock.set(T.plusSeconds(8));
    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.probe();
    } finally {
      stopLogCapture(appender);
    }
    assertThat(replayQueueUsers()).isZero();
    assertThat(appender.list).filteredOn(event -> event.getLevel() == Level.INFO)
        .allSatisfy(event -> assertThat(keyValues(event)).containsEntry("ageMs", 8000L));
  }

  @Test
  void should_notLoseEntries_when_drainBatchFails() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    clock.set(T.plusSeconds(1));

    service.probe();
    service.probe();

    assertThat(replayQueueUsers()).isEqualTo(1.0);
  }

  @Test
  void should_dropEntriesOlderThanKeyTtl_when_draining() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    bumpsSucceed();
    org.mockito.Mockito.clearInvocations(port);
    clock.set(T.plusSeconds(KEY_TTL_SECONDS));

    service.probe();

    verify(port, never()).bump(any(), anyCollection());
    assertThat(replayQueueUsers()).isZero();
  }

  @Test
  void should_replayEntryJustInsideKeyTtl() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    bumpsSucceed();
    clock.set(T.plusSeconds(KEY_TTL_SECONDS - 1));

    service.probe();

    verify(port, times(2)).bump(any(), anyCollection());
  }

  @Test
  void should_dropNewestAndCountPerDroppedId_when_replayQueueFull() {
    registry = new SimpleMeterRegistry();
    service = newService(registry, 2);
    failBumps();

    service.invalidateHolders(TENANT, users(5), "detach");

    assertThat(replayQueueUsers()).isEqualTo(2.0);
    assertThat(bumpFailed("detach", "overflow")).isEqualTo(3.0);
    assertThat(bumpFailed("detach", "redis")).isEqualTo(1.0);
  }

  @Test
  void should_coalesceRepeatedFailuresOfOneUser() {
    failBumps();

    service.invalidateUser(TENANT, USER, "revoke");
    service.invalidateUser(TENANT, USER, "revoke");

    assertThat(replayQueueUsers()).isEqualTo(1.0);
  }

  @Test
  void should_countRedisFailure_when_bumpFails() {
    failBumps();

    service.invalidateUser(TENANT, USER, "revoke");

    assertThat(bumpFailed("revoke", "redis")).isEqualTo(1.0);
  }

  @Test
  void should_logBumpFailedWithoutUserIds_when_drainFails() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.probe();
    } finally {
      stopLogCapture(appender);
    }

    assertThat(appender.list).singleElement().satisfies(event -> {
      assertThat(event.getLevel()).isEqualTo(Level.ERROR);
      assertThat(keyValues(event))
          .containsEntry("event", "RBAC_EPOCH_BUMP_FAILED")
          .containsEntry("operation", "replay")
          .containsEntry("tenantId", TENANT)
          .containsEntry("userCount", 1);
      assertThat(event.getFormattedMessage() + keyValues(event)).doesNotContain(USER.toString());
    });
    assertThat(bumpFailed("replay", "redis")).isEqualTo(1.0);
  }

  @Test
  void should_logReplayedWithTenantCountAndAge_when_drainSucceeds() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    bumpsSucceed();
    clock.set(T.plusMillis(1500));
    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.probe();
    } finally {
      stopLogCapture(appender);
    }

    assertThat(appender.list).singleElement().satisfies(event -> {
      assertThat(event.getLevel()).isEqualTo(Level.INFO);
      assertThat(keyValues(event))
          .containsEntry("event", "RBAC_EPOCH_BUMP_REPLAYED")
          .containsEntry("tenantId", TENANT)
          .containsEntry("userCount", 1)
          .containsEntry("ageMs", 1500L);
      assertThat(event.getFormattedMessage() + keyValues(event)).doesNotContain(USER.toString());
    });
  }

  @Test
  void should_recordWhatTheStoreWrote_when_replaySucceeds() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    storeWrites(EPOCH);
    service.probe();
    failRead();

    assertThat(service.check(TENANT, USER, EPOCH - 1)).isEqualTo(FreshnessVerdict.STALE);
    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.SKIPPED_ERROR);
  }

  @Test
  void should_notProbeOrDrain_when_degradedAndProbeFails() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    tripAtT();
    when(port.probe()).thenReturn(false);
    org.mockito.Mockito.clearInvocations(port);
    bumpsSucceed();

    service.probe();

    verify(port, never()).bump(any(), anyCollection());
    assertThat(replayQueueUsers()).isEqualTo(1.0);
  }

  @Test
  void should_stayDegradedUntilDrainSucceeds_when_probeSucceeds() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    tripAtT();
    clock.set(T.plusSeconds(10));
    recoverNow();

    assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_OPEN);

    bumpsSucceed();
    clock.set(T.plusSeconds(11));
    service.probe();

    assertThat(service.state()).isEqualTo(DegradedState.RECOVERING);
    assertThat(replayQueueUsers()).isZero();
  }

  @Test
  void should_drainThenRecoverInSameTick_when_degradedAndProbeSucceeds() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    tripAtT();
    bumpsSucceed();
    clock.set(T.plusSeconds(10));

    recoverNow();

    assertThat(service.state()).isEqualTo(DegradedState.RECOVERING);
  }

  /** RC-53: a write-only Redis failure never turns off checks that reads still enforce. */
  @Test
  void should_stayHealthyAndEnforce_when_drainsKeepFailingButReadsSucceed() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));

    for (int second = 1; second <= 60; second++) {
      clock.set(T.plusSeconds(second));
      service.probe();
      assertThat(service.check(TENANT, USER, EPOCH - 1)).isEqualTo(FreshnessVerdict.STALE);
    }

    assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);
    assertThat(bumpFailed("replay", "redis")).isEqualTo(60.0);
    assertThat(replayQueueUsers()).isEqualTo(1.0);
  }

  @Test
  void should_neverTripOrRelapse_when_onlyBumpsAndDrainsFail() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    tripAtT();
    clock.set(T.plusSeconds(100));
    bumpsSucceed();
    recoverNow();
    failBumps();

    for (int second = 101; second <= 130; second++) {
      clock.set(T.plusSeconds(second));
      service.invalidateUser(TENANT, UUID.randomUUID(), "revoke");
      service.probe();
    }

    assertThat(service.state()).isEqualTo(DegradedState.RECOVERING);
  }

  /** L-4: a drain failure while Recovering does not reset the 60 s sustain. */
  @Test
  void should_reachHealthy60sAfterProbeSuccess_when_drainFailsWhileRecovering() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    tripAtT();
    bumpsSucceed();
    clock.set(T.plusSeconds(100));
    recoverNow();
    assertThat(service.state()).isEqualTo(DegradedState.RECOVERING);
    failBumps();
    clock.set(T.plusSeconds(110));
    service.invalidateUser(TENANT, USER, "revoke");
    clock.set(T.plusSeconds(120));
    service.probe();
    clock.set(T.plusSeconds(159));
    service.probe();
    assertThat(service.state()).isEqualTo(DegradedState.RECOVERING);

    clock.set(T.plusSeconds(160));
    service.probe();

    assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);
  }

  @Test
  void should_registerReplayCountersAtZero_when_constructed() {
    assertThat(replayQueueUsers()).isZero();
    assertThat(bumpReplayed()).isZero();
  }

  // --- review fixes: M-1, M-2, L-1, L-2, L-3 ---

  /** M-1: a coalesced user is replayed while their newest lost bump is inside the key TTL. */
  @Test
  void should_replayCoalescedUser_when_newestLostBumpInsideTtlButOldestExpired() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    clock.set(T.plusSeconds(900));
    service.invalidateUser(TENANT, USER, "revoke");
    bumpsSucceed();
    org.mockito.Mockito.clearInvocations(port);
    clock.set(T.plusSeconds(KEY_TTL_SECONDS));

    service.probe();

    verify(port).bump(TENANT, List.of(USER));
    assertThat(bumpReplayed()).isEqualTo(1.0);
  }

  @Test
  void should_dropCoalescedUser_when_newestLostBumpAlsoOlderThanTtl() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    clock.set(T.plusSeconds(10));
    service.invalidateUser(TENANT, USER, "revoke");
    bumpsSucceed();
    org.mockito.Mockito.clearInvocations(port);
    clock.set(T.plusSeconds(10 + KEY_TTL_SECONDS));

    service.probe();

    verify(port, never()).bump(any(), anyCollection());
    assertThat(replayQueueUsers()).isZero();
  }

  /** M-2: the paging counter for a detach whose holders could not be read. */
  @Test
  void should_countHolderReadFailureAsPagingSignal() {
    service.holderReadFailed(TENANT, ROLE, "detach");

    assertThat(bumpFailed("detach", "holder_read")).isEqualTo(1.0);
  }

  // --- role-level replay (security review part 2, M-2) ---

  private double roleQueueSize() {
    return registry.get("nexus.rbac.epoch.role_replay_queue_roles").gauge().value();
  }

  private double rolesReplayed() {
    return registry.get("nexus.rbac.epoch.role_replayed").counter().count();
  }

  private void holdersOfRole(UUID... holders) {
    when(userRoles.findActiveUserIdsForRole(ROLE)).thenReturn(List.of(holders));
  }

  @Test
  void should_queueRole_when_holderReadFailed() {
    service.holderReadFailed(TENANT, ROLE, "detach");

    assertThat(roleQueueSize()).isEqualTo(1.0);
  }

  @Test
  void should_queueRoleOnce_when_sameRoleFailsTwice() {
    service.holderReadFailed(TENANT, ROLE, "detach");
    service.holderReadFailed(TENANT, ROLE, "detach");

    assertThat(roleQueueSize()).isEqualTo(1.0);
  }

  @Test
  void should_bumpEveryHolderAndEmptyQueue_when_tickResolvesRole() {
    UUID other = UUID.randomUUID();
    service.holderReadFailed(TENANT, ROLE, "detach");
    holdersOfRole(USER, other);
    storeWrites(EPOCH + 5);

    service.probe();

    verify(port).bump(TENANT, List.of(USER, other));
    assertThat(roleQueueSize()).isZero();
    assertThat(rolesReplayed()).isEqualTo(1.0);
  }

  @Test
  void should_makeHolderTokensStale_when_roleResolvedAfterFailedRead() {
    service.holderReadFailed(TENANT, ROLE, "detach");
    holdersOfRole(USER);
    storeWrites(EPOCH + 5);
    service.probe();
    failRead();

    assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.STALE);
  }

  @Test
  void should_notReadHolders_when_nothingQueued() {
    service.probe();

    verifyNoInteractions(userRoles);
  }

  @Test
  void should_keepRoleQueuedAndCount_when_holderReadFailsOnTick() {
    service.holderReadFailed(TENANT, ROLE, "detach");
    when(userRoles.findActiveUserIdsForRole(ROLE))
        .thenThrow(new QueryTimeoutException("db down"));

    service.probe();

    assertThat(roleQueueSize()).isEqualTo(1.0);
    assertThat(bumpFailed("role_replay", "holder_read")).isEqualTo(1.0);
    verify(port, never()).bump(any(), anyCollection());
  }

  @Test
  void should_resolveRole_when_holderReadRecoversOnLaterTick() {
    service.holderReadFailed(TENANT, ROLE, "detach");
    when(userRoles.findActiveUserIdsForRole(ROLE))
        .thenThrow(new QueryTimeoutException("db down"))
        .thenReturn(List.of(USER));
    storeWrites(EPOCH + 5);

    service.probe();
    service.probe();

    verify(port).bump(TENANT, List.of(USER));
    assertThat(roleQueueSize()).isZero();
  }

  @Test
  void should_keepOneErrorLinePerTick_when_holderReadKeepsFailing() {
    service.holderReadFailed(TENANT, ROLE, "detach");
    UUID otherRole = UUID.randomUUID();
    service.holderReadFailed(TENANT, otherRole, "detach");
    when(userRoles.findActiveUserIdsForRole(any()))
        .thenThrow(new QueryTimeoutException("db down"));

    service.probe();

    verify(userRoles, times(1)).findActiveUserIdsForRole(any());
    assertThat(roleQueueSize()).isEqualTo(2.0);
  }

  @Test
  void should_dropRoleWithoutReading_when_newestFailureOlderThanKeyTtl() {
    service.holderReadFailed(TENANT, ROLE, "detach");
    holdersOfRole(USER);
    clock.set(T.plusSeconds(KEY_TTL_SECONDS));

    service.probe();

    verify(userRoles, never()).findActiveUserIdsForRole(any());
    assertThat(roleQueueSize()).isZero();
  }

  @Test
  void should_stillResolveRole_when_oneSecondBeforeKeyTtl() {
    service.holderReadFailed(TENANT, ROLE, "detach");
    holdersOfRole(USER);
    storeWrites(EPOCH + 5);
    clock.set(T.plusSeconds(KEY_TTL_SECONDS - 1));

    service.probe();

    verify(port).bump(TENANT, List.of(USER));
  }

  @Test
  void should_extendLife_when_sameRoleFailsAgainLater() {
    service.holderReadFailed(TENANT, ROLE, "detach");
    clock.set(T.plusSeconds(500));
    service.holderReadFailed(TENANT, ROLE, "detach");
    holdersOfRole(USER);
    storeWrites(EPOCH + 5);
    clock.set(T.plusSeconds(KEY_TTL_SECONDS + 100));

    service.probe();

    verify(port).bump(TENANT, List.of(USER));
  }

  @Test
  void should_queueHoldersForUserReplay_when_roleResolvedButBumpFails() {
    service.holderReadFailed(TENANT, ROLE, "detach");
    holdersOfRole(USER, UUID.randomUUID());
    failBumps();

    service.probe();

    assertThat(roleQueueSize()).isZero();
    assertThat(replayQueueUsers()).isEqualTo(2.0);
  }

  @Test
  void should_resolveRoleWithoutBump_when_roleHasNoHolders() {
    service.holderReadFailed(TENANT, ROLE, "detach");
    holdersOfRole();

    service.probe();

    verify(port, never()).bump(any(), anyCollection());
    assertThat(roleQueueSize()).isZero();
  }

  @Test
  void should_dropNewestRoleAndCount_when_roleQueueFull() {
    SimpleMeterRegistry meters = new SimpleMeterRegistry();
    PermissionFreshnessService small = newService(meters, REPLAY_CAPACITY, 1, TENANT_PERCENT);
    small.holderReadFailed(TENANT, ROLE, "detach");

    small.holderReadFailed(TENANT, UUID.randomUUID(), "detach");

    assertThat(meters.get("nexus.rbac.epoch.role_replay_queue_roles").gauge().value())
        .isEqualTo(1.0);
    assertThat(meters.get("nexus.rbac.epoch.bump_failed")
            .tags("operation", "detach", "reason", "role_overflow").counter().count())
        .isEqualTo(1.0);
  }

  @Test
  void should_notReadHolders_when_degradedAndProbeFails() {
    tripAtT();
    service.holderReadFailed(TENANT, ROLE, "detach");
    when(port.probe()).thenReturn(false);

    service.probe();

    verify(userRoles, never()).findActiveUserIdsForRole(any());
  }

  @Test
  void should_resolveRole_when_degradedAndProbeSucceeds() {
    tripAtT();
    service.holderReadFailed(TENANT, ROLE, "detach");
    holdersOfRole(USER);
    storeWrites(EPOCH + 5);
    when(port.probe()).thenReturn(true);

    service.probe();

    verify(port).bump(TENANT, List.of(USER));
    assertThat(service.state()).isEqualTo(DegradedState.RECOVERING);
  }

  @Test
  void should_stayDegraded_when_roleStillQueuedAfterProbeSucceeds() {
    tripAtT();
    service.holderReadFailed(TENANT, ROLE, "detach");
    when(userRoles.findActiveUserIdsForRole(ROLE))
        .thenThrow(new QueryTimeoutException("db down"));
    when(port.probe()).thenReturn(true);

    service.probe();

    assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_OPEN);
  }

  @Test
  void should_notCountRoleReplayFailureAsReadFailure_when_recovering() {
    tripAtT();
    recoverNow();
    service.holderReadFailed(TENANT, ROLE, "detach");
    when(userRoles.findActiveUserIdsForRole(ROLE))
        .thenThrow(new QueryTimeoutException("db down"));

    for (int i = 0; i < 5; i++) {
      service.probe();
    }

    assertThat(service.state()).isEqualTo(DegradedState.RECOVERING);
  }

  @Test
  void should_notLogUserIds_when_roleReplayed() {
    service.holderReadFailed(TENANT, ROLE, "detach");
    holdersOfRole(USER);
    storeWrites(EPOCH + 5);
    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.probe();
    } finally {
      stopLogCapture(appender);
    }

    assertThat(appender.list)
        .noneSatisfy(event ->
            assertThat(event.getFormattedMessage() + keyValues(event)).contains(USER.toString()));
  }

  /** L-1: a corrupt key makes that user's tokens stale and never counts as a store failure. */
  @Test
  void should_returnStaleWithoutCounting_when_storedEpochUnparseable() {
    when(port.current(TENANT, USER)).thenThrow(new EpochUnparseableException());

    for (int i = 0; i < 10; i++) {
      assertThat(service.check(TENANT, USER, EPOCH)).isEqualTo(FreshnessVerdict.STALE);
    }

    assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);
    assertThat(outcomeCount("skipped_error")).isZero();
    assertThat(outcomeCount("stale")).isZero();
    assertThat(outcomeCount("unparseable")).isEqualTo(10.0);
  }

  @Test
  void should_notCountUnparseableTowardsRelapse_when_recovering() {
    tripAtT();
    recoverNow();
    when(port.current(TENANT, USER)).thenThrow(new EpochUnparseableException());

    for (int i = 0; i < 10; i++) {
      service.check(TENANT, USER, EPOCH);
    }

    assertThat(service.state()).isEqualTo(DegradedState.RECOVERING);
  }

  @Test
  void should_warnWithTenantOnly_when_storedEpochUnparseable() {
    when(port.current(TENANT, USER)).thenThrow(new EpochUnparseableException());
    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.check(TENANT, USER, EPOCH);
    } finally {
      stopLogCapture(appender);
    }

    assertThat(appender.list).singleElement().satisfies(event -> {
      assertThat(event.getLevel()).isEqualTo(Level.WARN);
      assertThat(keyValues(event))
          .containsEntry("event", "RBAC_EPOCH_UNPARSEABLE")
          .containsEntry("tenantId", TENANT)
          .doesNotContainKey("userId");
      assertThat(event.getFormattedMessage() + keyValues(event)).doesNotContain(USER.toString());
    });
  }

  @Test
  void should_mintUnverifiedZero_when_storedEpochUnparseable() {
    when(port.current(TENANT, USER)).thenThrow(new EpochUnparseableException());

    assertThat(service.mintEpoch(TENANT, USER))
        .isEqualTo(new PermissionFreshnessService.MintEpoch(0L, false));
  }

  // --- RBAC_EPOCH_UNPARSEABLE rate limit (security review part 2, L-2) ---

  private List<ILoggingEvent> unparseableWarnsDuring(Runnable action) {
    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      action.run();
    } finally {
      stopLogCapture(appender);
    }
    return appender.list.stream()
        .filter(e -> "RBAC_EPOCH_UNPARSEABLE".equals(keyValues(e).get("event")))
        .toList();
  }

  @Test
  void should_warnOncePerMinutePerTenant_when_manyChecksUnparseable() {
    when(port.current(TENANT, USER)).thenThrow(new EpochUnparseableException());

    List<ILoggingEvent> warns = unparseableWarnsDuring(() -> {
      for (int i = 0; i < 50; i++) {
        service.check(TENANT, USER, EPOCH);
      }
    });

    assertThat(warns).singleElement()
        .satisfies(e -> assertThat(keyValues(e)).containsEntry("suppressed", 0L));
  }

  @Test
  void should_reportSuppressedCount_when_nextWindowOpens() {
    when(port.current(TENANT, USER)).thenThrow(new EpochUnparseableException());
    for (int i = 0; i < 5; i++) {
      service.check(TENANT, USER, EPOCH);
    }
    clock.set(T.plusSeconds(60));

    List<ILoggingEvent> warns = unparseableWarnsDuring(() -> service.check(TENANT, USER, EPOCH));

    assertThat(warns).singleElement()
        .satisfies(e -> assertThat(keyValues(e)).containsEntry("suppressed", 4L));
  }

  @Test
  void should_stillSuppress_when_oneSecondBeforeWindowEnds() {
    when(port.current(TENANT, USER)).thenThrow(new EpochUnparseableException());
    service.check(TENANT, USER, EPOCH);
    clock.set(T.plusSeconds(59));

    List<ILoggingEvent> warns = unparseableWarnsDuring(() -> service.check(TENANT, USER, EPOCH));

    assertThat(warns).isEmpty();
  }

  @Test
  void should_warnForEachTenant_when_twoTenantsUnparseable() {
    UUID other = UUID.fromString("00000000-0000-7000-8000-0000000000ad");
    when(port.current(any(), any())).thenThrow(new EpochUnparseableException());

    List<ILoggingEvent> warns = unparseableWarnsDuring(() -> {
      service.check(TENANT, USER, EPOCH);
      service.check(other, USER, EPOCH);
      service.check(TENANT, USER, EPOCH);
    });

    assertThat(warns).hasSize(2);
  }

  @Test
  void should_shareTheLimitBetweenCheckAndMint_when_sameTenant() {
    when(port.current(TENANT, USER)).thenThrow(new EpochUnparseableException());

    List<ILoggingEvent> warns = unparseableWarnsDuring(() -> {
      service.check(TENANT, USER, EPOCH);
      service.mintEpoch(TENANT, USER);
    });

    assertThat(warns).hasSize(1);
  }

  @Test
  void should_reportZeroSuppressed_when_windowEndedWithoutFurtherEvents() {
    when(port.current(TENANT, USER)).thenThrow(new EpochUnparseableException());
    service.check(TENANT, USER, EPOCH);
    clock.set(T.plusSeconds(600));
    service.probe();

    List<ILoggingEvent> warns = unparseableWarnsDuring(() -> service.check(TENANT, USER, EPOCH));

    assertThat(warns).singleElement()
        .satisfies(e -> assertThat(keyValues(e)).containsEntry("suppressed", 0L));
  }

  @Test
  void should_notCountUnparseableAsStaleOrFresh_when_checkUnparseable() {
    when(port.current(TENANT, USER)).thenThrow(new EpochUnparseableException());

    service.check(TENANT, USER, EPOCH);

    assertThat(outcomeCount("unparseable")).isEqualTo(1.0);
    assertThat(outcomeCount("stale")).isZero();
    assertThat(outcomeCount("fresh")).isZero();
  }

  /** L-2: the 60 s sustain starts when the drain is done, not when the probe answered. */
  @Test
  void should_measureSustainFromDrainEnd_when_drainTakesLong() {
    failBumps();
    service.invalidateUser(TENANT, USER, "revoke");
    tripAtT();
    when(port.probe()).thenReturn(true);
    doAnswer(invocation -> {
      clock.set(clock.instant().plusSeconds(60));
      return Map.of();
    }).when(port).bump(any(), anyCollection());
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));

    service.probe();
    assertThat(service.state()).isEqualTo(DegradedState.RECOVERING);
    service.check(TENANT, USER, EPOCH);

    assertThat(service.state()).isEqualTo(DegradedState.RECOVERING);
    clock.set(clock.instant().plusSeconds(60));
    service.check(TENANT, USER, EPOCH);
    assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);
  }

  // --- L-3: verified / unverified mint epoch ---

  @Test
  void should_reportVerified_when_storeAnsweredTheMintRead() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));

    assertThat(service.mintEpoch(TENANT, USER))
        .isEqualTo(new PermissionFreshnessService.MintEpoch(EPOCH, true));
  }

  @Test
  void should_reportVerifiedZero_when_keyAbsent() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(0L));

    assertThat(service.mintEpoch(TENANT, USER).verified()).isTrue();
  }

  @Test
  void should_reportUnverified_when_mintReadFailsTwiceAndSeenEpochUsed() {
    when(port.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));
    service.mintEpoch(TENANT, USER);
    failRead();

    assertThat(service.mintEpoch(TENANT, USER))
        .isEqualTo(new PermissionFreshnessService.MintEpoch(EPOCH, false));
  }

  @Test
  void should_reportUnverified_when_degraded() {
    tripAtT();

    assertThat(service.mintEpoch(TENANT, USER).verified()).isFalse();
  }

  private double stateGauge(String state) {
    return registry.get("nexus.rbac.epoch.degraded").tag("state", state).gauge().value();
  }

  /** A clock the test moves by hand. */
  private static final class MutableClock extends Clock {
    private volatile Instant now;

    MutableClock(Instant now) {
      this.now = now;
    }

    void set(Instant instant) {
      this.now = instant;
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
