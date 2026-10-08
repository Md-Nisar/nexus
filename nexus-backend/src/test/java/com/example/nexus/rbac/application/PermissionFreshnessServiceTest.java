package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.doNothing;
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
import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.UUID;
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

  private PermissionEpochPort port;
  private SimpleMeterRegistry registry;
  private PermissionFreshnessService service;

  @BeforeEach
  void setUp() {
    port = mock(PermissionEpochPort.class);
    registry = new SimpleMeterRegistry();
    service = new PermissionFreshnessService(port, registry);
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
    doNothing()
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
}
