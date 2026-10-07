package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.List;
import java.util.OptionalLong;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.dao.QueryTimeoutException;

/** Unit tests for {@link PermissionFreshnessService} (US-018 T-009, design §9.2, §9.9). */
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

  private double outcomeCount(String outcome) {
    return registry.get("nexus.rbac.epoch.check").tag("outcome", outcome).counter().count();
  }
}
