package com.example.nexus.identity.infrastructure.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.identity.domain.AuditAlert;
import com.example.nexus.identity.domain.AuditAlertType;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.slf4j.LoggerFactory;

class LoggingAuditAlertAdapterTest {

  private SimpleMeterRegistry meterRegistry;
  private LoggingAuditAlertAdapter adapter;
  private ListAppender<ILoggingEvent> appender;

  @BeforeEach
  void setUp() {
    meterRegistry = new SimpleMeterRegistry();
    adapter = new LoggingAuditAlertAdapter(meterRegistry);
    appender = startLogCapture();
  }

  @AfterEach
  void tearDown() {
    stopLogCapture(appender);
  }

  @Test
  void should_logAtWarn_when_bufferDepthWarnRaised() {
    adapter.raise(alertOf(AuditAlertType.BUFFER_DEPTH_WARN));

    assertThat(messagesAt(Level.WARN)).isNotEmpty();
    assertThat(messagesAt(Level.ERROR)).isEmpty();
  }

  @Test
  void should_logAtError_when_bufferDepthCriticalRaised() {
    adapter.raise(alertOf(AuditAlertType.BUFFER_DEPTH_CRITICAL));

    assertThat(messagesAt(Level.ERROR)).isNotEmpty();
    assertThat(messagesAt(Level.WARN)).isEmpty();
  }

  @Test
  void should_logAtError_when_bufferAgeCriticalRaised() {
    adapter.raise(alertOf(AuditAlertType.BUFFER_AGE_CRITICAL));

    assertThat(messagesAt(Level.ERROR)).isNotEmpty();
    assertThat(messagesAt(Level.WARN)).isEmpty();
  }

  @Test
  void should_logAtError_when_retryExhaustedRaised() {
    adapter.raise(alertOf(AuditAlertType.RETRY_EXHAUSTED));

    assertThat(messagesAt(Level.ERROR)).isNotEmpty();
    assertThat(messagesAt(Level.WARN)).isEmpty();
  }

  @ParameterizedTest
  @EnumSource(AuditAlertType.class)
  void should_incrementCounterWithTypeTag_when_alertRaised(AuditAlertType type) {
    adapter.raise(alertOf(type));

    double count =
        meterRegistry.get("nexus.audit.alert.raised").tag("type", type.name()).counter().count();

    assertThat(count).isEqualTo(1.0);
  }

  @Test
  void should_onlyIncrementMatchingTypeTag_when_alertRaised() {
    adapter.raise(alertOf(AuditAlertType.BUFFER_DEPTH_WARN));
    adapter.raise(alertOf(AuditAlertType.BUFFER_DEPTH_WARN));
    adapter.raise(alertOf(AuditAlertType.RETRY_EXHAUSTED));

    double warnCount =
        meterRegistry
            .get("nexus.audit.alert.raised")
            .tag("type", AuditAlertType.BUFFER_DEPTH_WARN.name())
            .counter()
            .count();
    double exhaustedCount =
        meterRegistry
            .get("nexus.audit.alert.raised")
            .tag("type", AuditAlertType.RETRY_EXHAUSTED.name())
            .counter()
            .count();

    assertThat(warnCount).isEqualTo(2.0);
    assertThat(exhaustedCount).isEqualTo(1.0);
  }

  @ParameterizedTest
  @EnumSource(AuditAlertType.class)
  void should_notThrow_when_alertRaised(AuditAlertType type) {
    assertThatCode(() -> adapter.raise(alertOf(type))).doesNotThrowAnyException();
  }

  private AuditAlert alertOf(AuditAlertType type) {
    return new AuditAlert(type, "test message for " + type, Instant.now(), 42);
  }

  private ListAppender<ILoggingEvent> startLogCapture() {
    Logger logger = (Logger) LoggerFactory.getLogger(LoggingAuditAlertAdapter.class);
    ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);
    return listAppender;
  }

  private void stopLogCapture(ListAppender<ILoggingEvent> listAppender) {
    Logger logger = (Logger) LoggerFactory.getLogger(LoggingAuditAlertAdapter.class);
    logger.detachAppender(listAppender);
    listAppender.stop();
  }

  private List<String> messagesAt(Level level) {
    return appender.list.stream()
        .filter(event -> event.getLevel() == level)
        .map(ILoggingEvent::getFormattedMessage)
        .toList();
  }
}
