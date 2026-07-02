package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.infrastructure.audit.AuditRetryProperties;
import com.example.nexus.identity.infrastructure.audit.AuthEventRetryBuffer;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;

@ExtendWith(MockitoExtension.class)
class JpaAuthEventAdapterTest {

  @Mock private JpaAuthEventRepository authEventRepository;

  @Mock private AuthEventRetryBuffer retryBuffer;

  private ListAppender<ILoggingEvent> appender;

  @BeforeEach
  void setUp() {
    appender = startLogCapture();
  }

  @AfterEach
  void tearDown() {
    stopLogCapture(appender);
  }

  @Test
  void record_savesEvent_onSuccess() {
    JpaAuthEventAdapter adapter = adapterWith(enabledProps());
    AuthEvent event = new AuthEvent(UUID.randomUUID(), "REGISTRATION_SUCCESS", "SUCCESS");

    adapter.record(event);

    verify(authEventRepository).save(event);
    verifyNoInteractions(retryBuffer);
  }

  @Test
  void record_swallowsDataAccessException_andDoesNotRethrow() {
    JpaAuthEventAdapter adapter = adapterWith(enabledProps());
    AuthEvent event = new AuthEvent(UUID.randomUUID(), "REGISTRATION_FAILED", "FAILURE");
    doThrow(new DataIntegrityViolationException("DB error"))
        .when(authEventRepository)
        .save(event);

    assertThatCode(() -> adapter.record(event)).doesNotThrowAnyException();
  }

  @Test
  void record_enqueuesToRetryBuffer_onDataAccessException_whenEnabled() {
    JpaAuthEventAdapter adapter = adapterWith(enabledProps());
    AuthEvent event = new AuthEvent(UUID.randomUUID(), "LOGIN_FAILURE", "FAILURE");
    doThrow(new DataIntegrityViolationException("DB error"))
        .when(authEventRepository)
        .save(event);
    when(retryBuffer.enqueue(event)).thenReturn(true);

    assertThatCode(() -> adapter.record(event)).doesNotThrowAnyException();

    verify(retryBuffer).enqueue(event);
  }

  @Test
  void record_doesNotEnqueue_whenRetryBufferDisabled() {
    JpaAuthEventAdapter adapter = adapterWith(disabledProps());
    AuthEvent event = new AuthEvent(UUID.randomUUID(), "LOGIN_FAILURE", "FAILURE");
    doThrow(new DataIntegrityViolationException("DB error"))
        .when(authEventRepository)
        .save(event);

    assertThatCode(() -> adapter.record(event)).doesNotThrowAnyException();

    verifyNoInteractions(retryBuffer);
  }

  @Test
  void record_warnLog_containsOnlyEventTypeAndExceptionMessage_noUserAgent() {
    JpaAuthEventAdapter adapter = adapterWith(enabledProps());
    AuthEvent event = new AuthEvent(UUID.randomUUID(), "LOGIN_FAILURE", "FAILURE");
    String attackerUserAgent = "Mozilla/5.0 EVIL-UA-MARKER";
    doThrow(new DataIntegrityViolationException("DB error"))
        .when(authEventRepository)
        .save(event);
    when(retryBuffer.enqueue(event)).thenReturn(true);

    adapter.record(event);

    List<String> warnMessages = messagesAt(Level.WARN);
    assertThat(warnMessages).isNotEmpty();
    assertThat(warnMessages.get(0)).contains("LOGIN_FAILURE").contains("DB error");
    assertThat(warnMessages.get(0)).doesNotContain(attackerUserAgent).doesNotContain("user_agent");
  }

  private JpaAuthEventAdapter adapterWith(AuditRetryProperties properties) {
    return new JpaAuthEventAdapter(authEventRepository, retryBuffer, properties);
  }

  private AuditRetryProperties enabledProps() {
    return new AuditRetryProperties(
        true, 200, 800, 10000L, 5, List.of(Duration.ofSeconds(1)), null, null);
  }

  private AuditRetryProperties disabledProps() {
    return new AuditRetryProperties(
        false, 200, 800, 10000L, 5, List.of(Duration.ofSeconds(1)), null, null);
  }

  private ListAppender<ILoggingEvent> startLogCapture() {
    Logger logger = (Logger) LoggerFactory.getLogger(JpaAuthEventAdapter.class);
    ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);
    return listAppender;
  }

  private void stopLogCapture(ListAppender<ILoggingEvent> listAppender) {
    Logger logger = (Logger) LoggerFactory.getLogger(JpaAuthEventAdapter.class);
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
