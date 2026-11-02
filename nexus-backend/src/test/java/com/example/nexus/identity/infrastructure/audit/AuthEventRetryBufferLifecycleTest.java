package com.example.nexus.identity.infrastructure.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.common.observation.ExecutionObserver;
import com.example.nexus.identity.application.port.out.AuditAlertPort;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.AuthEventType;
import com.example.nexus.identity.infrastructure.persistence.JpaAuthEventRepository;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataAccessResourceFailureException;

/**
 * Unit tests verifying lifecycle management and graceful shutdown draining in
 * {@link AuthEventRetryBuffer} ([OR-3.3-05]).
 */
@Tag("UnitTest")
@ExtendWith(MockitoExtension.class)
class AuthEventRetryBufferLifecycleTest {

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
    properties = new AuditRetryProperties(
        true, 100, 100, 10_000L, 5,
        List.of(Duration.ofSeconds(1), Duration.ofSeconds(5)),
        null, null);
    buffer = new AuthEventRetryBuffer(
        repository,
        alertPort,
        meterRegistry,
        clock,
        properties,
        new ExecutionObserver(meterRegistry));
  }

  @Test
  void should_drain_buffer_on_shutdown() {
    AuthEvent priority1 = new AuthEvent(UUID.randomUUID(), AuthEventType.LOCKOUT, "FAILURE");
    AuthEvent standard1 = new AuthEvent(UUID.randomUUID(), AuthEventType.LOGIN_FAILURE, "FAILURE");
    AuthEvent standard2 = new AuthEvent(UUID.randomUUID(), AuthEventType.LOGOUT, "SUCCESS");

    buffer.enqueue(priority1);
    buffer.enqueue(standard1);
    buffer.enqueue(standard2);

    assertThat(buffer.depth(AuditLane.PRIORITY)).isEqualTo(1);
    assertThat(buffer.depth(AuditLane.STANDARD)).isEqualTo(2);

    buffer.shutdown();

    assertThat(buffer.depth(AuditLane.PRIORITY)).isZero();
    assertThat(buffer.depth(AuditLane.STANDARD)).isZero();
    verify(repository, times(1)).save(priority1);
    verify(repository, times(1)).save(standard1);
    verify(repository, times(1)).save(standard2);
  }

  @Test
  void should_handle_repository_failure_during_shutdown_gracefully() {
    AuthEvent priority = new AuthEvent(UUID.randomUUID(), AuthEventType.LOCKOUT, "FAILURE");
    AuthEvent standard = new AuthEvent(UUID.randomUUID(), AuthEventType.LOGIN_FAILURE, "FAILURE");

    when(repository.save(any()))
        .thenThrow(new DataAccessResourceFailureException("Database shutdown in progress"));

    buffer.enqueue(priority);
    buffer.enqueue(standard);

    assertThatCode(() -> buffer.shutdown()).doesNotThrowAnyException();

    assertThat(buffer.depth(AuditLane.PRIORITY)).isZero();
    assertThat(buffer.depth(AuditLane.STANDARD)).isZero();
    verify(repository, times(2)).save(any(AuthEvent.class));
  }

  @Test
  void should_do_nothing_when_buffer_empty_on_shutdown() {
    assertThat(buffer.depth(AuditLane.PRIORITY)).isZero();
    assertThat(buffer.depth(AuditLane.STANDARD)).isZero();

    buffer.shutdown();

    verify(repository, never()).save(any());
  }
}
