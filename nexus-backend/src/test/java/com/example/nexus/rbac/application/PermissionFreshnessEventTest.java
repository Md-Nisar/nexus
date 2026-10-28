package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.example.nexus.rbac.application.event.PermissionFreshnessStateTransitionEvent;
import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;

/**
 * Unit tests verifying asynchronous decoupling of circuit breaker state transition events
 * in {@link PermissionFreshnessService} ([OR-2.1-09]).
 */
@Tag("UnitTest")
class PermissionFreshnessEventTest {

  @Test
  void should_publish_state_transitions_asynchronously() throws Exception {
    PermissionEpochPort epochPort = mock(PermissionEpochPort.class);
    UserRoleAssignmentPort userRoleAssignmentPort = mock(UserRoleAssignmentPort.class);
    PermissionCachePort permissionCachePort = mock(PermissionCachePort.class);

    PermissionFreshnessService service = new PermissionFreshnessService(
        epochPort,
        userRoleAssignmentPort,
        permissionCachePort,
        new SimpleMeterRegistry(),
        Clock.systemUTC(),
        Duration.ofSeconds(30),
        1,
        Duration.ofSeconds(10),
        Duration.ofSeconds(60),
        3600,
        1000,
        1000,
        10);

    ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
    service.setApplicationEventPublisher(publisher);

    CountDownLatch eventDispatched = new CountDownLatch(1);
    AtomicReference<Thread> publishingThread = new AtomicReference<>();

    service.setEventExecutor(runnable -> new Thread(() -> {
      publishingThread.set(Thread.currentThread());
      runnable.run();
      eventDispatched.countDown();
    }, "async-freshness-event-thread").start());

    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    service.check(tenantId, userId, 1L, 0L);

    assertThat(eventDispatched.await(5, TimeUnit.SECONDS)).isTrue();
    assertThat(publishingThread.get()).isNotNull();
    assertThat(publishingThread.get()).isNotEqualTo(Thread.currentThread());

    verify(publisher).publishEvent(any(PermissionFreshnessStateTransitionEvent.class));
  }
}
