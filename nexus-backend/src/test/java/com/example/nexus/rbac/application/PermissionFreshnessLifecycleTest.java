package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Unit tests verifying lifecycle management and graceful shutdown of executors
 * in {@link PermissionFreshnessService} ([OR-2.1-08]).
 */
@Tag("UnitTest")
class PermissionFreshnessLifecycleTest {

  @Test
  void should_shutdown_executors_on_context_close() throws Exception {
    PermissionFreshnessService service = new PermissionFreshnessService(
        mock(PermissionEpochPort.class),
        mock(UserRoleAssignmentPort.class),
        mock(PermissionCachePort.class),
        new SimpleMeterRegistry(),
        Clock.systemUTC(),
        Duration.ofSeconds(30),
        3,
        Duration.ofSeconds(10),
        Duration.ofSeconds(60),
        3600,
        1000,
        1000,
        10);

    assertThat(service.isExecutorShutdown()).isFalse();

    CountDownLatch taskRunning = new CountDownLatch(1);
    service.runOnRoleReadThread(() -> {
      taskRunning.countDown();
      try {
        Thread.sleep(5000);
      } catch (InterruptedException ignored) {
        // Expected when shutdownNow() interrupts
      }
    });

    assertThat(taskRunning.await(5, TimeUnit.SECONDS)).isTrue();

    // Trigger @PreDestroy lifecycle method
    service.shutdown();

    assertThat(service.isExecutorShutdown()).isTrue();
    assertThat(service.isExecutorTerminated()).isTrue();
  }
}
