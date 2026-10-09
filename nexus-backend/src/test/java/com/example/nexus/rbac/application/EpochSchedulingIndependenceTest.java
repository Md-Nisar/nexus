package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.infrastructure.cache.EpochSchedulingConfig;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.scheduling.annotation.ScheduledAnnotationBeanPostProcessor;

/**
 * The epoch probe must run even when the audit retry buffer's escape hatch is off (US-018 T-011,
 * RC-52): its scheduling comes from {@link EpochSchedulingConfig}, not from the identity
 * context's conditional {@code SchedulingConfig}. The replay drain runs from the same task, so it
 * is covered the same way (T-012, RC-52 drain half).
 */
@Tag("UnitTest")
class EpochSchedulingIndependenceTest {

  private static final UUID TENANT = UUID.fromString("00000000-0000-7000-8000-0000000000aa");
  private static final UUID USER = UUID.fromString("00000000-0000-7000-8000-0000000000bb");
  private static final long AWAIT_MILLIS = 10_000;

  @Test
  void should_runProbe_when_retryBufferDisabled() throws Exception {
    CountingPort port = new CountingPort();
    new ApplicationContextRunner()
        .withInitializer(ctx -> ctx.getBeanFactory()
            .setConversionService(ApplicationConversionService.getSharedInstance()))
        .withUserConfiguration(EpochSchedulingConfig.class)
        .withBean(PermissionEpochPort.class, () -> port)
        .withBean(UserRoleAssignmentPort.class, () -> mock(UserRoleAssignmentPort.class))
        .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
        .withBean(Clock.class, Clock::systemUTC)
        .withBean(PermissionFreshnessService.class)
        .withPropertyValues(
            "nexus.identity.audit.retry-buffer.enabled=false",
            "nexus.rbac.epoch.fail-open-window=PT15M",
            "nexus.rbac.epoch.entry-failure-threshold=3",
            "nexus.rbac.epoch.entry-failure-window=PT10S",
            "nexus.rbac.epoch.recovery-sustain=PT60S",
            "nexus.rbac.epoch.key-ttl-seconds=960",
            "nexus.rbac.epoch.replay-capacity-users=1000")
        .run(context -> {
          assertThat(context).hasSingleBean(ScheduledAnnotationBeanPostProcessor.class);
          PermissionFreshnessService service = context.getBean(PermissionFreshnessService.class);
          for (int i = 0; i < 3; i++) {
            service.check(TENANT, USER, 0L);
          }
          assertThat(service.state()).isEqualTo(DegradedState.DEGRADED_OPEN);

          long deadline = System.currentTimeMillis() + AWAIT_MILLIS;
          while (port.probes.get() == 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
          }

          assertThat(port.probes.get()).as("scheduled probe executions").isPositive();
        });
  }

  @Test
  void should_drainReplayQueue_when_retryBufferDisabled() {
    CountingPort port = new CountingPort();
    port.failNextBumps.set(1);
    new ApplicationContextRunner()
        .withInitializer(ctx -> ctx.getBeanFactory()
            .setConversionService(ApplicationConversionService.getSharedInstance()))
        .withUserConfiguration(EpochSchedulingConfig.class)
        .withBean(PermissionEpochPort.class, () -> port)
        .withBean(UserRoleAssignmentPort.class, () -> mock(UserRoleAssignmentPort.class))
        .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
        .withBean(Clock.class, Clock::systemUTC)
        .withBean(PermissionFreshnessService.class)
        .withPropertyValues(
            "nexus.identity.audit.retry-buffer.enabled=false",
            "nexus.rbac.epoch.fail-open-window=PT15M",
            "nexus.rbac.epoch.entry-failure-threshold=3",
            "nexus.rbac.epoch.entry-failure-window=PT10S",
            "nexus.rbac.epoch.recovery-sustain=PT60S",
            "nexus.rbac.epoch.key-ttl-seconds=960",
            "nexus.rbac.epoch.replay-capacity-users=1000")
        .run(context -> {
          PermissionFreshnessService service = context.getBean(PermissionFreshnessService.class);
          service.invalidateUser(TENANT, USER, "revoke");
          assertThat(service.state()).isEqualTo(DegradedState.HEALTHY);

          long deadline = System.currentTimeMillis() + AWAIT_MILLIS;
          while (port.successfulBumps.get() == 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
          }

          assertThat(port.successfulBumps.get()).as("replayed bumps").isEqualTo(1);
        });
  }

  @Test
  void should_resolveRoleQueue_when_retryBufferDisabled() {
    CountingPort port = new CountingPort();
    UserRoleAssignmentPort userRoles = mock(UserRoleAssignmentPort.class);
    UUID role = UUID.fromString("00000000-0000-7000-8000-0000000000c1");
    when(userRoles.findActiveUserIdsForRole(role)).thenReturn(List.of(USER));
    new ApplicationContextRunner()
        .withInitializer(ctx -> ctx.getBeanFactory()
            .setConversionService(ApplicationConversionService.getSharedInstance()))
        .withUserConfiguration(EpochSchedulingConfig.class)
        .withBean(PermissionEpochPort.class, () -> port)
        .withBean(UserRoleAssignmentPort.class, () -> userRoles)
        .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
        .withBean(Clock.class, Clock::systemUTC)
        .withBean(PermissionFreshnessService.class)
        .withPropertyValues(
            "nexus.identity.audit.retry-buffer.enabled=false",
            "nexus.rbac.epoch.fail-open-window=PT15M",
            "nexus.rbac.epoch.entry-failure-threshold=3",
            "nexus.rbac.epoch.entry-failure-window=PT10S",
            "nexus.rbac.epoch.recovery-sustain=PT60S",
            "nexus.rbac.epoch.key-ttl-seconds=960",
            "nexus.rbac.epoch.replay-capacity-users=1000")
        .run(context -> {
          PermissionFreshnessService service = context.getBean(PermissionFreshnessService.class);
          service.holderReadFailed(TENANT, role, "detach");

          long deadline = System.currentTimeMillis() + AWAIT_MILLIS;
          while (port.successfulBumps.get() == 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
          }

          assertThat(port.successfulBumps.get()).as("role-resolved bumps").isEqualTo(1);
        });
  }

  /** Reads always fail; counts probes; fails the first {@code failNextBumps} bumps. */
  private static final class CountingPort implements PermissionEpochPort {
    private final AtomicInteger probes = new AtomicInteger();
    private final AtomicInteger failNextBumps = new AtomicInteger();
    private final AtomicInteger successfulBumps = new AtomicInteger();

    @Override
    public OptionalLong current(UUID tenantId, UUID userId) {
      return OptionalLong.empty();
    }

    @Override
    public Map<UUID, Long> bump(UUID tenantId, Collection<UUID> userIds) {
      if (failNextBumps.getAndUpdate(n -> Math.max(0, n - 1)) > 0) {
        throw new QueryTimeoutException("bump timeout");
      }
      successfulBumps.incrementAndGet();
      return Map.of();
    }

    @Override
    public boolean probe() {
      probes.incrementAndGet();
      return false;
    }
  }
}
