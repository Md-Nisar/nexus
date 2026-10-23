package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.rbac.application.PiiPermissionGrantRule.Outcome;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.context.logging.LoggingApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;

/**
 * US-019 T-007 (03-design.md §4.8; RC-60.2, RC-60.3, RC-66.4): the administrator-only rule for
 * granting {@code user:directory:read}, its switch, the startup WARN when it is off, and the
 * detective WARN and counter.
 */
@Tag("UnitTest")
class PiiPermissionGrantRuleTest {

  private static final UUID PII = RbacSeededPermissionIds.USER_DIRECTORY_READ;
  private static final String PROPERTY = "nexus.rbac.pii-grant-requires-administrator";
  private static final String DELEGATED_COUNTER = "nexus.rbac.pii_permission_delegated";

  private SimpleMeterRegistry meterRegistry;

  @BeforeEach
  void setUp() {
    meterRegistry = new SimpleMeterRegistry();
  }

  private PiiPermissionGrantRule rule(boolean enforced) {
    return new PiiPermissionGrantRule(enforced, meterRegistry);
  }

  // --- evaluate ---

  @Test
  void should_beNotAPiiGrant_when_grantedIdsLackThePermission() {
    AtomicInteger administratorReads = new AtomicInteger();

    Outcome outcome =
        rule(true)
            .evaluate(
                Set.of(RbacSeededPermissionIds.USER_READ, RbacSeededPermissionIds.ROLE_WRITE),
                () -> {
                  administratorReads.incrementAndGet();
                  return false;
                });

    assertThat(outcome).isEqualTo(Outcome.NOT_A_PII_GRANT);
    assertThat(administratorReads).as("no administrator evaluation off the PII path").hasValue(0);
  }

  @Test
  void should_beNotAPiiGrant_when_grantedIdsAreEmpty() {
    assertThat(rule(true).evaluate(Set.of(), () -> false)).isEqualTo(Outcome.NOT_A_PII_GRANT);
  }

  @Test
  void should_deny_when_ruleOnAndCallerNotAdministrator() {
    assertThat(rule(true).evaluate(Set.of(PII), () -> false)).isEqualTo(Outcome.DENIED);
  }

  @Test
  void should_deny_when_ruleOnAndPermissionIsAmongSeveralGrantedIds() {
    assertThat(
            rule(true).evaluate(Set.of(RbacSeededPermissionIds.USER_READ, PII), () -> false))
        .isEqualTo(Outcome.DENIED);
  }

  @Test
  void should_allowAsAdministratorGrant_when_ruleOnAndCallerIsAdministrator() {
    assertThat(rule(true).evaluate(Set.of(PII), () -> true))
        .isEqualTo(Outcome.ADMINISTRATOR_GRANT);
  }

  @Test
  void should_allowAsDelegated_when_ruleOffAndCallerNotAdministrator() {
    assertThat(rule(false).evaluate(Set.of(PII), () -> false)).isEqualTo(Outcome.DELEGATED);
  }

  @Test
  void should_allowAsAdministratorGrant_when_ruleOffAndCallerIsAdministrator() {
    assertThat(rule(false).evaluate(Set.of(PII), () -> true))
        .isEqualTo(Outcome.ADMINISTRATOR_GRANT);
  }

  // --- startup WARN (RC-66.4) ---

  @Test
  void should_logStartupWarn_when_ruleDisabled() {
    List<ILoggingEvent> events = captureLogs(() -> rule(false).warnIfDisabled());

    assertThat(events).hasSize(1);
    assertThat(events.get(0).getLevel()).isEqualTo(Level.WARN);
    assertThat(keyValueMap(events.get(0)))
        .containsOnly(Map.entry("event", "RBAC_PII_GRANT_RULE_DISABLED"), Map.entry("property", PROPERTY));
  }

  @Test
  void should_logNothingAtStartup_when_ruleEnabled() {
    assertThat(captureLogs(() -> rule(true).warnIfDisabled())).isEmpty();
  }

  // --- denied WARN and detective signal (RC-60.2, RC-60.3) ---

  @Test
  void should_logDeniedWarnWithIdsOnly_when_grantDenied() {
    UUID tenantId = UUID.randomUUID();
    UUID actorUserId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();
    UUID targetUserId = UUID.randomUUID();

    List<ILoggingEvent> events =
        captureLogs(
            () -> rule(true).warnDenied(tenantId, actorUserId, roleId, targetUserId, "assign"));

    assertThat(events).hasSize(1);
    assertThat(events.get(0).getLevel()).isEqualTo(Level.WARN);
    assertThat(keyValueMap(events.get(0)))
        .containsOnly(
            Map.entry("event", "RBAC_PII_PERMISSION_GRANT_DENIED"),
            Map.entry("tenantId", tenantId),
            Map.entry("actorUserId", actorUserId),
            Map.entry("roleId", roleId),
            Map.entry("targetUserId", targetUserId),
            Map.entry("operation", "assign"));
  }

  @Test
  void should_logDelegatedWarnAndIncrementUntaggedCounterOnce_when_delegationRecorded() {
    UUID tenantId = UUID.randomUUID();
    UUID actorUserId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();

    List<ILoggingEvent> events =
        captureLogs(() -> rule(false).recordDelegated(tenantId, actorUserId, roleId, null));

    assertThat(events).hasSize(1);
    assertThat(events.get(0).getLevel()).isEqualTo(Level.WARN);
    Map<String, Object> fields = keyValueMap(events.get(0));
    assertThat(fields)
        .containsOnlyKeys("event", "tenantId", "actorUserId", "roleId", "targetUserId")
        .containsEntry("event", "RBAC_PII_PERMISSION_DELEGATED")
        .containsEntry("tenantId", tenantId)
        .containsEntry("actorUserId", actorUserId)
        .containsEntry("roleId", roleId);
    assertThat(fields.get("targetUserId")).isNull();
    Counter counter = meterRegistry.find(DELEGATED_COUNTER).counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
    assertThat(counter.getId().getTags()).isEmpty();
  }

  // --- profile resolution (RC-66.4) ---

  @Test
  void should_resolveTrue_when_noProfileActive() {
    assertThat(resolveProperty()).isTrue();
  }

  @Test
  void should_resolveTrue_when_prodProfileActive() {
    assertThat(resolveProperty("prod")).isTrue();
  }

  // --- helpers ---

  /**
   * Resolves the property from the real {@code application*.yml} files through Boot's config-data
   * loading only (see {@code ThrottleSharedStoreStartupAssertionTest}).
   */
  private static Boolean resolveProperty(String... profiles) {
    SpringApplication app = new SpringApplication(EmptyConfig.class);
    app.setWebApplicationType(WebApplicationType.NONE);
    app.setRegisterShutdownHook(false);
    app.setLogStartupInfo(false);
    app.setListeners(
        app.getListeners().stream()
            .filter(listener -> !(listener instanceof LoggingApplicationListener))
            .toList());
    app.setAdditionalProfiles(profiles);
    try (ConfigurableApplicationContext context = app.run("--spring.main.banner-mode=off")) {
      return context.getEnvironment().getProperty(PROPERTY, Boolean.class);
    }
  }

  private static List<ILoggingEvent> captureLogs(Runnable action) {
    Logger logger = (Logger) LoggerFactory.getLogger(PiiPermissionGrantRule.class);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    try {
      action.run();
    } finally {
      logger.detachAppender(appender);
      appender.stop();
    }
    return List.copyOf(appender.list);
  }

  private static Map<String, Object> keyValueMap(ILoggingEvent event) {
    Map<String, Object> map = new HashMap<>();
    if (event.getKeyValuePairs() != null) {
      event.getKeyValuePairs().forEach(kv -> map.put(kv.key, kv.value));
    }
    return map;
  }

  /** Deliberately empty: only the environment is under test. */
  @Configuration(proxyBeanMethods = false)
  static class EmptyConfig {}
}
