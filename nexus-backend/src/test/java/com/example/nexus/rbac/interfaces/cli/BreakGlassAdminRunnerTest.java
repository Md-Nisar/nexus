package com.example.nexus.rbac.interfaces.cli;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.rbac.application.BootstrapAdminService;
import com.example.nexus.rbac.application.BreakGlassOutcome;
import com.example.nexus.rbac.application.BreakGlassRefusalReason;
import com.example.nexus.rbac.application.ChangeRef;
import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlertPort;
import com.example.nexus.rbac.application.port.out.BreakGlassAuditEvent;
import com.example.nexus.rbac.application.port.out.BreakGlassGrantLookupPort;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import java.io.IOException;
import java.time.Duration;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.web.context.reactive.GenericReactiveWebApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.web.context.support.GenericWebApplicationContext;

/**
 * US-018 T-008 (03-design.md §7.1, §7.2): the break-glass runner's argument validation (RC-47,
 * RC-54(a), L-6), exit codes, web-context guard (RC-37.6, RC-50(d)), log-flush wait (RC-37.4) and
 * profile configuration. Plain JUnit and Mockito, no Spring context.
 */
@Tag("UnitTest")
class BreakGlassAdminRunnerTest {

  private static final String VALID_TARGET = "0195f3a0-1c2d-7e8f-9a0b-1c2d3e4f5a6b";
  private static final String VALID_REF = "ABC-1";

  /** Pinned exit codes (03-design.md §7.1; 7 and 1 added by T-008, confirmed by the user). */
  private static final Map<BreakGlassRefusalReason, Integer> EXPECTED_EXIT_CODES =
      new EnumMap<>(
          Map.of(
              BreakGlassRefusalReason.INVALID_ARGUMENT, 2,
              BreakGlassRefusalReason.TARGET_USER_NOT_FOUND, 3,
              BreakGlassRefusalReason.TARGET_USER_NOT_ACTIVE, 3,
              BreakGlassRefusalReason.NO_SYSTEM_ADMIN_ROLE, 4,
              BreakGlassRefusalReason.TENANT_HAS_ADMIN, 5,
              BreakGlassRefusalReason.CHANGE_REF_REUSED, 6,
              BreakGlassRefusalReason.CONCURRENT_INVOCATION, 7,
              BreakGlassRefusalReason.UNEXPECTED_ERROR, 1));

  private BootstrapAdminService service;
  private BreakGlassAdminRunner runner;
  private ListAppender<ILoggingEvent> runnerLog;

  @BeforeEach
  void setUp() {
    service = mock(BootstrapAdminService.class);
    when(service.recordInvalidArgument())
        .thenReturn(new BreakGlassOutcome.Refused(BreakGlassRefusalReason.INVALID_ARGUMENT));
    runner = new BreakGlassAdminRunner(service, new GenericApplicationContext(), Duration.ZERO);
    runnerLog = new ListAppender<>();
    runnerLog.start();
    runnerLogger().addAppender(runnerLog);
  }

  @AfterEach
  void tearDown() {
    runnerLogger().detachAppender(runnerLog);
    runnerLog.stop();
  }

  // ── Exit codes ──────────────────────────────────────────────────────────────────────────

  @Test
  void should_emit_structured_json_to_stdout() throws Exception {
    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
    java.io.PrintStream testOut =
        new java.io.PrintStream(baos, true, java.nio.charset.StandardCharsets.UTF_8);
    BreakGlassAdminRunner customRunner =
        new BreakGlassAdminRunner(service, new GenericApplicationContext(), Duration.ZERO, testOut);

    UUID target = UUID.fromString(VALID_TARGET);
    when(service.grantFirstAdmin(target, new ChangeRef(VALID_REF)))
        .thenReturn(new BreakGlassOutcome.Granted(UUID.randomUUID(), target, UUID.randomUUID()));

    customRunner.run(args("--target-user-id=" + VALID_TARGET, "--change-ref=" + VALID_REF));

    String stdout = baos.toString(java.nio.charset.StandardCharsets.UTF_8);
    assertThat(stdout)
        .contains("\"@timestamp\"")
        .contains("\"log.level\":\"INFO\"")
        .contains("\"event\":{\"action\":\"break_glass\",\"outcome\":\"success\"}")
        .contains("\"process\":{\"exit_code\":0}");
  }

  @Test
  void should_exit0_when_serviceGrants() throws Exception {
    UUID target = UUID.fromString(VALID_TARGET);
    when(service.grantFirstAdmin(target, new ChangeRef(VALID_REF)))
        .thenReturn(new BreakGlassOutcome.Granted(UUID.randomUUID(), target, UUID.randomUUID()));

    runner.run(args("--target-user-id=" + VALID_TARGET, "--change-ref=" + VALID_REF));

    assertThat(runner.getExitCode()).isZero();
  }

  @ParameterizedTest
  @EnumSource(BreakGlassRefusalReason.class)
  void should_exitWithReasonCode_when_serviceRefuses(BreakGlassRefusalReason reason)
      throws Exception {
    assertThat(EXPECTED_EXIT_CODES).containsOnlyKeys(BreakGlassRefusalReason.values());
    when(service.grantFirstAdmin(any(), any())).thenReturn(new BreakGlassOutcome.Refused(reason));

    runner.run(args("--target-user-id=" + VALID_TARGET, "--change-ref=" + VALID_REF));

    assertThat(reason.exitCode()).isEqualTo(EXPECTED_EXIT_CODES.get(reason));
    assertThat(runner.getExitCode()).isEqualTo(EXPECTED_EXIT_CODES.get(reason));
  }

  @Test
  void should_reportOutcomeThroughExitCodeGenerator() throws Exception {
    when(service.grantFirstAdmin(any(), any()))
        .thenReturn(new BreakGlassOutcome.Refused(BreakGlassRefusalReason.TENANT_HAS_ADMIN));
    assertThat(runner.getExitCode()).as("before run: never success").isEqualTo(1);

    runner.run(args("--target-user-id=" + VALID_TARGET, "--change-ref=" + VALID_REF));

    org.springframework.boot.ExitCodeGenerator generator = runner;
    assertThat(generator.getExitCode()).isEqualTo(5);
  }

  /** An exception from the service propagates (exit 1 from Spring Boot), after the flush wait. */
  @Test
  void should_propagate_andKeepNonZeroExitCode_when_serviceThrows() {
    IllegalStateException down = new IllegalStateException("db down");
    when(service.grantFirstAdmin(any(), any())).thenThrow(down);

    assertThatThrownBy(
            () -> runner.run(args("--target-user-id=" + VALID_TARGET, "--change-ref=" + VALID_REF)))
        .isSameAs(down);

    assertThat(runner.getExitCode()).isEqualTo(1);
  }

  /** T-008 review Nit 2: a reused runner never reports a previous run's code for a failed run. */
  @Test
  void should_reportExit1_when_runThrowsAfterAnEarlierSuccessfulRunOnTheSameInstance()
      throws Exception {
    UUID target = UUID.fromString(VALID_TARGET);
    when(service.grantFirstAdmin(target, new ChangeRef(VALID_REF)))
        .thenReturn(new BreakGlassOutcome.Granted(UUID.randomUUID(), target, UUID.randomUUID()))
        .thenThrow(new IllegalStateException("db down"));
    runner.run(args("--target-user-id=" + VALID_TARGET, "--change-ref=" + VALID_REF));
    assertThat(runner.getExitCode()).isZero();

    assertThatThrownBy(
            () -> runner.run(args("--target-user-id=" + VALID_TARGET, "--change-ref=" + VALID_REF)))
        .isInstanceOf(IllegalStateException.class);

    assertThat(runner.getExitCode()).isEqualTo(1);
  }

  // ── Argument validation (RC-47, RC-54(a)) ───────────────────────────────────────────────

  @ParameterizedTest
  @ValueSource(strings = {"not-a-uuid", "1-1-1-1-1", "", "0195f3a01c2d7e8f9a0b1c2d3e4f5a6b"})
  void should_exit2_andRecordInvalidArgument_when_targetUserIdIsNotAUuid(String target)
      throws Exception {
    runner.run(args("--target-user-id=" + target, "--change-ref=" + VALID_REF));

    assertInvalidArgument();
  }

  @Test
  void should_acceptUppercaseCanonicalUuid() throws Exception {
    UUID target = UUID.fromString(VALID_TARGET);
    when(service.grantFirstAdmin(target, new ChangeRef(VALID_REF)))
        .thenReturn(new BreakGlassOutcome.Granted(UUID.randomUUID(), target, UUID.randomUUID()));

    runner.run(
        args("--target-user-id=" + VALID_TARGET.toUpperCase(), "--change-ref=" + VALID_REF));

    assertThat(runner.getExitCode()).isZero();
  }

  @Test
  void should_exit2_when_targetUserIdOrChangeRefMissing() throws Exception {
    runner.run(args("--change-ref=" + VALID_REF));
    assertInvalidArgument();

    runner.run(args("--target-user-id=" + VALID_TARGET));
    assertThat(runner.getExitCode()).isEqualTo(2);

    runner.run(args());
    assertThat(runner.getExitCode()).isEqualTo(2);

    // "--change-ref ABC-1" (a space, not "=") is an option without a value plus a stray argument.
    runner.run(args("--target-user-id=" + VALID_TARGET, "--change-ref", VALID_REF));
    assertThat(runner.getExitCode()).isEqualTo(2);
    verify(service, never()).grantFirstAdmin(any(), any());
  }

  @Test
  void should_exit2_when_optionRepeated() throws Exception {
    runner.run(
        args(
            "--target-user-id=" + VALID_TARGET,
            "--target-user-id=" + VALID_TARGET,
            "--change-ref=" + VALID_REF));
    assertInvalidArgument();

    runner.run(
        args("--target-user-id=" + VALID_TARGET, "--change-ref=ABC-1", "--change-ref=ABC-2"));
    assertThat(runner.getExitCode()).isEqualTo(2);
    verify(service, never()).grantFirstAdmin(any(), any());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "ABC-0",
        "ABC-01",
        "abc-1",
        "fix tenant",
        "ABC-1\n",
        "A-1",
        "ABCDEFGHIJK-1",
        "ABC-123456789",
        "ABC-0001",
        ""
      })
  void should_exit2_when_changeRefIsNotCanonical(String changeRef) throws Exception {
    runner.run(args("--target-user-id=" + VALID_TARGET, "--change-ref=" + changeRef));

    assertInvalidArgument();
  }

  @ParameterizedTest
  @ValueSource(strings = {"ABC-1", "ABCDEFGHIJ-12345678"})
  void should_passValidatedArgumentsToGrant_when_bothCanonical(String changeRef) throws Exception {
    UUID target = UUID.fromString(VALID_TARGET);
    when(service.grantFirstAdmin(target, new ChangeRef(changeRef)))
        .thenReturn(new BreakGlassOutcome.Granted(UUID.randomUUID(), target, UUID.randomUUID()));

    runner.run(
        args(
            "--target-user-id=" + VALID_TARGET,
            "--change-ref=" + changeRef,
            "--spring.profiles.active=break-glass",
            "positional"));

    verify(service).grantFirstAdmin(target, new ChangeRef(changeRef));
    verify(service, never()).recordInvalidArgument();
    assertThat(runner.getExitCode()).isZero();
  }

  /**
   * L-6: with a REAL service over mocked ports, an invalid argument reaches neither the audit row
   * nor the page, and nothing is looked up.
   */
  @Test
  void should_passNoRawArgumentToAlertOrAudit_when_argumentInvalid() throws Exception {
    UserDirectoryPort userDirectoryPort = mock(UserDirectoryPort.class);
    UserRoleAssignmentPort userRoleAssignmentPort = mock(UserRoleAssignmentPort.class);
    RbacAuditPort rbacAuditPort = mock(RbacAuditPort.class);
    BreakGlassAlertPort alertPort = mock(BreakGlassAlertPort.class);
    BreakGlassGrantLookupPort lookupPort = mock(BreakGlassGrantLookupPort.class);
    PlatformTransactionManager transactionManager = mock(PlatformTransactionManager.class);
    BootstrapAdminService realService =
        new BootstrapAdminService(
            userDirectoryPort,
            userRoleAssignmentPort,
            rbacAuditPort,
            alertPort,
            lookupPort,
            transactionManager);
    BreakGlassAdminRunner realRunner =
        new BreakGlassAdminRunner(realService, new GenericApplicationContext(), Duration.ZERO);

    realRunner.run(args("--target-user-id=" + VALID_TARGET, "--change-ref=ABC-0001"));

    assertThat(realRunner.getExitCode()).isEqualTo(2);
    ArgumentCaptor<BreakGlassAlert> alert = ArgumentCaptor.forClass(BreakGlassAlert.class);
    verify(alertPort).alert(alert.capture());
    assertThat(alert.getValue().tenantId()).isNull();
    assertThat(alert.getValue().targetUserId()).isNull();
    assertThat(alert.getValue().changeRef()).isNull();
    assertThat(alert.getValue().reason()).isEqualTo("INVALID_ARGUMENT");
    ArgumentCaptor<BreakGlassAuditEvent> event = ArgumentCaptor.forClass(BreakGlassAuditEvent.class);
    verify(rbacAuditPort).recordBreakGlassRefusal(event.capture(), any());
    assertThat(event.getValue()).isEqualTo(new BreakGlassAuditEvent(null, null, null));
    verifyNoInteractions(lookupPort, userDirectoryPort, userRoleAssignmentPort, transactionManager);
  }

  @Test
  void should_neverLogAnArgument() throws Exception {
    runner.run(args("--target-user-id=" + VALID_TARGET, "--change-ref=fix tenant"));

    assertThat(runnerLog.list)
        .allSatisfy(
            e -> {
              assertThat(e.getFormattedMessage()).doesNotContain(VALID_TARGET, "fix tenant");
              assertThat(String.valueOf(e.getKeyValuePairs()))
                  .doesNotContain(VALID_TARGET, "fix tenant");
            });
  }

  // ── Web-context guard (RC-37.6, RC-50(d)) ───────────────────────────────────────────────

  @Test
  void should_throwAndLogWebContextAlert_when_contextIsServletWeb() {
    BreakGlassAdminRunner webRunner =
        new BreakGlassAdminRunner(service, new GenericWebApplicationContext(), Duration.ZERO);

    assertThatThrownBy(webRunner::afterPropertiesSet)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("web-application-type")
        .hasMessageContaining("SERVLET");

    assertThat(runnerLog.list).hasSize(1);
    ILoggingEvent event = runnerLog.list.get(0);
    assertThat(event.getLevel()).isEqualTo(Level.ERROR);
    assertThat(keyValues(event))
        .containsEntry("event", "RBAC_BREAK_GLASS_USED")
        .containsEntry("outcome", "REFUSED")
        .containsEntry("reason", "WEB_CONTEXT")
        .doesNotContainKeys("tenantId", "targetUserId", "changeRef");
    verifyNoInteractions(service);
  }

  @Test
  void should_throw_when_contextIsReactiveWeb() {
    BreakGlassAdminRunner webRunner =
        new BreakGlassAdminRunner(
            service, new GenericReactiveWebApplicationContext(), Duration.ZERO);

    assertThatThrownBy(webRunner::afterPropertiesSet)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("REACTIVE");
    assertThat(keyValues(runnerLog.list.get(0))).containsEntry("reason", "WEB_CONTEXT");
  }

  /** T-008 review Low 2: the WEB_CONTEXT page gets the same capture window as every other page. */
  @Test
  void should_waitConfiguredFlushInterval_beforeThrowing_when_contextIsServletWeb() {
    BreakGlassAdminRunner webRunner =
        new BreakGlassAdminRunner(
            service, new GenericWebApplicationContext(), Duration.ofMillis(50));

    long start = System.nanoTime();
    assertThatThrownBy(webRunner::afterPropertiesSet).isInstanceOf(IllegalStateException.class);
    long elapsed = System.nanoTime() - start;

    assertThat(Duration.ofNanos(elapsed)).isGreaterThanOrEqualTo(Duration.ofMillis(50));
  }

  @Test
  void should_passGuard_when_contextIsNotWeb() {
    assertThatCode(runner::afterPropertiesSet).doesNotThrowAnyException();

    assertThat(runnerLog.list).isEmpty();
  }

  // ── Log-flush wait (RC-37.4) ────────────────────────────────────────────────────────────

  @Test
  void should_waitConfiguredFlushInterval_beforeReturning() throws Exception {
    BreakGlassAdminRunner waiting =
        new BreakGlassAdminRunner(service, new GenericApplicationContext(), Duration.ofMillis(50));

    long start = System.nanoTime();
    waiting.run(args());
    long elapsed = System.nanoTime() - start;

    assertThat(Duration.ofNanos(elapsed)).isGreaterThanOrEqualTo(Duration.ofMillis(50));
    assertThat(waiting.getExitCode()).isEqualTo(2);
  }

  @Test
  void should_restoreInterruptFlag_andKeepExitCode_when_interruptedDuringFlushWait()
      throws Exception {
    BreakGlassAdminRunner waiting =
        new BreakGlassAdminRunner(service, new GenericApplicationContext(), Duration.ofSeconds(30));
    Thread.currentThread().interrupt();
    try {
      waiting.run(args());

      assertThat(Thread.currentThread().isInterrupted()).isTrue();
      assertThat(waiting.getExitCode()).isEqualTo(2);
      assertThat(runnerLog.list)
          .anySatisfy(e -> assertThat(e.getLevel()).isEqualTo(Level.WARN));
    } finally {
      Thread.interrupted();
    }
  }

  // ── Profile configuration ───────────────────────────────────────────────────────────────

  @Test
  void should_pinBreakGlassProfileConfig() throws IOException {
    List<PropertySource<?>> sources =
        new YamlPropertySourceLoader()
            .load("break-glass", new ClassPathResource("application-break-glass.yml"));

    assertThat(sources).hasSize(1);
    PropertySource<?> config = sources.get(0);
    assertThat(value(config, "spring.config.activate.on-profile")).isEqualTo("break-glass");
    assertThat(value(config, "spring.main.web-application-type")).isEqualTo("none");
    assertThat(value(config, "spring.flyway.enabled")).isEqualTo("false");
    assertThat(value(config, "nexus.rbac.break-glass.log-flush-wait"))
        .isEqualTo("${NEXUS_RBAC_BREAK_GLASS_LOG_FLUSH_WAIT:15s}");
    // Pool size 4 is a user decision (T-008 review); no longer a correctness minimum.
    assertThat(value(config, "spring.datasource.hikari.maximum-pool-size")).isEqualTo("4");
  }

  // ── Helpers ─────────────────────────────────────────────────────────────────────────────

  private void assertInvalidArgument() {
    assertThat(runner.getExitCode()).isEqualTo(2);
    verify(service).recordInvalidArgument();
    verify(service, never()).grantFirstAdmin(any(), any());
  }

  private static String value(PropertySource<?> source, String key) {
    Object value = source.getProperty(key);
    return value == null ? null : value.toString();
  }

  private static DefaultApplicationArguments args(String... args) {
    return new DefaultApplicationArguments(args);
  }

  private static Map<String, Object> keyValues(ILoggingEvent event) {
    Map<String, Object> map = new HashMap<>();
    if (event.getKeyValuePairs() != null) {
      event.getKeyValuePairs().forEach(kv -> map.put(kv.key, kv.value));
    }
    return map;
  }

  private static Logger runnerLogger() {
    return (Logger) LoggerFactory.getLogger(BreakGlassAdminRunner.class);
  }
  @Test
  void should_verify_flush_completion_before_exit() throws Exception {
    Runnable logFlusher = mock(Runnable.class);
    BreakGlassAdminRunner customRunner =
        new BreakGlassAdminRunner(service, new GenericApplicationContext(), Duration.ZERO, null, logFlusher);

    customRunner.run(args());

    verify(logFlusher, atLeastOnce()).run();
  }
}
