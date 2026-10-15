package com.example.nexus.rbac.interfaces.cli;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.application.BootstrapAdminService;
import com.example.nexus.rbac.application.BreakGlassOutcome;
import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlertPort;
import com.example.nexus.rbac.application.port.out.BreakGlassAuditEvent;
import com.example.nexus.rbac.application.port.out.BreakGlassGrantLookupPort;
import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.DefaultApplicationArguments;

/** Unit tests for {@link BreakGlassAdminRunner} (US-018 A7, T-008; 03-design.md §7.1). */
@Tag("UnitTest")
class BreakGlassAdminRunnerTest {

  private static final UUID TARGET = UUID.fromString("0198a000-0000-7000-8000-000000000042");

  private final BootstrapAdminService service = mock(BootstrapAdminService.class);
  private final BreakGlassAlertPort alertPort = mock(BreakGlassAlertPort.class);
  private final BreakGlassExit exit = mock(BreakGlassExit.class);

  private BreakGlassAdminRunner runner(Duration flushInterval) {
    return new BreakGlassAdminRunner(service, alertPort, exit, flushInterval);
  }

  private static DefaultApplicationArguments args(String... args) {
    return new DefaultApplicationArguments(args);
  }

  private static DefaultApplicationArguments validArgs() {
    return args("--target-user-id=" + TARGET, "--change-ref=OPS-12");
  }

  // ── Exit-code mapping ────────────────────────────────────────────────────────────────

  @ParameterizedTest
  @EnumSource(BreakGlassOutcome.class)
  void should_exitWithTheOutcomeCode_when_serviceReturnsAnyOutcome(BreakGlassOutcome outcome) {
    when(service.grantFirstAdmin(TARGET, "OPS-12")).thenReturn(outcome);

    runner(Duration.ZERO).run(validArgs());

    verify(exit).exit(outcome.exitCode());
  }

  @Test
  void should_mapEveryDocumentedExitCode() {
    assertThat(BreakGlassOutcome.GRANTED.exitCode()).isZero();
    assertThat(BreakGlassOutcome.INVALID_ARGUMENT.exitCode()).isEqualTo(2);
    assertThat(BreakGlassOutcome.USER_NOT_FOUND.exitCode()).isEqualTo(3);
    assertThat(BreakGlassOutcome.USER_NOT_ACTIVE.exitCode()).isEqualTo(3);
    assertThat(BreakGlassOutcome.NO_SYSTEM_ADMIN_ROLE.exitCode()).isEqualTo(4);
    assertThat(BreakGlassOutcome.TENANT_HAS_ADMIN.exitCode()).isEqualTo(5);
    assertThat(BreakGlassOutcome.CHANGE_REF_REUSED.exitCode()).isEqualTo(6);
  }

  @Test
  void should_passParsedArgumentsToTheService_when_theyAreValid() {
    when(service.grantFirstAdmin(TARGET, "OPS-12")).thenReturn(BreakGlassOutcome.GRANTED);

    runner(Duration.ZERO).run(validArgs());

    verify(service).grantFirstAdmin(TARGET, "OPS-12");
    verify(service, never()).refuseInvalidArgument();
  }

  @Test
  void should_exit1AndPageWithTheValidatedIdentifiers_when_theGrantFailsAfterValidation() {
    when(service.grantFirstAdmin(TARGET, "OPS-12")).thenThrow(new IllegalStateException("db down"));

    runner(Duration.ZERO).run(validArgs());

    verify(exit).exit(1);
    ArgumentCaptor<BreakGlassAlert> captor = ArgumentCaptor.forClass(BreakGlassAlert.class);
    verify(alertPort).raise(captor.capture());
    // M5 L-4: both values passed validation, so a grant whose COMMIT ack was lost is traceable.
    assertThat(captor.getValue())
        .isEqualTo(
            new BreakGlassAlert(
                null, TARGET, BreakGlassAlert.OUTCOME_ERROR, "UNEXPECTED_ERROR", "OPS-12"));
  }

  @Test
  void should_exit1AndPageWithoutIdentifiers_when_theFailureHappensBeforeValidationSucceeds() {
    when(service.refuseInvalidArgument()).thenThrow(new IllegalStateException("db down"));

    runner(Duration.ZERO).run(args("--target-user-id=not-a-uuid", "--change-ref=OPS-12"));

    verify(exit).exit(1);
    ArgumentCaptor<BreakGlassAlert> captor = ArgumentCaptor.forClass(BreakGlassAlert.class);
    verify(alertPort).raise(captor.capture());
    // RC-54(a) / L-6: a rejected value is never echoed, and the valid half is withheld with it.
    assertThat(captor.getValue())
        .isEqualTo(new BreakGlassAlert(null, null, BreakGlassAlert.OUTCOME_ERROR, "UNEXPECTED_ERROR", null));
  }

  // ── Argument validation (RC-54(a), RC-47) ───────────────────────────────────────────

  static Stream<Arguments> invalidArguments() {
    String ok = "--target-user-id=" + TARGET;
    return Stream.of(
        Arguments.of("non-UUID target", new String[] {"--target-user-id=not-a-uuid", "--change-ref=OPS-12"}),
        Arguments.of("short UUID", new String[] {"--target-user-id=1-1-1-1-1", "--change-ref=OPS-12"}),
        Arguments.of("UUID with trailing text", new String[] {"--target-user-id=" + TARGET + "x", "--change-ref=OPS-12"}),
        Arguments.of("missing target", new String[] {"--change-ref=OPS-12"}),
        Arguments.of("missing change-ref", new String[] {ok}),
        Arguments.of("no arguments", new String[] {}),
        Arguments.of("blank change-ref", new String[] {ok, "--change-ref="}),
        Arguments.of("repeated target", new String[] {ok, ok, "--change-ref=OPS-12"}),
        Arguments.of("repeated change-ref", new String[] {ok, "--change-ref=OPS-1", "--change-ref=OPS-2"}));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("invalidArguments")
  void should_exit2AndRefuseWithoutGranting_when_anArgumentIsMissingOrMalformed(
      String description, String[] arguments) {
    when(service.refuseInvalidArgument()).thenReturn(BreakGlassOutcome.INVALID_ARGUMENT);

    runner(Duration.ZERO).run(args(arguments));

    verify(exit).exit(2);
    verify(service).refuseInvalidArgument();
    verify(service, never()).grantFirstAdmin(any(), any());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "ABC-0", // zero is not a ticket number
        "ABC-01", // leading zero (RC-47)
        "ABC-0001",
        "abc-1", // lowercase
        "Abc-1",
        "fix tenant", // free text
        "A-1", // prefix needs 2 to 10 characters
        "ABCDEFGHIJK-1", // 11-character prefix
        "1ABC-1", // prefix starts with a letter
        "ABC-123456789", // 9-digit number
        "ABC-1 ",
        " ABC-1",
        "ABC-1\n",
        "ABC--1",
        "ABC_1",
        "ABC-1; DROP TABLE auth_events",
        "ABC-١" // non-ASCII digit
      })
  void should_exit2_when_changeRefIsNotTheCanonicalTicketShape(String changeRef) {
    when(service.refuseInvalidArgument()).thenReturn(BreakGlassOutcome.INVALID_ARGUMENT);

    runner(Duration.ZERO).run(args("--target-user-id=" + TARGET, "--change-ref=" + changeRef));

    verify(exit).exit(2);
    verify(service, never()).grantFirstAdmin(any(), any());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"AB-1", "ABC-1", "OPS-4711", "A1-9", "ABCDEFGHIJ-12345678", "A0000000A0-99999999"})
  void should_accept_when_changeRefIsTheCanonicalTicketShape(String changeRef) {
    when(service.grantFirstAdmin(TARGET, changeRef)).thenReturn(BreakGlassOutcome.GRANTED);

    runner(Duration.ZERO).run(args("--target-user-id=" + TARGET, "--change-ref=" + changeRef));

    verify(service).grantFirstAdmin(TARGET, changeRef);
    verify(exit).exit(0);
  }

  /**
   * L-6 / RC-54(a): through the REAL service, a rejected argument reaches neither the audit row
   * nor the page. The runner passes nothing to either port on this path.
   */
  @Test
  void should_passNoRawArgumentToAuditOrAlertPort_when_argumentsAreInvalid() {
    RbacAuditPort auditPort = mock(RbacAuditPort.class);
    BootstrapAdminService realService =
        new BootstrapAdminService(
            mock(UserRoleAssignmentPort.class),
            mock(UserDirectoryPort.class),
            auditPort,
            alertPort,
            mock(BreakGlassGrantLookupPort.class),
            mock(PermissionCachePort.class));
    BreakGlassAdminRunner real = new BreakGlassAdminRunner(realService, alertPort, exit, Duration.ZERO);

    real.run(args("--target-user-id=SECRET-TARGET", "--change-ref=ABC-0001"));

    ArgumentCaptor<BreakGlassAlert> alert = ArgumentCaptor.forClass(BreakGlassAlert.class);
    verify(alertPort).raise(alert.capture());
    assertThat(alert.getValue())
        .isEqualTo(
            new BreakGlassAlert(null, null, BreakGlassAlert.OUTCOME_REFUSED, "INVALID_ARGUMENT", null));
    ArgumentCaptor<BreakGlassAuditEvent> row = ArgumentCaptor.forClass(BreakGlassAuditEvent.class);
    verify(auditPort).recordBreakGlassRefused(row.capture());
    assertThat(row.getValue()).isEqualTo(new BreakGlassAuditEvent(null, null, null, "INVALID_ARGUMENT"));
    assertThat(List.of(alert.getValue().toString(), row.getValue().toString()))
        .allSatisfy(text -> assertThat(text).doesNotContain("ABC-0001").doesNotContain("SECRET-TARGET"));
    verify(exit).exit(2);
  }

  @Test
  void should_neverTouchTheAlertPortItself_when_argumentsAreInvalid() {
    when(service.refuseInvalidArgument()).thenReturn(BreakGlassOutcome.INVALID_ARGUMENT);

    runner(Duration.ZERO).run(args("--target-user-id=x", "--change-ref=fix tenant"));

    verifyNoInteractions(alertPort);
  }

  // ── Log-shipper flush wait (RC-37.4) ────────────────────────────────────────────────

  @Test
  void should_waitOneFlushIntervalBeforeExiting() {
    when(service.grantFirstAdmin(TARGET, "OPS-12")).thenReturn(BreakGlassOutcome.GRANTED);
    long[] exitedAtNanos = new long[1];
    BreakGlassExit timedExit = code -> exitedAtNanos[0] = System.nanoTime();
    BreakGlassAdminRunner timed =
        new BreakGlassAdminRunner(service, alertPort, timedExit, Duration.ofMillis(200));

    long start = System.nanoTime();
    timed.run(validArgs());

    assertThat(Duration.ofNanos(exitedAtNanos[0] - start)).isGreaterThanOrEqualTo(Duration.ofMillis(190));
  }

  @Test
  void should_decideBeforeExiting() {
    when(service.grantFirstAdmin(TARGET, "OPS-12")).thenReturn(BreakGlassOutcome.GRANTED);

    runner(Duration.ofMillis(5)).run(validArgs());

    var order = inOrder(service, exit);
    order.verify(service).grantFirstAdmin(TARGET, "OPS-12");
    order.verify(exit).exit(0);
  }
}
