package com.example.nexus.rbac.interfaces.cli;

import com.example.nexus.rbac.application.BootstrapAdminService;
import com.example.nexus.rbac.application.BreakGlassOutcome;
import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlertPort;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * The break-glass first-administrator CLI (US-018 A7, ADR-0025, 03-design.md §7). Run from the
 * service jar with profile {@code break-glass}: {@code --target-user-id=<uuid> --change-ref=<ticket>}.
 *
 * <p>It validates both arguments, hands them to {@link BootstrapAdminService}, waits one
 * log-shipper flush interval so the page is read before the pod can vanish (RC-37.4), then exits
 * with the outcome's code: 0 granted, 1 unexpected error, 2 invalid argument, 3 user missing or
 * not ACTIVE, 4 no system {@code TENANT_ADMIN}, 5 tenant already has an administrator, 6 change
 * reference already used. No picocli or spring-shell: two arguments do not justify a dependency.
 *
 * <p><b>L-6 / RC-54(a):</b> a rejected argument is never echoed. On an invalid argument the runner
 * calls {@link BootstrapAdminService#refuseInvalidArgument()}, which takes no argument, and passes
 * nothing to the alert port itself; so neither the audit row nor the page nor any log line holds
 * the rejected value.
 */
@Component
@Profile("break-glass")
public class BreakGlassAdminRunner implements ApplicationRunner {

  private static final Logger log = LoggerFactory.getLogger(BreakGlassAdminRunner.class);

  static final String OPTION_TARGET_USER_ID = "target-user-id";
  static final String OPTION_CHANGE_REF = "change-ref";

  /** Exit code for a failure no outcome describes (a database or audit error). */
  static final int EXIT_UNEXPECTED_ERROR = 1;

  /**
   * The only admissible change reference (RC-37.1, RC-47): a ticket id, one canonical form. The
   * number has no leading zero, so {@code ABC-1}, {@code ABC-01} and {@code ABC-0001} cannot be
   * three strings for one ticket. ASCII only; no free text.
   */
  private static final Pattern CHANGE_REF = Pattern.compile("[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,7}");

  private static final Pattern UUID_TEXT =
      Pattern.compile(
          "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

  private final BootstrapAdminService bootstrapAdminService;
  private final BreakGlassAlertPort alertPort;
  private final BreakGlassExit exit;
  private final Duration logFlushInterval;

  public BreakGlassAdminRunner(
      BootstrapAdminService bootstrapAdminService,
      BreakGlassAlertPort alertPort,
      BreakGlassExit exit,
      @Value("${nexus.rbac.break-glass.log-flush-interval:15s}") Duration logFlushInterval) {
    this.bootstrapAdminService = bootstrapAdminService;
    this.alertPort = alertPort;
    this.exit = exit;
    this.logFlushInterval = logFlushInterval;
  }

  @Override
  public void run(ApplicationArguments args) {
    int exitCode = execute(args);
    awaitLogShipper();
    exit.exit(exitCode);
  }

  private int execute(ApplicationArguments args) {
    // Set only once BOTH arguments have passed validation; they alone may appear in an error page.
    UUID targetUserId = null;
    String changeRef = null;
    try {
      UUID parsedTarget = parseTargetUserId(args);
      String parsedRef = parseChangeRef(args);
      if (parsedTarget == null || parsedRef == null) {
        return bootstrapAdminService.refuseInvalidArgument().exitCode();
      }
      targetUserId = parsedTarget;
      changeRef = parsedRef;
      BreakGlassOutcome outcome = bootstrapAdminService.grantFirstAdmin(targetUserId, changeRef);
      return outcome.exitCode();
    } catch (RuntimeException e) {
      // A database or audit failure. The grant may or may not have committed (a lost COMMIT ack), so
      // when both arguments had passed validation the page carries them (M5 L-4, D-26): an
      // operator can then find the outcome in the audit table. A failure before validation
      // succeeded pages without identifiers (RC-54(a), L-6).
      log.error("break-glass invocation failed unexpectedly", e);
      alertPort.raise(
          new BreakGlassAlert(
              null, targetUserId, BreakGlassAlert.OUTCOME_ERROR, "UNEXPECTED_ERROR", changeRef));
      return EXIT_UNEXPECTED_ERROR;
    }
  }

  /** The target user id, or {@code null} when missing, repeated or not a canonical UUID. */
  private static UUID parseTargetUserId(ApplicationArguments args) {
    String value = singleValue(args, OPTION_TARGET_USER_ID);
    if (value == null || !UUID_TEXT.matcher(value).matches()) {
      return null;
    }
    return UUID.fromString(value);
  }

  /** The change reference, or {@code null} when missing, repeated or not the canonical shape. */
  private static String parseChangeRef(ApplicationArguments args) {
    String value = singleValue(args, OPTION_CHANGE_REF);
    if (value == null || !CHANGE_REF.matcher(value).matches()) {
      return null;
    }
    return value;
  }

  private static String singleValue(ApplicationArguments args, String option) {
    List<String> values = args.getOptionValues(option);
    if (values == null || values.size() != 1) {
      return null;
    }
    return values.get(0);
  }

  /** RC-37.4: give the node's log shipper one flush interval to read the page before exiting. */
  private void awaitLogShipper() {
    if (logFlushInterval.isZero() || logFlushInterval.isNegative()) {
      return;
    }
    try {
      Thread.sleep(logFlushInterval);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }
}
