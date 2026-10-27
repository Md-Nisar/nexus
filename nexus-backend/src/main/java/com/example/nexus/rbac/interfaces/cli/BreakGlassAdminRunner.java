package com.example.nexus.rbac.interfaces.cli;

import com.example.nexus.common.Profiles;
import com.example.nexus.rbac.application.BootstrapAdminService;
import com.example.nexus.rbac.application.BreakGlassOutcome;
import com.example.nexus.rbac.application.BreakGlassRefusalReason;
import com.example.nexus.rbac.application.ChangeRef;
import java.io.PrintStream;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.ExitCodeGenerator;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.web.context.reactive.ReactiveWebApplicationContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;

/**
 * US-018 A7 break-glass CLI (T-008; 03-design.md §7.1, §7.2; ADR-0025): {@code java -jar} with
 * profile {@code break-glass}, {@code --target-user-id=<uuid>} and {@code --change-ref=<ref>}.
 * Runs once during startup; {@code NexusApplication.main} then exits through {@code
 * SpringApplication.exit} with the code this bean reports as an {@link ExitCodeGenerator}.
 *
 * <ul>
 *   <li><b>Web-context guard</b> (RC-37.6, RC-50(d)): unless the context is non-web, bean
 *       initialization logs the paging ERROR {@code RBAC_BREAK_GLASS_USED {reason=WEB_CONTEXT}},
 *       waits one log-shipper flush interval and throws, failing the context refresh before the
 *       embedded server starts. Log only: no audit row.
 *   <li><b>Arguments</b> (RC-47, RC-54(a), L-6): each option exactly once; the target a UUID in
 *       canonical form, the change reference a {@link ChangeRef}. Anything else is refused through
 *       {@link BootstrapAdminService#recordInvalidArgument()} (exit 2), which takes no argument
 *       value. Other options (for example {@code --spring.*}) and positional arguments are
 *       ignored. This class never logs an argument value.
 *   <li><b>Page capture</b> (RC-37.4): waits one configured log-shipper flush interval before
 *       returning, also when the run throws.
 * </ul>
 */
@Component
@Profile(Profiles.BREAK_GLASS)
public class BreakGlassAdminRunner
    implements ApplicationRunner, ExitCodeGenerator, InitializingBean {

  private static final Logger log = LoggerFactory.getLogger(BreakGlassAdminRunner.class);

  static final String TARGET_USER_ID_OPTION = "target-user-id";
  static final String CHANGE_REF_OPTION = "change-ref";

  private final BootstrapAdminService bootstrapAdminService;
  private final WebApplicationType webApplicationType;
  private final Duration logFlushWait;
  private final PrintStream out;

  /** Reset to 1 at the start of every run, so a failed run cannot report success. */
  private int exitCode = BreakGlassRefusalReason.UNEXPECTED_ERROR.exitCode();

  /**
   * Creates the runner. The context is read once, here, for its web type; it is not retained.
   *
   * @param bootstrapAdminService the break-glass service
   * @param applicationContext the context this bean lives in
   * @param logFlushWait {@code nexus.rbac.break-glass.log-flush-wait} (RC-37.4)
   */
  public BreakGlassAdminRunner(
      BootstrapAdminService bootstrapAdminService,
      ApplicationContext applicationContext,
      @Value("${nexus.rbac.break-glass.log-flush-wait}") Duration logFlushWait) {
    this(bootstrapAdminService, applicationContext, logFlushWait, defaultOut());
  }

  BreakGlassAdminRunner(
      BootstrapAdminService bootstrapAdminService,
      ApplicationContext applicationContext,
      Duration logFlushWait,
      PrintStream out) {
    this.bootstrapAdminService = bootstrapAdminService;
    this.webApplicationType = effectiveWebApplicationType(applicationContext);
    this.logFlushWait = logFlushWait;
    this.out = out != null ? out : defaultOut();
  }

  /**
   * The web-context guard. Throws unless the context is non-web.
   *
   * @throws IllegalStateException if the context is a servlet or reactive web context
   */
  @Override
  public void afterPropertiesSet() {
    if (webApplicationType == WebApplicationType.NONE) {
      return;
    }
    log.atError()
        .addKeyValue("event", "RBAC_BREAK_GLASS_USED")
        .addKeyValue("outcome", "REFUSED")
        .addKeyValue("reason", "WEB_CONTEXT")
        .log("Break-glass profile active in a {} web context; refusing to start",
            webApplicationType);
    // RC-37.4: the WEB_CONTEXT page needs the same capture window as every other page.
    waitForLogFlush();
    throw new IllegalStateException(
        "The break-glass profile requires spring.main.web-application-type=none, but the context"
            + " is "
            + webApplicationType
            + " (RC-37.6)");
  }

  @Override
  public void run(ApplicationArguments args) {
    exitCode = BreakGlassRefusalReason.UNEXPECTED_ERROR.exitCode();
    try {
      exitCode = dispatch(args);
    } finally {
      waitForLogFlush();
    }
  }

  @Override
  public int getExitCode() {
    return exitCode;
  }

  private int dispatch(ApplicationArguments args) {
    Optional<UUID> targetUserId =
        singleValue(args, TARGET_USER_ID_OPTION).flatMap(BreakGlassAdminRunner::canonicalUuid);
    Optional<ChangeRef> changeRef =
        singleValue(args, CHANGE_REF_OPTION).flatMap(BreakGlassAdminRunner::changeRef);
    BreakGlassOutcome outcome =
        targetUserId.isPresent() && changeRef.isPresent()
            ? bootstrapAdminService.grantFirstAdmin(targetUserId.get(), changeRef.get())
            : bootstrapAdminService.recordInvalidArgument();
    emitCompletionJson(outcome);
    return outcome.exitCode();
  }

  private void emitCompletionJson(BreakGlassOutcome outcome) {
    String timestamp = Instant.now().toString();
    String level = outcome.exitCode() == 0 ? "INFO" : "WARN";
    String eventOutcome = outcome.exitCode() == 0 ? "success" : "failure";
    int code = outcome.exitCode();
    String json =
        String.format(
            "{\"@timestamp\":\"%s\",\"log.level\":\"%s\",\"message\":\"Break-glass"
                + " execution finished\",\"event\":{\"action\":\"break_glass\","
                + "\"outcome\":\"%s\"},\"process\":{\"exit_code\":%d}}",
            timestamp, level, eventOutcome, code);
    out.println(json);
  }

  private void waitForLogFlush() {
    try {
      Thread.sleep(logFlushWait);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      log.atWarn()
          .addKeyValue("event", "RBAC_BREAK_GLASS_FLUSH_WAIT_INTERRUPTED")
          .log("Break-glass log-flush wait interrupted; the page may not have been shipped");
    }
  }

  private static Optional<String> singleValue(ApplicationArguments args, String option) {
    List<String> values = args.getOptionValues(option);
    return values != null && values.size() == 1 ? Optional.of(values.get(0)) : Optional.empty();
  }

  /** {@link UUID#fromString} is lenient ({@code 1-1-1-1-1}); only the canonical form passes. */
  private static Optional<UUID> canonicalUuid(String raw) {
    try {
      UUID uuid = UUID.fromString(raw);
      return uuid.toString().equalsIgnoreCase(raw) ? Optional.of(uuid) : Optional.empty();
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  private static Optional<ChangeRef> changeRef(String raw) {
    try {
      return Optional.of(new ChangeRef(raw));
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  private static WebApplicationType effectiveWebApplicationType(ApplicationContext context) {
    if (context instanceof WebApplicationContext) {
      return WebApplicationType.SERVLET;
    }
    if (context instanceof ReactiveWebApplicationContext) {
      return WebApplicationType.REACTIVE;
    }
    return WebApplicationType.NONE;
  }
  private static PrintStream defaultOut() {
    return new PrintStream(
        new java.io.FileOutputStream(java.io.FileDescriptor.out),
        false,
        java.nio.charset.StandardCharsets.UTF_8);
  }
}
