package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.NexusApplication;
import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.audit.BreakGlassAlertAdapter;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.BootstrapAdminService;
import com.example.nexus.rbac.application.BreakGlassOutcome;
import com.example.nexus.rbac.application.BreakGlassRefusalReason;
import com.example.nexus.rbac.application.ChangeRef;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.domain.LastAdminRoleException;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.interfaces.cli.BreakGlassAdminRunner;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.TypeExcludeFilter;
import org.springframework.boot.logging.LoggingSystem;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.context.WebServerInitializedEvent;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.type.classreading.MetadataReader;
import org.springframework.core.type.classreading.MetadataReaderFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MySQLContainer;

/**
 * US-018 T-007 and T-008 TS-6 (03-design.md §7.1, §7.3): the break-glass first-administrator
 * grant against real MySQL. T-007 cases call the {@link BootstrapAdminService} bean directly;
 * T-008 cases drive a {@link BreakGlassAdminRunner} built over that bean (no flush wait) through
 * {@code run(ApplicationArguments)} and {@code getExitCode()}, so the real {@code
 * RbacAuthEventAdapter}, {@code BreakGlassAlertAdapter}, lookup and M10/M11 adapters run end to
 * end. Two T-008 cases start a separate {@code break-glass} application context against this
 * class's containers. Every log event is captured from the ROOT logger; the page is the {@link
 * BreakGlassAlertAdapter} subset.
 *
 * <p>Every test seeds its own fresh tenant; nothing touches the bootstrap tenant. Change
 * references used by T-008 cases are random, because the replay lookup is global.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class BreakGlassAdminIT {

  private static final String EVENT_TYPE = "ROLE_BREAK_GLASS_GRANT";

  @Autowired private BootstrapAdminService bootstrapAdminService;
  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private MySQLContainer<?> mysqlContainer;

  @Autowired
  @Qualifier("redisContainer")
  private GenericContainer<?> redisContainer;

  private ListAppender<ILoggingEvent> logs;

  @BeforeEach
  void captureLogs() {
    logs = new ListAppender<>();
    logs.start();
    rootLogger().addAppender(logs);
  }

  @AfterEach
  void stopCapture() {
    rootLogger().detachAppender(logs);
    logs.stop();
    jdbc.execute("DROP TRIGGER IF EXISTS trg_ts6_block_break_glass_success");
    jdbc.execute("DROP TRIGGER IF EXISTS trg_t008_signal_deadlock");
  }

  // ── Grant ─────────────────────────────────────────────────────────────────────────────────

  @Test
  void should_grantTenantAdmin_writeSuccessRow_andLogAlert_when_tenantHasZeroAdmins() {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User target = seedActiveUser(tenantId, "grant");
    String changeRef = freshChangeRef();

    BreakGlassOutcome outcome =
        bootstrapAdminService.grantFirstAdmin(target.getId(), new ChangeRef(changeRef));

    assertThat(outcome)
        .isEqualTo(new BreakGlassOutcome.Granted(tenantId, target.getId(), tenantAdmin.getId()));
    assertThat(outcome.exitCode()).isZero();
    Map<String, Object> assignment =
        jdbc.queryForMap(
            "SELECT assigned_by, tenant_id FROM user_roles WHERE user_id = ? AND role_id = ?"
                + " AND revoked_at IS NULL",
            toBytes(target.getId()),
            toBytes(tenantAdmin.getId()));
    assertThat(toUuid((byte[]) assignment.get("assigned_by"))).isEqualTo(target.getId());
    assertThat(toUuid((byte[]) assignment.get("tenant_id"))).isEqualTo(tenantId);

    List<Map<String, Object>> rows = auditRows(target.getId());
    assertThat(rows).hasSize(1);
    assertThat(rows.get(0))
        .containsEntry("outcome", "SUCCESS")
        .containsEntry("actor_type", "BREAK_GLASS_CLI")
        .containsEntry("change_ref", changeRef);
    assertThat(rows.get(0).get("reason")).isNull();
    assertThat(toUuid((byte[]) rows.get(0).get("tenant_id"))).isEqualTo(tenantId);

    assertThat(singleAlert())
        .containsEntry("event", "RBAC_BREAK_GLASS_USED")
        .containsEntry("outcome", "GRANTED")
        .containsEntry("tenantId", tenantId)
        .containsEntry("targetUserId", target.getId())
        .containsEntry("changeRef", changeRef);
  }

  // ── Refusals ──────────────────────────────────────────────────────────────────────────────

  @Test
  void should_refuseWithExit5_writeFailureRow_logAlert_andInsertNothing_when_tenantHasAnAdministrator() {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User admin = seedActiveUser(tenantId, "existing-admin");
    seedAssignment(tenantId, tenantAdmin.getId(), admin.getId());
    User target = seedActiveUser(tenantId, "target");

    BreakGlassOutcome outcome =
        bootstrapAdminService.grantFirstAdmin(target.getId(), new ChangeRef(freshChangeRef()));

    assertRefused(outcome, BreakGlassRefusalReason.TENANT_HAS_ADMIN, 5, target.getId(), tenantId);
    assertThat(countActive(tenantId, tenantAdmin.getId())).isEqualTo(1);
    assertThat(countActiveForUser(target.getId())).isZero();
  }

  @Test
  void should_refuseWithExit4_when_tenantHasNoSeededTenantAdminRole() {
    UUID tenantId = uuidGenerator.newId();
    User target = seedActiveUser(tenantId, "no-role");

    BreakGlassOutcome outcome =
        bootstrapAdminService.grantFirstAdmin(target.getId(), new ChangeRef(freshChangeRef()));

    assertRefused(
        outcome, BreakGlassRefusalReason.NO_SYSTEM_ADMIN_ROLE, 4, target.getId(), tenantId);
    assertThat(countActiveForUser(target.getId())).isZero();
  }

  @ParameterizedTest
  @ValueSource(strings = {"PENDING", "LOCKED", "DISABLED"})
  void should_refuseWithExit3_when_targetUserIsNotActive(String status) {
    UUID tenantId = uuidGenerator.newId();
    seedSystemTenantAdminRole(tenantId);
    User target = seedActiveUser(tenantId, "inactive");
    jdbc.update("UPDATE users SET status = ? WHERE id = ?", status, toBytes(target.getId()));

    BreakGlassOutcome outcome =
        bootstrapAdminService.grantFirstAdmin(target.getId(), new ChangeRef(freshChangeRef()));

    assertRefused(
        outcome, BreakGlassRefusalReason.TARGET_USER_NOT_ACTIVE, 3, target.getId(), tenantId);
    assertThat(countActiveForUser(target.getId())).isZero();
  }

  @Test
  void should_refuseWithExit3_withNullTenant_when_targetUserDoesNotExist() {
    UUID unknownUserId = uuidGenerator.newId();

    BreakGlassOutcome outcome =
        bootstrapAdminService.grantFirstAdmin(unknownUserId, new ChangeRef(freshChangeRef()));

    assertRefused(outcome, BreakGlassRefusalReason.TARGET_USER_NOT_FOUND, 3, unknownUserId, null);
  }

  @Test
  void should_refuseWithExit5_when_reRunAfterSuccessfulGrant() {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User target = seedActiveUser(tenantId, "rerun");
    String firstRef = freshChangeRef();
    String rerunRef = freshChangeRef();
    assertThat(
            bootstrapAdminService.grantFirstAdmin(target.getId(), new ChangeRef(firstRef)).exitCode())
        .isZero();

    BreakGlassOutcome rerun =
        bootstrapAdminService.grantFirstAdmin(target.getId(), new ChangeRef(rerunRef));

    assertThat(rerun).isEqualTo(new BreakGlassOutcome.Refused(BreakGlassRefusalReason.TENANT_HAS_ADMIN));
    assertThat(rerun.exitCode()).isEqualTo(5);
    assertThat(countActive(tenantId, tenantAdmin.getId())).isEqualTo(1);
    assertThat(auditRows(target.getId()))
        .extracting(r -> r.get("outcome") + "/" + r.get("change_ref"))
        .containsExactly("SUCCESS/" + firstRef, "FAILURE/" + rerunRef);
  }

  // ── Atomicity (TS-5 style) ────────────────────────────────────────────────────────────────

  /**
   * The grant rolls back with its failed SUCCESS row; T-008 then writes one UNEXPECTED_ERROR
   * FAILURE row (with the tenant) after the rollback, and pages it. No GRANTED page.
   */
  @Test
  void should_rollBackGrant_when_successAuditInsertFails() {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User target = seedActiveUser(tenantId, "rollback");
    jdbc.execute(
        "CREATE TRIGGER trg_ts6_block_break_glass_success BEFORE INSERT ON auth_events FOR EACH ROW"
            + " BEGIN IF NEW.event_type = 'ROLE_BREAK_GLASS_GRANT' AND NEW.outcome = 'SUCCESS'"
            + " THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'TS-6 test-only block'; END IF;"
            + " END");

    BreakGlassOutcome outcome =
        bootstrapAdminService.grantFirstAdmin(target.getId(), new ChangeRef(freshChangeRef()));

    assertRefused(
        outcome, BreakGlassRefusalReason.UNEXPECTED_ERROR, 1, target.getId(), tenantId);
    assertThat(countActive(tenantId, tenantAdmin.getId())).isZero();
    assertThat(alertEvents())
        .extracting(e -> keyValues(e).get("outcome"))
        .containsExactly("REFUSED");
  }

  // ── T-008: the runner ─────────────────────────────────────────────────────────────────────

  /** RC-37.2: an old approval cannot be replayed after the tenant falls to zero again. */
  @Test
  void should_refuseWithExit6_auditAndPage_andGrantNothing_when_usedChangeRefIsReplayedAfterAdminRevoked() {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User target = seedActiveUser(tenantId, "replay");
    String changeRef = freshChangeRef();
    assertThat(runCli(target.getId().toString(), changeRef)).isZero();
    jdbc.update(
        "UPDATE user_roles SET revoked_at = NOW(6) WHERE tenant_id = ? AND revoked_at IS NULL",
        toBytes(tenantId));
    assertThat(countActive(tenantId, tenantAdmin.getId())).isZero();
    logs.list.clear();

    int exitCode = runCli(target.getId().toString(), changeRef);

    assertThat(exitCode).isEqualTo(6);
    assertThat(countActive(tenantId, tenantAdmin.getId())).isZero();
    assertThat(auditRows(target.getId()))
        .extracting(r -> r.get("outcome") + "/" + r.get("change_ref") + "/" + r.get("reason"))
        .containsExactly(
            "SUCCESS/" + changeRef + "/null", "FAILURE/" + changeRef + "/CHANGE_REF_REUSED");
    Map<String, Object> failure = auditRows(target.getId()).get(1);
    assertThat(failure.get("tenant_id")).isNull();
    assertThat(singleAlert())
        .containsEntry("outcome", "REFUSED")
        .containsEntry("reason", "CHANGE_REF_REUSED")
        .containsEntry("targetUserId", target.getId())
        .containsEntry("changeRef", changeRef)
        .doesNotContainKey("tenantId");
  }

  /** RC-47: the lookup is global; a reference approves one grant anywhere. */
  @Test
  void should_refuseWithExit6_when_changeRefWasUsedOnASuccessfulGrantInAnotherTenant() {
    UUID tenantA = uuidGenerator.newId();
    seedSystemTenantAdminRole(tenantA);
    User targetA = seedActiveUser(tenantA, "tenant-a");
    UUID tenantB = uuidGenerator.newId();
    Role adminB = seedSystemTenantAdminRole(tenantB);
    User targetB = seedActiveUser(tenantB, "tenant-b");
    String changeRef = freshChangeRef();
    assertThat(runCli(targetA.getId().toString(), changeRef)).isZero();

    int exitCode = runCli(targetB.getId().toString(), changeRef);

    assertThat(exitCode).isEqualTo(6);
    assertThat(countActive(tenantB, adminB.getId())).isZero();
    assertThat(auditRows(targetB.getId()))
        .extracting(r -> r.get("outcome") + "/" + r.get("reason"))
        .containsExactly("FAILURE/CHANGE_REF_REUSED");
  }

  /**
   * RC-47 padded replay and RC-54(a)/L-6: {@code ABC-0001} after {@code ABC-1} (with a random
   * prefix in place of {@code ABC}, so a reused container never already holds it) fails argument
   * validation (exit 2), grants nothing, writes exactly one FAILURE row with no tenant, no user
   * and metadata {actorType, reason} only, and neither the padded value nor the target id appears
   * in that row or in any captured log event.
   */
  @Test
  void should_refuseWithExit2_writeOneValueFreeRow_andLogNoArgument_when_paddedReplayOfAUsedReference() {
    UUID tenantA = uuidGenerator.newId();
    seedSystemTenantAdminRole(tenantA);
    User first = seedActiveUser(tenantA, "padded-first");
    String prefix = randomTicketPrefix();
    String used = prefix + "-1";
    String padded = prefix + "-0001";
    assertThat(runCli(first.getId().toString(), used)).isZero();
    UUID tenantB = uuidGenerator.newId();
    Role adminB = seedSystemTenantAdminRole(tenantB);
    User target = seedActiveUser(tenantB, "padded-target");
    Set<String> idsBefore = authEventIds();
    logs.list.clear();

    int exitCode = runCli(target.getId().toString(), padded);

    assertThat(exitCode).isEqualTo(2);
    assertThat(countActive(tenantB, adminB.getId())).isZero();
    assertThat(countActiveForUser(target.getId())).isZero();
    Set<String> newIds = new HashSet<>(authEventIds());
    newIds.removeAll(idsBefore);
    assertThat(newIds).hasSize(1);
    Map<String, Object> row =
        jdbc.queryForMap(
            "SELECT event_type, outcome, tenant_id, user_id, CAST(metadata AS CHAR) AS metadata,"
                + " metadata = CAST('{\"actorType\":\"BREAK_GLASS_CLI\",\"reason\":\"INVALID_ARGUMENT\"}'"
                + " AS JSON) AS exact_metadata FROM auth_events WHERE id = UNHEX(?)",
            newIds.iterator().next());
    assertThat(row)
        .containsEntry("event_type", EVENT_TYPE)
        .containsEntry("outcome", "FAILURE");
    assertThat(row.get("tenant_id")).isNull();
    assertThat(row.get("user_id")).isNull();
    assertThat(((Number) row.get("exact_metadata")).intValue()).isEqualTo(1);
    assertThat((String) row.get("metadata"))
        .doesNotContain(padded, target.getId().toString());

    assertThat(singleAlert())
        .containsEntry("outcome", "REFUSED")
        .containsEntry("reason", "INVALID_ARGUMENT")
        .doesNotContainKeys("tenantId", "targetUserId", "changeRef");
    assertThat(logs.list).isNotEmpty();
    for (ILoggingEvent event : logs.list) {
      assertThat(renderEverything(event))
          .as("log event from %s", event.getLoggerName())
          .doesNotContain(padded, target.getId().toString());
    }
  }

  /**
   * A deadlock on the {@code user_roles} insert (signalled deterministically by a test-only
   * trigger, MySQL errno 1213, SQLSTATE 40001) rolls the grant back; the refusal is written after
   * the rollback with the tenant, and paged.
   */
  @Test
  void should_refuseWithExit7_writeFailureRowWithTenant_andPage_when_grantInsertDeadlocks() {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User target = seedActiveUser(tenantId, "deadlock");
    jdbc.execute(
        "CREATE TRIGGER trg_t008_signal_deadlock BEFORE INSERT ON user_roles FOR EACH ROW"
            + " BEGIN IF NEW.tenant_id = UUID_TO_BIN('" + tenantId + "') THEN"
            + " SIGNAL SQLSTATE '40001' SET MYSQL_ERRNO = 1213,"
            + " MESSAGE_TEXT = 'T-008 test-only deadlock'; END IF; END");
    String changeRef = freshChangeRef();

    int exitCode = runCli(target.getId().toString(), changeRef);

    assertThat(exitCode).isEqualTo(7);
    assertThat(countActive(tenantId, tenantAdmin.getId())).isZero();
    List<Map<String, Object>> rows = auditRows(target.getId());
    assertThat(rows)
        .extracting(r -> r.get("outcome") + "/" + r.get("change_ref") + "/" + r.get("reason"))
        .containsExactly("FAILURE/" + changeRef + "/CONCURRENT_INVOCATION");
    assertThat(toUuid((byte[]) rows.get(0).get("tenant_id"))).isEqualTo(tenantId);
    assertThat(singleAlert())
        .containsEntry("outcome", "REFUSED")
        .containsEntry("reason", "CONCURRENT_INVOCATION")
        .containsEntry("tenantId", tenantId)
        .containsEntry("targetUserId", target.getId());
    assertThat(logs.list)
        .anySatisfy(
            e -> assertThat(keyValues(e)).containsEntry("event", "RBAC_BREAK_GLASS_CONFLICT"));
  }

  /**
   * RC-37.6 / RC-50(d): the break-glass profile under a servlet web type fails the context refresh
   * in the runner's bean initialization, pages WEB_CONTEXT, and the embedded server never starts.
   */
  @Test
  void should_failContextRefresh_beforeWebServerStarts_when_breakGlassRunsWithServletWebType() {
    AtomicBoolean webServerInitialized = new AtomicBoolean();

    assertThatThrownBy(
            () ->
                runBreakGlassApplication(
                    webServerInitialized,
                    "--spring.main.web-application-type=servlet",
                    "--server.port=0",
                    "--target-user-id=" + UUID.randomUUID(),
                    "--change-ref=" + freshChangeRef()))
        .hasRootCauseInstanceOf(IllegalStateException.class)
        .rootCause()
        .hasMessageContaining("web-application-type");

    assertThat(webServerInitialized).isFalse();
    assertThat(logs.list)
        .anySatisfy(
            e ->
                assertThat(keyValues(e))
                    .containsEntry("event", "RBAC_BREAK_GLASS_USED")
                    .containsEntry("reason", "WEB_CONTEXT"));
  }

  /**
   * End to end through Spring Boot: a non-web break-glass context with a bad change reference runs
   * the runner during startup and reports exit 2 through {@code SpringApplication.exit}.
   */
  @Test
  void should_exitWith2ThroughSpringApplicationExit_when_nonWebBreakGlassContextGetsBadArguments()
      throws Exception {
    AtomicBoolean webServerInitialized = new AtomicBoolean();
    Set<String> idsBefore = authEventIds();

    ConfigurableApplicationContext context =
        runBreakGlassApplication(
            webServerInitialized,
            "--target-user-id=" + UUID.randomUUID(),
            "--change-ref=fix tenant");
    boolean webContext = context instanceof WebApplicationContext;
    int exitCode = SpringApplication.exit(context);

    assertThat(exitCode).isEqualTo(2);
    assertThat(webContext).isFalse();
    assertThat(webServerInitialized).isFalse();
    Set<String> newIds = new HashSet<>(authEventIds());
    newIds.removeAll(idsBefore);
    assertThat(newIds).hasSize(1);
  }

  // ── Concurrency ───────────────────────────────────────────────────────────────────────────

  /**
   * The tenant's last administrator self-revokes while the CLI runs against another user. Proves
   * the race ends cleanly: no deadlock, no 500, the revoke refused (409, last admin), the CLI
   * refused (exit 5) and exactly one active administrator row. It does NOT prove the zero-admin
   * check runs under the set lock: the outcome is the same in either lock order (the revoke is
   * always 409 and the CLI always sees one administrator), so it cannot tell a locked check from
   * an unlocked one. The unit test {@code
   * BootstrapAdminServiceTest#should_takeSetLockBeforeZeroAdminCheckBeforeInsert} covers ordering.
   */
  @Test
  void should_endWithoutDeadlockOr500_andKeepOneAdminRow_when_lastAdminSelfRevokeRacesCli()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User admin = seedActiveUser(tenantId, "last-admin");
    UserRole adminRow = seedAssignment(tenantId, tenantAdmin.getId(), admin.getId());
    User target = seedActiveUser(tenantId, "race-target");
    RoleChangeActor actor = new RoleChangeActor(admin.getId(), tenantId);

    ExecutorService executor = Executors.newFixedThreadPool(2);
    CyclicBarrier barrier = new CyclicBarrier(2);
    try {
      Future<String> revoke =
          executor.submit(
              (Callable<String>)
                  () -> {
                    barrier.await(5, TimeUnit.SECONDS);
                    try {
                      roleAssignmentService.revoke(
                          actor, admin.getId(), tenantAdmin.getId(), requestContext());
                      return "revoked";
                    } catch (LastAdminRoleException e) {
                      return "409";
                    }
                  });
      Future<String> cli =
          executor.submit(
              (Callable<String>)
                  () -> {
                    barrier.await(5, TimeUnit.SECONDS);
                    return "exit"
                        + bootstrapAdminService
                            .grantFirstAdmin(target.getId(), new ChangeRef(freshChangeRef()))
                            .exitCode();
                  });

      assertThat(List.of(revoke.get(30, TimeUnit.SECONDS), cli.get(30, TimeUnit.SECONDS)))
          .containsExactly("409", "exit5");
    } finally {
      executor.shutdownNow();
    }
    assertThat(countActive(tenantId, tenantAdmin.getId())).isEqualTo(1);
    assertThat(isActive(adminRow.getId())).isTrue();
    assertThat(countActiveForUser(target.getId())).isZero();
  }

  /**
   * Two CLI runs race on one zero-admin tenant for two different users, through the runner.
   * Exactly one grant goes through. The loser either sees one administrator (exit 5) or, because
   * the set lock finds no rows and takes only gap locks, dies with a deadlock on the {@code
   * user_roles} insert, which becomes an audited, paged CONCURRENT_INVOCATION refusal (exit 7)
   * written after the rollback (04-tasks.md T-008 risks).
   */
  @Test
  void should_grantExactlyOnce_when_twoCliRunsRaceOnTheSameZeroAdminTenant() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User first = seedActiveUser(tenantId, "race-1");
    User second = seedActiveUser(tenantId, "race-2");
    String firstRef = freshChangeRef();
    String secondRef = freshChangeRef();

    ExecutorService executor = Executors.newFixedThreadPool(2);
    CyclicBarrier barrier = new CyclicBarrier(2);
    List<Integer> exitCodes = new ArrayList<>();
    try {
      Future<Integer> a = submitCli(executor, barrier, first.getId(), firstRef);
      Future<Integer> b = submitCli(executor, barrier, second.getId(), secondRef);
      exitCodes.add(a.get(30, TimeUnit.SECONDS));
      exitCodes.add(b.get(30, TimeUnit.SECONDS));
    } finally {
      executor.shutdownNow();
    }

    assertThat(exitCodes).containsAnyOf(5, 7).contains(0).hasSize(2);
    boolean firstWon = exitCodes.get(0) == 0;
    User winner = firstWon ? first : second;
    User loser = firstWon ? second : first;
    String winnerRef = firstWon ? firstRef : secondRef;
    int loserExit = firstWon ? exitCodes.get(1) : exitCodes.get(0);
    String loserReason = loserExit == 5 ? "TENANT_HAS_ADMIN" : "CONCURRENT_INVOCATION";

    assertThat(countActive(tenantId, tenantAdmin.getId())).isEqualTo(1);
    assertThat(countActiveForUser(winner.getId())).isEqualTo(1);
    assertThat(countActiveForUser(loser.getId())).isZero();

    List<Map<String, Object>> tenantRows =
        jdbc.queryForList(
            "SELECT outcome, user_id, tenant_id, "
                + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.changeRef')) AS change_ref, "
                + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.reason')) AS reason "
                + "FROM auth_events WHERE event_type = ? AND (tenant_id = ? OR user_id IN (?, ?))",
            EVENT_TYPE,
            toBytes(tenantId),
            toBytes(first.getId()),
            toBytes(second.getId()));
    assertThat(tenantRows).hasSize(2);
    assertThat(tenantRows)
        .allSatisfy(r -> assertThat(toUuid((byte[]) r.get("tenant_id"))).isEqualTo(tenantId));
    assertThat(tenantRows)
        .extracting(
            r -> r.get("outcome") + "/" + toUuid((byte[]) r.get("user_id")) + "/" + r.get("reason"))
        .containsExactlyInAnyOrder(
            "SUCCESS/" + winner.getId() + "/null", "FAILURE/" + loser.getId() + "/" + loserReason);
    assertThat(tenantRows)
        .filteredOn(r -> "SUCCESS".equals(r.get("outcome")))
        .extracting(r -> r.get("change_ref"))
        .containsExactly(winnerRef);

    assertThat(alertEvents())
        .extracting(e -> keyValues(e).get("outcome") + "/" + keyValues(e).get("reason"))
        .containsExactlyInAnyOrder("GRANTED/null", "REFUSED/" + loserReason);
    assertThat(logs.list)
        .noneSatisfy(
            e -> assertThat(keyValues(e)).containsEntry("event", "RBAC_AUDIT_WRITE_FAILED"));
    assertThat(logs.list)
        .noneSatisfy(
            e -> assertThat(keyValues(e)).containsEntry("event", "RBAC_AUDIT_WRITE_LOST"));
  }

  // ── Helpers ───────────────────────────────────────────────────────────────────────────────

  private Future<Integer> submitCli(
      ExecutorService executor, CyclicBarrier barrier, UUID targetUserId, String changeRef) {
    return executor.submit(
        () -> {
          barrier.await(5, TimeUnit.SECONDS);
          return runCli(targetUserId.toString(), changeRef);
        });
  }

  /**
   * Runs a fresh runner over the shared context's service with no flush wait. The runner is built
   * directly, so its web-context guard (exercised by the separate-context tests) is not invoked.
   */
  private int runCli(String targetUserId, String changeRef) {
    BreakGlassAdminRunner runner =
        new BreakGlassAdminRunner(
            bootstrapAdminService, new GenericApplicationContext(), Duration.ZERO);
    runner.run(
        new DefaultApplicationArguments(
            "--target-user-id=" + targetUserId, "--change-ref=" + changeRef));
    return runner.getExitCode();
  }

  /**
   * Starts the real application with profiles {@code test,break-glass} against this class's
   * containers, as {@code java -jar} would (Flyway off: the schema already exists). Never calls
   * {@code NexusApplication.main}, which would {@code System.exit}. Test classes are excluded
   * from the component scan as in the packaged jar, and Spring Boot's logging system is left
   * alone so the shared context's logging (and this class's ROOT appender) is untouched.
   */
  private ConfigurableApplicationContext runBreakGlassApplication(
      AtomicBoolean webServerInitialized, String... extraArgs) {
    List<String> args =
        new ArrayList<>(
            List.of(
                "--spring.datasource.url=" + mysqlContainer.getJdbcUrl(),
                "--spring.datasource.username=" + mysqlContainer.getUsername(),
                "--spring.datasource.password=" + mysqlContainer.getPassword(),
                "--spring.data.redis.host=" + redisContainer.getHost(),
                "--spring.data.redis.port=" + redisContainer.getMappedPort(6379),
                "--spring.mail.host=127.0.0.1",
                "--nexus.mail.from-address=test@nexus.test",
                "--nexus.frontend.base-url=http://localhost:2000",
                "--nexus.rbac.break-glass.log-flush-wait=0s"));
    args.addAll(List.of(extraArgs));
    String previous = System.getProperty(LoggingSystem.SYSTEM_PROPERTY);
    System.setProperty(LoggingSystem.SYSTEM_PROPERTY, LoggingSystem.NONE);
    try {
      return new SpringApplicationBuilder(NexusApplication.class)
          .profiles("test", "break-glass")
          .initializers(
              context ->
                  context
                      .getBeanFactory()
                      .registerSingleton("excludeTestClasses", new ExcludeTestClasses()))
          .listeners(
              event -> {
                if (event instanceof WebServerInitializedEvent) {
                  webServerInitialized.set(true);
                }
              })
          .run(args.toArray(String[]::new));
    } finally {
      if (previous == null) {
        System.clearProperty(LoggingSystem.SYSTEM_PROPERTY);
      } else {
        System.setProperty(LoggingSystem.SYSTEM_PROPERTY, previous);
      }
    }
  }

  /** Excludes every class compiled from the test sources, as in the packaged jar. */
  public static final class ExcludeTestClasses extends TypeExcludeFilter {

    @Override
    public boolean match(MetadataReader metadataReader, MetadataReaderFactory factory)
        throws IOException {
      return metadataReader.getResource().getURI().toString().contains("/test-classes/");
    }

    @Override
    public boolean equals(Object other) {
      return other instanceof ExcludeTestClasses;
    }

    @Override
    public int hashCode() {
      return ExcludeTestClasses.class.hashCode();
    }
  }

  private static String freshChangeRef() {
    return "BGIT-" + ThreadLocalRandom.current().nextInt(1, 100_000_000);
  }

  /**
   * A random RC-47 ticket prefix ({@code Z} plus 9 letters), so the padded-replay pair differs per
   * run and a reused container never already holds it.
   */
  private static String randomTicketPrefix() {
    StringBuilder prefix = new StringBuilder("Z");
    for (int i = 0; i < 9; i++) {
      prefix.append((char) ('A' + ThreadLocalRandom.current().nextInt(26)));
    }
    return prefix.toString();
  }

  private Set<String> authEventIds() {
    return new HashSet<>(jdbc.queryForList("SELECT HEX(id) FROM auth_events", String.class));
  }

  /** Every rendered part of a log event: message, arguments, key-values, throwable chain. */
  private static String renderEverything(ILoggingEvent event) {
    StringBuilder all = new StringBuilder(String.valueOf(event.getFormattedMessage()));
    all.append('|').append(event.getMessage());
    if (event.getArgumentArray() != null) {
      for (Object argument : event.getArgumentArray()) {
        all.append('|').append(argument);
      }
    }
    if (event.getKeyValuePairs() != null) {
      event.getKeyValuePairs().forEach(kv -> all.append('|').append(kv.key).append('=').append(kv.value));
    }
    for (var proxy = event.getThrowableProxy(); proxy != null; proxy = proxy.getCause()) {
      all.append('|').append(proxy.getClassName()).append(':').append(proxy.getMessage());
    }
    all.append('|').append(Objects.toString(event.getMDCPropertyMap()));
    return all.toString();
  }

  private void assertRefused(
      BreakGlassOutcome outcome,
      BreakGlassRefusalReason reason,
      int exitCode,
      UUID targetUserId,
      UUID tenantId) {
    assertThat(outcome).isEqualTo(new BreakGlassOutcome.Refused(reason));
    assertThat(outcome.exitCode()).isEqualTo(exitCode);

    List<Map<String, Object>> rows = auditRows(targetUserId);
    assertThat(rows).hasSize(1);
    Map<String, Object> row = rows.get(0);
    assertThat(row)
        .containsEntry("outcome", "FAILURE")
        .containsEntry("actor_type", "BREAK_GLASS_CLI")
        .containsEntry("reason", reason.name());
    assertThat(row.get("tenant_id") == null ? null : toUuid((byte[]) row.get("tenant_id")))
        .isEqualTo(tenantId);

    Map<String, Object> alert = singleAlert();
    assertThat(alert)
        .containsEntry("event", "RBAC_BREAK_GLASS_USED")
        .containsEntry("outcome", "REFUSED")
        .containsEntry("reason", reason.name())
        .containsEntry("targetUserId", targetUserId);
    if (tenantId == null) {
      assertThat(alert).doesNotContainKey("tenantId");
    } else {
      assertThat(alert).containsEntry("tenantId", tenantId);
    }
  }

  private List<Map<String, Object>> auditRows(UUID targetUserId) {
    return jdbc.queryForList(
        "SELECT outcome, tenant_id, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.actorType')) AS actor_type, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.changeRef')) AS change_ref, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.reason')) AS reason "
            + "FROM auth_events WHERE user_id = ? AND event_type = ? ORDER BY created_at, id",
        toBytes(targetUserId),
        EVENT_TYPE);
  }

  private List<ILoggingEvent> alertEvents() {
    return logs.list.stream()
        .filter(e -> BreakGlassAlertAdapter.class.getName().equals(e.getLoggerName()))
        .filter(e -> keyValues(e).containsKey("event"))
        .filter(e -> "RBAC_BREAK_GLASS_USED".equals(keyValues(e).get("event")))
        .toList();
  }

  private Map<String, Object> singleAlert() {
    List<ILoggingEvent> events = alertEvents();
    assertThat(events).hasSize(1);
    return keyValues(events.get(0));
  }

  private static Map<String, Object> keyValues(ILoggingEvent event) {
    Map<String, Object> map = new HashMap<>();
    if (event.getKeyValuePairs() != null) {
      event.getKeyValuePairs().forEach(kv -> map.put(kv.key, kv.value));
    }
    return map;
  }

  private static Logger rootLogger() {
    return (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
  }

  private User seedActiveUser(UUID tenantId, String tag) {
    String email = "bg-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    user.verify(Instant.now());
    return userRepository.save(user);
  }

  /** A system {@code TENANT_ADMIN} carrying the whole permission catalogue, as a seeded one does. */
  private Role seedSystemTenantAdminRole(UUID tenantId) {
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, "TENANT_ADMIN", "BreakGlassAdminIT", true));
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions",
        role.getId().toString());
    return role;
  }

  private UserRole seedAssignment(UUID tenantId, UUID roleId, UUID userId) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), userId, roleId, tenantId, userId));
  }

  private int countActive(UUID tenantId, UUID roleId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE role_id = ? AND tenant_id = ?"
                + " AND revoked_at IS NULL",
            Integer.class,
            toBytes(roleId),
            toBytes(tenantId));
    return count == null ? 0 : count;
  }

  private int countActiveForUser(UUID userId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND revoked_at IS NULL",
            Integer.class,
            toBytes(userId));
    return count == null ? 0 : count;
  }

  private boolean isActive(UUID userRoleId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE id = ? AND revoked_at IS NULL",
            Integer.class,
            toBytes(userRoleId));
    return count != null && count == 1;
  }

  private static RequestContext requestContext() {
    return RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "BreakGlassAdminIT");
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }

  private static UUID toUuid(byte[] bytes) {
    ByteBuffer buf = ByteBuffer.wrap(bytes);
    return new UUID(buf.getLong(), buf.getLong());
  }
}
