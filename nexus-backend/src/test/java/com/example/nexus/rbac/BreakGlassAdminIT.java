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
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
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
import org.junit.jupiter.api.io.TempDir;
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
    jdbc.execute("DROP TRIGGER IF EXISTS trg_qa_block_break_glass_failure");
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

  // ── Phase 8 QA audit additions (08-test-audit-M5.md) ─────────────────────────────────────

  /**
   * The replay lookup counts SUCCESS rows only. A FAILURE row also carries the {@code changeRef}
   * (exit 3 here), and must not burn the approval: the operator fixes the target and re-runs the
   * same, still unused, reference.
   */
  @Test
  void should_grantWithTheSameChangeRef_when_theEarlierAttemptLeftOnlyAFailureRow() {
    UUID tenantId = uuidGenerator.newId();
    seedSystemTenantAdminRole(tenantId);
    User target = seedActiveUser(tenantId, "retry-same-ref");
    setUserStatus(target.getId(), "DISABLED");
    String changeRef = freshChangeRef();
    assertThat(runCli(target.getId().toString(), changeRef)).isEqualTo(3);
    setUserStatus(target.getId(), "ACTIVE");

    int exitCode = runCli(target.getId().toString(), changeRef);

    assertThat(exitCode).isZero();
    assertThat(auditRows(target.getId()))
        .extracting(r -> r.get("outcome") + "/" + r.get("reason"))
        .containsExactly("FAILURE/TARGET_USER_NOT_ACTIVE", "SUCCESS/null");
  }

  /**
   * RC-47: the lookup is an exact match. A used {@code XX-12} is not {@code XX-1} (prefix) nor
   * {@code XX-123} (superstring); only the identical string is refused.
   */
  @Test
  void should_grantOtherReferences_andRefuseOnlyTheIdenticalOne_when_similarReferenceWasUsed() {
    String prefix = randomTicketPrefix();
    UUID[] tenants = {uuidGenerator.newId(), uuidGenerator.newId(), uuidGenerator.newId()};
    User[] targets = new User[3];
    for (int i = 0; i < 3; i++) {
      seedSystemTenantAdminRole(tenants[i]);
      targets[i] = seedActiveUser(tenants[i], "similar-" + i);
    }
    UUID fourthTenant = uuidGenerator.newId();
    seedSystemTenantAdminRole(fourthTenant);
    User fourth = seedActiveUser(fourthTenant, "similar-identical");

    int used = runCli(targets[0].getId().toString(), prefix + "-12");
    int prefixOfUsed = runCli(targets[1].getId().toString(), prefix + "-1");
    int supersetOfUsed = runCli(targets[2].getId().toString(), prefix + "-123");
    int identical = runCli(fourth.getId().toString(), prefix + "-12");

    assertThat(List.of(used, prefixOfUsed, supersetOfUsed, identical)).containsExactly(0, 0, 0, 6);
  }

  /** The zero-admin check is per tenant: another tenant's administrator never blocks the grant. */
  @Test
  void should_grantInTenantB_when_onlyTenantAHasAnAdministrator() {
    UUID tenantA = uuidGenerator.newId();
    Role adminRoleA = seedSystemTenantAdminRole(tenantA);
    User adminA = seedActiveUser(tenantA, "tenant-a-admin");
    seedAssignment(tenantA, adminRoleA.getId(), adminA.getId());
    UUID tenantB = uuidGenerator.newId();
    Role adminRoleB = seedSystemTenantAdminRole(tenantB);
    User targetB = seedActiveUser(tenantB, "tenant-b-target");

    int exitCode = runCli(targetB.getId().toString(), freshChangeRef());

    assertThat(exitCode).isZero();
    assertThat(countActive(tenantB, adminRoleB.getId())).isEqualTo(1);
    assertThat(countActive(tenantA, adminRoleA.getId())).isEqualTo(1);
  }

  /**
   * ADR-0021 against real data: a holder of a custom role carrying the whole permission catalogue
   * IS an administrator (admin-defining role), so break-glass refuses (exit 5).
   */
  @Test
  void should_refuseWithExit5_when_aCustomRoleCarryingTheWholeCatalogueIsHeld() {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    Role custom = seedCustomRole(tenantId, "qa-full-admin");
    grantWholeCatalogue(custom);
    User holder = seedActiveUser(tenantId, "custom-admin");
    seedAssignment(tenantId, custom.getId(), holder.getId());
    User target = seedActiveUser(tenantId, "custom-admin-target");

    int exitCode = runCli(target.getId().toString(), freshChangeRef());

    assertThat(exitCode).isEqualTo(5);
    assertThat(countActive(tenantId, tenantAdmin.getId())).isZero();
  }

  /**
   * The converse: a custom role that lost admin-defining status (one catalogue permission short,
   * as after a detach) no longer makes its holder an administrator; the grant goes.
   */
  @Test
  void should_grant_when_theOnlyHeldCustomRoleLostAdminDefiningStatus() {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    Role custom = seedCustomRole(tenantId, "qa-partial-admin");
    grantWholeCatalogue(custom);
    jdbc.update(
        "DELETE FROM role_permissions WHERE role_id = ? LIMIT 1", toBytes(custom.getId()));
    User holder = seedActiveUser(tenantId, "partial-admin");
    seedAssignment(tenantId, custom.getId(), holder.getId());
    User target = seedActiveUser(tenantId, "partial-admin-target");

    int exitCode = runCli(target.getId().toString(), freshChangeRef());

    assertThat(exitCode).isZero();
    assertThat(countActive(tenantId, tenantAdmin.getId())).isEqualTo(1);
  }

  /** The three legacy dangerous permissions alone no longer make a role administrator-defining. */
  @Test
  void should_grant_when_theOnlyHeldCustomRoleCarriesTheThreeFormerDangerousPermissions() {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    Role custom =
        seedCustomRole(tenantId, "qa-three", "role:write", "user:write", "tenant:write");
    User holder = seedActiveUser(tenantId, "three-holder");
    seedAssignment(tenantId, custom.getId(), holder.getId());
    User target = seedActiveUser(tenantId, "three-holder-target");

    int exitCode = runCli(target.getId().toString(), freshChangeRef());

    assertThat(exitCode).isZero();
    assertThat(countActive(tenantId, tenantAdmin.getId())).isEqualTo(1);
  }

  /** A tenant-created role named {@code TENANT_ADMIN} is not the system role: exit 4, no grant. */
  @Test
  void should_refuseWithExit4_when_theTenantAdminRoleIsNotASystemRole() {
    UUID tenantId = uuidGenerator.newId();
    Role lookalike = seedCustomRole(tenantId, "TENANT_ADMIN");
    User target = seedActiveUser(tenantId, "lookalike-target");

    int exitCode = runCli(target.getId().toString(), freshChangeRef());

    assertThat(exitCode).isEqualTo(4);
    assertThat(countActive(tenantId, lookalike.getId())).isZero();
  }

  /**
   * O-7 decision (2026-10-15): a temporarily LOCKED sole administrator still counts as an
   * administrator for break-glass; a lockout recovers by itself.
   */
  @Test
  void should_refuseWithExit5_when_theSoleAdministratorIsLocked() {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User admin = seedActiveUser(tenantId, "locked-admin");
    seedAssignment(tenantId, tenantAdmin.getId(), admin.getId());
    setUserStatus(admin.getId(), "LOCKED");
    User target = seedActiveUser(tenantId, "locked-admin-target");

    int exitCode = runCli(target.getId().toString(), freshChangeRef());

    assertThat(exitCode).isEqualTo(5);
  }

  /**
   * O-7 decision (2026-10-15; security review M-1): for break-glass only, a holder whose user is
   * DISABLED is not an administrator. A tenant whose sole administrator is DISABLED is recoverable:
   * the target gets TENANT_ADMIN, one SUCCESS row is written and the grant is paged. The DISABLED
   * holder's assignment is left as it is.
   */
  @Test
  void should_grantExit0_writeSuccessRow_andPage_when_theSoleAdministratorIsDisabled() {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User admin = seedActiveUser(tenantId, "disabled-admin");
    UserRole disabledAdminRow = seedAssignment(tenantId, tenantAdmin.getId(), admin.getId());
    setUserStatus(admin.getId(), "DISABLED");
    User target = seedActiveUser(tenantId, "disabled-admin-target");
    String changeRef = freshChangeRef();

    int exitCode = runCli(target.getId().toString(), changeRef);

    assertThat(exitCode).isZero();
    assertThat(countActive(tenantId, tenantAdmin.getId())).isEqualTo(2);
    assertThat(countActiveForUser(target.getId())).isEqualTo(1);
    assertThat(isActive(disabledAdminRow.getId())).isTrue();
    List<Map<String, Object>> rows = auditRows(target.getId());
    assertThat(rows)
        .extracting(r -> r.get("outcome") + "/" + r.get("change_ref") + "/" + r.get("reason"))
        .containsExactly("SUCCESS/" + changeRef + "/null");
    assertThat(toUuid((byte[]) rows.get(0).get("tenant_id"))).isEqualTo(tenantId);
    assertThat(singleAlert())
        .containsEntry("event", "RBAC_BREAK_GLASS_USED")
        .containsEntry("outcome", "GRANTED")
        .containsEntry("tenantId", tenantId)
        .containsEntry("targetUserId", target.getId())
        .containsEntry("changeRef", changeRef);
  }

  /** O-7: one DISABLED administrator does not hide an ACTIVE one; break-glass refuses (exit 5). */
  @Test
  void should_refuseWithExit5_andGrantNothing_when_oneAdministratorIsDisabledAndAnotherIsActive() {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User disabledAdmin = seedActiveUser(tenantId, "mixed-disabled-admin");
    seedAssignment(tenantId, tenantAdmin.getId(), disabledAdmin.getId());
    setUserStatus(disabledAdmin.getId(), "DISABLED");
    User activeAdmin = seedActiveUser(tenantId, "mixed-active-admin");
    seedAssignment(tenantId, tenantAdmin.getId(), activeAdmin.getId());
    User target = seedActiveUser(tenantId, "mixed-target");

    BreakGlassOutcome outcome =
        bootstrapAdminService.grantFirstAdmin(target.getId(), new ChangeRef(freshChangeRef()));

    assertRefused(outcome, BreakGlassRefusalReason.TENANT_HAS_ADMIN, 5, target.getId(), tenantId);
    assertThat(countActive(tenantId, tenantAdmin.getId())).isEqualTo(2);
    assertThat(countActiveForUser(target.getId())).isZero();
  }

  /**
   * O-7, no stale read: the DISABLED sole administrator is re-enabled by a transaction that is
   * still open when the CLI reaches the status read. The CLI's locking read waits for it and sees
   * the committed ACTIVE status, so it refuses (exit 5). A plain snapshot read would have seen
   * DISABLED and granted.
   */
  @Test
  void should_refuseWithExit5_when_theDisabledSoleAdministratorIsReEnabledConcurrently()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User admin = seedActiveUser(tenantId, "re-enabled-admin");
    seedAssignment(tenantId, tenantAdmin.getId(), admin.getId());
    setUserStatus(admin.getId(), "DISABLED");
    User target = seedActiveUser(tenantId, "re-enabled-target");

    int exitCode = runCliWhileAnotherTransactionSetsStatus(admin.getId(), "ACTIVE", target.getId());

    assertThat(exitCode).isEqualTo(5);
    assertThat(countActive(tenantId, tenantAdmin.getId())).isEqualTo(1);
    assertThat(countActiveForUser(target.getId())).isZero();
    assertThat(auditRows(target.getId()))
        .extracting(r -> r.get("outcome") + "/" + r.get("reason"))
        .containsExactly("FAILURE/TENANT_HAS_ADMIN");
  }

  /**
   * L-2: the target is ACTIVE when the CLI resolves it, then DISABLED by a transaction that is
   * still open when the CLI reaches the status read inside the grant transaction. The CLI waits
   * for it, sees DISABLED and refuses (exit 3, audited with the tenant); nothing is granted.
   */
  @Test
  void should_refuseWithExit3_andGrantNothing_when_theTargetIsDisabledConcurrently()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User target = seedActiveUser(tenantId, "disabled-concurrently");

    int exitCode =
        runCliWhileAnotherTransactionSetsStatus(target.getId(), "DISABLED", target.getId());

    assertThat(exitCode).isEqualTo(3);
    assertThat(countActive(tenantId, tenantAdmin.getId())).isZero();
    List<Map<String, Object>> rows = auditRows(target.getId());
    assertThat(rows)
        .extracting(r -> r.get("outcome") + "/" + r.get("reason"))
        .containsExactly("FAILURE/TARGET_USER_NOT_ACTIVE");
    assertThat(toUuid((byte[]) rows.get(0).get("tenant_id"))).isEqualTo(tenantId);
  }

  /**
   * A refusal whose FAILURE row cannot be written is lost with a signal, never thrown, and never
   * hides the page or the exit code (design §7.2; RBAC_AUDIT_WRITE_LOST). Real MySQL, via a
   * test-only trigger that rejects FAILURE break-glass rows.
   */
  @Test
  void should_keepExitCodeAndPage_andLogWriteLost_when_theRefusalRowCannotBeWritten() {
    UUID unknownUserId = uuidGenerator.newId();
    jdbc.execute(
        "CREATE TRIGGER trg_qa_block_break_glass_failure BEFORE INSERT ON auth_events FOR EACH ROW"
            + " BEGIN IF NEW.event_type = 'ROLE_BREAK_GLASS_GRANT' AND NEW.outcome = 'FAILURE'"
            + " THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'QA test-only block'; END IF;"
            + " END");

    int exitCode = runCli(unknownUserId.toString(), freshChangeRef());

    assertThat(exitCode).isEqualTo(3);
    assertThat(auditRows(unknownUserId)).isEmpty();
    assertThat(singleAlert())
        .containsEntry("outcome", "REFUSED")
        .containsEntry("reason", "TARGET_USER_NOT_FOUND");
    assertThat(logs.list)
        .anySatisfy(
            e -> assertThat(keyValues(e)).containsEntry("event", "RBAC_AUDIT_WRITE_LOST"));
  }

  // ── Process boundary: NexusApplication.main, as nexus_app ────────────────────────────────

  /**
   * The whole chain in a real JVM, as {@code java -jar} runs it, connecting as the least-privilege
   * runtime user {@code nexus_app} (every other IT connects as the container user, which would
   * hide a missing grant): profile config, Flyway off, runner, M10/M11 locking reads, grant,
   * SUCCESS row, and {@code main}'s {@code System.exit(SpringApplication.exit(...))}. Takes
   * seconds (a full application boot), which is the point of the test.
   */
  @Test
  void should_exitProcessWith0_andGrant_when_mainRunsBreakGlassAsNexusApp(@TempDir Path tmp)
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User target = seedActiveUser(tenantId, "main-exit0");
    String changeRef = freshChangeRef();
    Path output = tmp.resolve("child.log");

    int exitCode =
        runMainInChildJvm(
            output,
            "nexus_app",
            "nexus_app_test_only",
            "--target-user-id=" + target.getId(),
            "--change-ref=" + changeRef);

    assertThat(exitCode).as("child JVM output tail:%n%s", tail(output)).isZero();
    assertThat(countActive(tenantId, tenantAdmin.getId())).isEqualTo(1);
    assertThat(auditRows(target.getId()))
        .extracting(r -> r.get("outcome") + "/" + r.get("change_ref"))
        .containsExactly("SUCCESS/" + changeRef);
  }

  /** A refusal's exit code survives {@code main} and the JVM: a replayed reference is exit 6. */
  @Test
  void should_exitProcessWithTheRefusalCode_when_mainRunsAReplayedChangeRef(@TempDir Path tmp)
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    seedSystemTenantAdminRole(tenantId);
    User target = seedActiveUser(tenantId, "main-exit6");
    String changeRef = freshChangeRef();
    assertThat(runCli(target.getId().toString(), changeRef)).isZero();
    Path output = tmp.resolve("child.log");

    int exitCode =
        runMainInChildJvm(
            output,
            "nexus_app",
            "nexus_app_test_only",
            "--target-user-id=" + target.getId(),
            "--change-ref=" + changeRef);

    assertThat(exitCode).as("child JVM output tail:%n%s", tail(output)).isEqualTo(6);
  }

  /**
   * RC-37.6 end to end: the profile forced onto a servlet context kills the process (exit 1) and
   * leaves no grant behind.
   */
  @Test
  void should_exitProcessWith1_andGrantNothing_when_mainRunsBreakGlassWithServletWebType(
      @TempDir Path tmp) throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User target = seedActiveUser(tenantId, "main-servlet");
    Path output = tmp.resolve("child.log");

    int exitCode =
        runMainInChildJvm(
            output,
            "nexus_app",
            "nexus_app_test_only",
            "--spring.main.web-application-type=servlet",
            "--server.port=0",
            "--target-user-id=" + target.getId(),
            "--change-ref=" + freshChangeRef());

    assertThat(exitCode).as("child JVM output tail:%n%s", tail(output)).isEqualTo(1);
    assertThat(Files.readString(output)).contains("refusing to start");
    assertThat(countActive(tenantId, tenantAdmin.getId())).isZero();
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

  /**
   * Sets {@code userId}'s status in a transaction on its own connection and keeps it open, runs
   * the CLI for {@code targetUserId} on another thread, waits until the CLI is blocked on a lock
   * held by that transaction, then commits it and returns the CLI's exit code. The lock wait is
   * observed in {@code performance_schema} (as root), so the test never relies on a sleep.
   */
  private int runCliWhileAnotherTransactionSetsStatus(
      UUID userId, String status, UUID targetUserId) throws Exception {
    ExecutorService executor = Executors.newSingleThreadExecutor();
    try (Connection writer =
            DriverManager.getConnection(
                mysqlContainer.getJdbcUrl(),
                mysqlContainer.getUsername(),
                mysqlContainer.getPassword());
        Connection monitor =
            DriverManager.getConnection(
                mysqlContainer.getJdbcUrl(), "root", mysqlContainer.getPassword())) {
      writer.setAutoCommit(false);
      try (PreparedStatement update =
          writer.prepareStatement("UPDATE users SET status = ? WHERE id = ?")) {
        update.setString(1, status);
        update.setBytes(2, toBytes(userId));
        assertThat(update.executeUpdate()).isEqualTo(1);
      }
      long writerConnectionId;
      try (Statement statement = writer.createStatement();
          ResultSet rs = statement.executeQuery("SELECT CONNECTION_ID()")) {
        rs.next();
        writerConnectionId = rs.getLong(1);
      }

      Future<Integer> cli =
          executor.submit(() -> runCli(targetUserId.toString(), freshChangeRef()));
      awaitLockWaitBlockedBy(monitor, writerConnectionId, cli);
      writer.commit();
      return cli.get(30, TimeUnit.SECONDS);
    } finally {
      executor.shutdownNow();
    }
  }

  private static void awaitLockWaitBlockedBy(
      Connection monitor, long blockingConnectionId, Future<Integer> cli) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
    try (PreparedStatement waits =
        monitor.prepareStatement(
            "SELECT COUNT(*) FROM performance_schema.data_lock_waits w"
                + " JOIN performance_schema.threads t ON w.BLOCKING_THREAD_ID = t.THREAD_ID"
                + " WHERE t.PROCESSLIST_ID = ?")) {
      waits.setLong(1, blockingConnectionId);
      while (System.nanoTime() < deadline) {
        assertThat(cli.isDone())
            .as("the CLI finished without waiting for the open status change")
            .isFalse();
        try (ResultSet rs = waits.executeQuery()) {
          rs.next();
          if (rs.getInt(1) > 0) {
            return;
          }
        }
        Thread.sleep(25);
      }
    }
    throw new AssertionError("the CLI never waited on the open status change");
  }

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
        new ArrayList<>(containerArgs(mysqlContainer.getUsername(), mysqlContainer.getPassword()));
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

  /** The datasource, Redis and mandatory-property arguments that let the app boot on the containers. */
  private List<String> containerArgs(String dbUser, String dbPassword) {
    return List.of(
        "--spring.datasource.url=" + mysqlContainer.getJdbcUrl(),
        "--spring.datasource.username=" + dbUser,
        "--spring.datasource.password=" + dbPassword,
        "--spring.data.redis.host=" + redisContainer.getHost(),
        "--spring.data.redis.port=" + redisContainer.getMappedPort(6379),
        "--spring.mail.host=127.0.0.1",
        "--nexus.mail.from-address=test@nexus.test",
        "--nexus.frontend.base-url=http://localhost:2000",
        "--nexus.rbac.break-glass.log-flush-wait=0s");
  }

  /**
   * Boots {@code NexusApplication.main} in a separate JVM exactly as {@code java -jar} would
   * (profiles {@code test,break-glass}, test classes off the classpath) and returns the PROCESS
   * exit code, so {@code main}'s {@code System.exit(SpringApplication.exit(context))} is exercised
   * for real. Output goes to a file kept for the failure message.
   */
  private int runMainInChildJvm(Path logFile, String dbUser, String dbPassword, String... extraArgs)
      throws Exception {
    String classpath =
        String.join(
            File.pathSeparator,
            List.of(System.getProperty("java.class.path").split(File.pathSeparator)).stream()
                .filter(entry -> !entry.replace('\\', '/').endsWith("/test-classes"))
                .toList());
    List<String> command = new ArrayList<>();
    command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
    command.add("-cp");
    command.add(classpath);
    command.add(NexusApplication.class.getName());
    command.add("--spring.profiles.active=test,break-glass");
    command.addAll(containerArgs(dbUser, dbPassword));
    command.addAll(List.of(extraArgs));
    Process process =
        new ProcessBuilder(command)
            .redirectErrorStream(true)
            .redirectOutput(logFile.toFile())
            .start();
    if (!process.waitFor(180, TimeUnit.SECONDS)) {
      process.destroyForcibly();
      throw new AssertionError("child JVM did not exit within 180 s:\n" + tail(logFile));
    }
    return process.exitValue();
  }

  private static String tail(Path logFile) throws IOException {
    List<String> lines = Files.readAllLines(logFile);
    return String.join("\n", lines.subList(Math.max(0, lines.size() - 40), lines.size()));
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

  /** A tenant-scoped, non-system custom role carrying exactly the named permissions. */
  private Role seedCustomRole(UUID tenantId, String name, String... permissionNames) {
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, name, "BreakGlassAdminIT", false));
    for (String permissionName : permissionNames) {
      jdbc.update(
          "INSERT INTO role_permissions (role_id, permission_id) "
              + "SELECT UUID_TO_BIN(?), id FROM permissions WHERE name = ?",
          role.getId().toString(),
          permissionName);
    }
    return role;
  }

  private void grantWholeCatalogue(Role role) {
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions",
        role.getId().toString());
  }

  private void setUserStatus(UUID userId, String status) {
    jdbc.update("UPDATE users SET status = ? WHERE id = ?", status, toBytes(userId));
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
