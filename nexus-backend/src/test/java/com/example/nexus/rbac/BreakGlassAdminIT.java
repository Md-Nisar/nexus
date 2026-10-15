package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
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
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

/**
 * US-018 T-007 TS-6 (03-design.md §7.1, §7.3): the break-glass first-administrator grant against
 * real MySQL. Calls the {@link BootstrapAdminService} bean directly (the CLI runner is T-008), so
 * the real {@code RbacAuthEventAdapter}, {@code BreakGlassAlertAdapter} and M10/M11 adapters run
 * end to end. The page is captured from {@link BreakGlassAlertAdapter}'s logger.
 *
 * <p>Every test seeds its own fresh tenant; nothing touches the bootstrap tenant.
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

  private ListAppender<ILoggingEvent> alerts;

  @BeforeEach
  void captureAlerts() {
    alerts = new ListAppender<>();
    alerts.start();
    alertLogger().addAppender(alerts);
  }

  @AfterEach
  void stopCapture() {
    alertLogger().detachAppender(alerts);
    alerts.stop();
    jdbc.execute("DROP TRIGGER IF EXISTS trg_ts6_block_break_glass_success");
  }

  // ── Grant ─────────────────────────────────────────────────────────────────────────────────

  @Test
  void should_grantTenantAdmin_writeSuccessRow_andLogAlert_when_tenantHasZeroAdmins() {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User target = seedActiveUser(tenantId, "grant");

    BreakGlassOutcome outcome =
        bootstrapAdminService.grantFirstAdmin(target.getId(), new ChangeRef("OPS-100"));

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
        .containsEntry("change_ref", "OPS-100");
    assertThat(rows.get(0).get("reason")).isNull();
    assertThat(toUuid((byte[]) rows.get(0).get("tenant_id"))).isEqualTo(tenantId);

    assertThat(singleAlert())
        .containsEntry("event", "RBAC_BREAK_GLASS_USED")
        .containsEntry("outcome", "GRANTED")
        .containsEntry("tenantId", tenantId)
        .containsEntry("targetUserId", target.getId())
        .containsEntry("changeRef", "OPS-100");
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
        bootstrapAdminService.grantFirstAdmin(target.getId(), new ChangeRef("OPS-101"));

    assertRefused(outcome, BreakGlassRefusalReason.TENANT_HAS_ADMIN, 5, target.getId(), tenantId);
    assertThat(countActive(tenantId, tenantAdmin.getId())).isEqualTo(1);
    assertThat(countActiveForUser(target.getId())).isZero();
  }

  @Test
  void should_refuseWithExit4_when_tenantHasNoSeededTenantAdminRole() {
    UUID tenantId = uuidGenerator.newId();
    User target = seedActiveUser(tenantId, "no-role");

    BreakGlassOutcome outcome =
        bootstrapAdminService.grantFirstAdmin(target.getId(), new ChangeRef("OPS-102"));

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
        bootstrapAdminService.grantFirstAdmin(target.getId(), new ChangeRef("OPS-103"));

    assertRefused(
        outcome, BreakGlassRefusalReason.TARGET_USER_NOT_ACTIVE, 3, target.getId(), tenantId);
    assertThat(countActiveForUser(target.getId())).isZero();
  }

  @Test
  void should_refuseWithExit3_withNullTenant_when_targetUserDoesNotExist() {
    UUID unknownUserId = uuidGenerator.newId();

    BreakGlassOutcome outcome =
        bootstrapAdminService.grantFirstAdmin(unknownUserId, new ChangeRef("OPS-104"));

    assertRefused(outcome, BreakGlassRefusalReason.TARGET_USER_NOT_FOUND, 3, unknownUserId, null);
  }

  @Test
  void should_refuseWithExit5_when_reRunAfterSuccessfulGrant() {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User target = seedActiveUser(tenantId, "rerun");
    assertThat(
            bootstrapAdminService.grantFirstAdmin(target.getId(), new ChangeRef("OPS-105")).exitCode())
        .isZero();

    BreakGlassOutcome rerun =
        bootstrapAdminService.grantFirstAdmin(target.getId(), new ChangeRef("OPS-106"));

    assertThat(rerun).isEqualTo(new BreakGlassOutcome.Refused(BreakGlassRefusalReason.TENANT_HAS_ADMIN));
    assertThat(rerun.exitCode()).isEqualTo(5);
    assertThat(countActive(tenantId, tenantAdmin.getId())).isEqualTo(1);
    assertThat(auditRows(target.getId()))
        .extracting(r -> r.get("outcome") + "/" + r.get("change_ref"))
        .containsExactly("SUCCESS/OPS-105", "FAILURE/OPS-106");
  }

  // ── Atomicity (TS-5 style) ────────────────────────────────────────────────────────────────

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

    assertThatThrownBy(
            () -> bootstrapAdminService.grantFirstAdmin(target.getId(), new ChangeRef("OPS-107")))
        .isInstanceOf(RuntimeException.class);

    assertThat(countActive(tenantId, tenantAdmin.getId())).isZero();
    assertThat(auditRows(target.getId())).isEmpty();
    assertThat(alertEvents()).isEmpty();
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
                            .grantFirstAdmin(target.getId(), new ChangeRef("OPS-108"))
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
   * Two CLI runs race on one zero-admin tenant for two different users. Exactly one grant goes
   * through. The loser either sees one administrator (exit 5) or, because the set lock finds no
   * rows and takes only gap locks, dies with a deadlock on the {@code user_roles} insert, which
   * T-008's runner maps to an audited, paged {@code CONCURRENT_RUN} refusal written after the
   * rollback. When T-008 re-enables this test it must accept the exit-code set {0, 5} or {0,
   * <the CONCURRENT_RUN exit code>}, assert exactly one active administrator row, and drive the
   * runs through the runner rather than this service (see 04-tasks.md T-008 risks).
   */
  @Disabled(
      "Known deadlock (MySQL 1213 on the user_roles insert) when two runs race on one zero-admin"
          + " tenant: the set lock finds no rows and takes only gap locks. Decision 2026-10-15:"
          + " T-008's runner maps any RuntimeException from grantFirstAdmin to an audited, paged"
          + " refusal written after the rollback (CONCURRENT_RUN for a lock failure). Re-enable"
          + " then, through the runner, accepting exit codes {0,5} or {0,<CONCURRENT_RUN code>}"
          + " plus exactly one active administrator row.")
  @Test
  void should_grantExactlyOnce_when_twoCliRunsRaceOnTheSameZeroAdminTenant() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role tenantAdmin = seedSystemTenantAdminRole(tenantId);
    User first = seedActiveUser(tenantId, "race-1");
    User second = seedActiveUser(tenantId, "race-2");

    ExecutorService executor = Executors.newFixedThreadPool(2);
    CyclicBarrier barrier = new CyclicBarrier(2);
    List<Integer> exitCodes = new ArrayList<>();
    try {
      Future<Integer> a = submitCli(executor, barrier, first.getId(), "OPS-109");
      Future<Integer> b = submitCli(executor, barrier, second.getId(), "OPS-110");
      exitCodes.add(a.get(30, TimeUnit.SECONDS));
      exitCodes.add(b.get(30, TimeUnit.SECONDS));
    } finally {
      executor.shutdownNow();
    }

    assertThat(exitCodes).containsExactlyInAnyOrder(0, 5);
    assertThat(countActive(tenantId, tenantAdmin.getId())).isEqualTo(1);
  }

  // ── Helpers ───────────────────────────────────────────────────────────────────────────────

  private Future<Integer> submitCli(
      ExecutorService executor, CyclicBarrier barrier, UUID targetUserId, String changeRef) {
    return executor.submit(
        () -> {
          barrier.await(5, TimeUnit.SECONDS);
          return bootstrapAdminService
              .grantFirstAdmin(targetUserId, new ChangeRef(changeRef))
              .exitCode();
        });
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
    return alerts.list.stream()
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

  private static Logger alertLogger() {
    return (Logger) LoggerFactory.getLogger(BreakGlassAlertAdapter.class);
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
