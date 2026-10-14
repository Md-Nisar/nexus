package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ch.qos.logback.classic.Level;
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
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.domain.LastAdminRoleException;
import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

/**
 * US-018 A7 (T-007, test scenario TS-6): the break-glass first-administrator grant against a real
 * MySQL. Drives {@link BootstrapAdminService} directly (the runner is T-008's half of this class).
 *
 * <p>Every test uses a freshly generated tenant, so no test depends on the migration-seeded
 * bootstrap tenant or leaves state another test can see. The system {@code TENANT_ADMIN} fixture
 * carries the whole permission catalogue, as a real one does, so the ADR-0018 caller-qualifying
 * population (A-6) recognises its holders as administrators.
 */
@SpringBootTest(
    properties = {
      "nexus.rbac.denial-throttle.max-denials=100",
      "spring.datasource.hikari.maximum-pool-size=15"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class BreakGlassAdminIT {

  private static final String CHANGE_REF = "OPS-4711";

  @Autowired private BootstrapAdminService bootstrapAdminService;
  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  private ListAppender<ILoggingEvent> alertLog;

  @BeforeEach
  void captureAlertLog() {
    alertLog = new ListAppender<>();
    alertLog.start();
    ((Logger) LoggerFactory.getLogger(BreakGlassAlertAdapter.class)).addAppender(alertLog);
  }

  @AfterEach
  void releaseAlertLog() {
    ((Logger) LoggerFactory.getLogger(BreakGlassAlertAdapter.class)).detachAppender(alertLog);
    alertLog.stop();
  }

  // ── Grant ────────────────────────────────────────────────────────────────────────────

  @Test
  void should_grantTenantAdminWithAssignedByTargetAuditAndPage_when_tenantHasZeroAdministrators() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedSystemTenantAdminRole(tenantId);
    User target = seedUser(tenantId, true);

    BreakGlassOutcome outcome = bootstrapAdminService.grantFirstAdmin(target.getId(), CHANGE_REF);

    assertThat(outcome).isEqualTo(BreakGlassOutcome.GRANTED);
    assertThat(outcome.exitCode()).isZero();
    assertThat(activeAssignedBy(target.getId(), adminRole.getId()))
        .as("assigned_by is the target (Decision 10)")
        .containsExactly(target.getId());
    List<Map<String, Object>> rows = auditRows(tenantId);
    assertThat(rows).hasSize(1);
    assertThat(rows.get(0)).containsEntry("outcome", "SUCCESS");
    assertThat(rows.get(0)).containsEntry("actorType", "BREAK_GLASS_CLI");
    assertThat(rows.get(0)).containsEntry("changeRef", CHANGE_REF);
    assertThat(pagedMessages())
        .singleElement()
        .satisfies(
            message ->
                assertThat(message)
                    .startsWith("RBAC_BREAK_GLASS_USED")
                    .contains("outcome=GRANTED")
                    .contains("tenantId=" + tenantId)
                    .contains("targetUserId=" + target.getId())
                    .contains("changeRef=" + CHANGE_REF));
  }

  @Test
  void should_refuseWithExit5AndAuditAndPage_when_rerunAfterSuccess() {
    UUID tenantId = uuidGenerator.newId();
    seedSystemTenantAdminRole(tenantId);
    User target = seedUser(tenantId, true);
    assertThat(bootstrapAdminService.grantFirstAdmin(target.getId(), CHANGE_REF))
        .isEqualTo(BreakGlassOutcome.GRANTED);

    BreakGlassOutcome second = bootstrapAdminService.grantFirstAdmin(target.getId(), CHANGE_REF);

    assertThat(second).isEqualTo(BreakGlassOutcome.TENANT_HAS_ADMIN);
    assertThat(second.exitCode()).isEqualTo(5);
    assertThat(activeAdminHolderCount(tenantId)).isEqualTo(1);
    assertThat(auditRows(tenantId))
        .extracting(row -> row.get("outcome") + ":" + row.get("reason"))
        .containsExactlyInAnyOrder("SUCCESS:null", "FAILURE:TENANT_HAS_ADMIN");
    assertThat(pagedMessages()).hasSize(2);
  }

  // ── Refusals ─────────────────────────────────────────────────────────────────────────

  @Test
  void should_refuseWithExit5_when_anAdministratorAlreadyExists() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedSystemTenantAdminRole(tenantId);
    User existingAdmin = seedUser(tenantId, true);
    userRoleRepository.save(
        new UserRole(
            uuidGenerator.newId(), existingAdmin.getId(), adminRole.getId(), tenantId,
            existingAdmin.getId()));
    User target = seedUser(tenantId, true);

    BreakGlassOutcome outcome = bootstrapAdminService.grantFirstAdmin(target.getId(), CHANGE_REF);

    assertThat(outcome).isEqualTo(BreakGlassOutcome.TENANT_HAS_ADMIN);
    assertThat(activeAssignedBy(target.getId(), adminRole.getId())).isEmpty();
    assertSingleRefusal(tenantId, "TENANT_HAS_ADMIN");
  }

  @Test
  void should_refuseWithExit4_when_tenantHasNoSeededTenantAdminRole() {
    UUID tenantId = uuidGenerator.newId();
    User target = seedUser(tenantId, true);

    BreakGlassOutcome outcome = bootstrapAdminService.grantFirstAdmin(target.getId(), CHANGE_REF);

    assertThat(outcome).isEqualTo(BreakGlassOutcome.NO_SYSTEM_ADMIN_ROLE);
    assertThat(outcome.exitCode()).isEqualTo(4);
    assertSingleRefusal(tenantId, "NO_SYSTEM_ADMIN_ROLE");
  }

  @Test
  void should_refuseWithExit4_when_theTenantAdminRoleIsNotASystemRole() {
    UUID tenantId = uuidGenerator.newId();
    roleRepository.save(new Role(uuidGenerator.newId(), tenantId, "TENANT_ADMIN", "custom", false));
    User target = seedUser(tenantId, true);

    assertThat(bootstrapAdminService.grantFirstAdmin(target.getId(), CHANGE_REF))
        .isEqualTo(BreakGlassOutcome.NO_SYSTEM_ADMIN_ROLE);
  }

  @Test
  void should_refuseWithExit3_when_targetUserIsNotActive() {
    UUID tenantId = uuidGenerator.newId();
    seedSystemTenantAdminRole(tenantId);
    User pending = seedUser(tenantId, false);

    BreakGlassOutcome outcome = bootstrapAdminService.grantFirstAdmin(pending.getId(), CHANGE_REF);

    assertThat(outcome).isEqualTo(BreakGlassOutcome.USER_NOT_ACTIVE);
    assertThat(outcome.exitCode()).isEqualTo(3);
    assertSingleRefusal(tenantId, "USER_NOT_ACTIVE");
  }

  @Test
  void should_refuseWithExit3AndNullTenantRow_when_targetUserDoesNotExist() {
    UUID unknownUser = uuidGenerator.newId();

    BreakGlassOutcome outcome = bootstrapAdminService.grantFirstAdmin(unknownUser, CHANGE_REF);

    assertThat(outcome).isEqualTo(BreakGlassOutcome.USER_NOT_FOUND);
    List<Map<String, Object>> rows =
        jdbc.queryForList(
            "SELECT outcome, JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.reason')) AS reason "
                + "FROM auth_events WHERE event_type = 'ROLE_BREAK_GLASS_GRANT' AND user_id = ?",
            toBytes(unknownUser));
    assertThat(rows).hasSize(1);
    assertThat(rows.get(0)).containsEntry("outcome", "FAILURE").containsEntry("reason", "USER_NOT_FOUND");
    assertThat(pagedMessages()).singleElement().asString().contains("reason=USER_NOT_FOUND");
  }

  // ── Concurrency (TS-6) ───────────────────────────────────────────────────────────────

  /**
   * A revoke of the tenant's last administrator racing the CLI. The revoke is blocked by the
   * last-admin lockout and the CLI refuses on the administrator it finds, whichever takes the set
   * lock first: exactly one administrator holds the tenant afterwards, never zero and never two.
   */
  @Test
  void should_serializeOnTheSetLock_when_revokeOfLastAdminRacesTheCli() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedSystemTenantAdminRole(tenantId);
    User admin = seedUser(tenantId, true);
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), admin.getId(), adminRole.getId(), tenantId, admin.getId()));
    User target = seedUser(tenantId, true);
    RoleChangeActor actor = new RoleChangeActor(admin.getId(), tenantId);

    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      CyclicBarrier barrier = new CyclicBarrier(2);
      Future<Object> revoke =
          pool.submit(
              (Callable<Object>)
                  () -> {
                    barrier.await(5, TimeUnit.SECONDS);
                    roleAssignmentService.revoke(
                        actor, admin.getId(), adminRole.getId(),
                        RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "BreakGlassAdminIT"));
                    return "revoked";
                  });
      Future<BreakGlassOutcome> cli =
          pool.submit(
              () -> {
                barrier.await(5, TimeUnit.SECONDS);
                return bootstrapAdminService.grantFirstAdmin(target.getId(), CHANGE_REF);
              });

      assertThatThrownBy(() -> revoke.get(30, TimeUnit.SECONDS))
          .isInstanceOf(ExecutionException.class)
          .hasCauseInstanceOf(LastAdminRoleException.class);
      assertThat(cli.get(30, TimeUnit.SECONDS)).isEqualTo(BreakGlassOutcome.TENANT_HAS_ADMIN);
    } finally {
      pool.shutdownNow();
    }

    assertThat(activeAdminHolderCount(tenantId)).isEqualTo(1);
    assertThat(activeAssignedBy(admin.getId(), adminRole.getId())).isNotEmpty();
  }

  /** Two invocations for two users of one zero-administrator tenant: exactly one grant. */
  @Test
  void should_grantExactlyOnce_when_twoInvocationsRaceOnAZeroAdministratorTenant() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    seedSystemTenantAdminRole(tenantId);
    User first = seedUser(tenantId, true);
    User second = seedUser(tenantId, true);

    ExecutorService pool = Executors.newFixedThreadPool(2);
    List<BreakGlassOutcome> outcomes = new ArrayList<>();
    try {
      CyclicBarrier barrier = new CyclicBarrier(2);
      Future<BreakGlassOutcome> a =
          pool.submit(
              () -> {
                barrier.await(5, TimeUnit.SECONDS);
                return bootstrapAdminService.grantFirstAdmin(first.getId(), "OPS-1");
              });
      Future<BreakGlassOutcome> b =
          pool.submit(
              () -> {
                barrier.await(5, TimeUnit.SECONDS);
                return bootstrapAdminService.grantFirstAdmin(second.getId(), "OPS-2");
              });
      outcomes.add(a.get(30, TimeUnit.SECONDS));
      outcomes.add(b.get(30, TimeUnit.SECONDS));
    } finally {
      pool.shutdownNow();
    }

    assertThat(outcomes)
        .containsExactlyInAnyOrder(BreakGlassOutcome.GRANTED, BreakGlassOutcome.TENANT_HAS_ADMIN);
    assertThat(activeAdminHolderCount(tenantId)).isEqualTo(1);
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────────────

  /** A system {@code TENANT_ADMIN} carrying the whole catalogue (a real one does since V6). */
  private Role seedSystemTenantAdminRole(UUID tenantId) {
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, RbacRoleNames.TENANT_ADMIN, "bg-it", true));
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions",
        role.getId().toString());
    return role;
  }

  private User seedUser(UUID tenantId, boolean active) {
    String email = "bg-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    if (active) {
      user.verify(Instant.now());
    }
    return userRepository.save(user);
  }

  private List<UUID> activeAssignedBy(UUID userId, UUID roleId) {
    return jdbc.query(
        "SELECT BIN_TO_UUID(assigned_by) FROM user_roles "
            + "WHERE user_id = ? AND role_id = ? AND revoked_at IS NULL",
        (rs, i) -> UUID.fromString(rs.getString(1)),
        toBytes(userId),
        toBytes(roleId));
  }

  private int activeAdminHolderCount(UUID tenantId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id "
                + "WHERE ur.tenant_id = ? AND r.name = 'TENANT_ADMIN' AND ur.revoked_at IS NULL",
            Integer.class,
            toBytes(tenantId));
    return count == null ? 0 : count;
  }

  private List<Map<String, Object>> auditRows(UUID tenantId) {
    return jdbc.queryForList(
        "SELECT outcome, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.actorType')) AS actorType, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.changeRef')) AS changeRef, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.reason')) AS reason "
            + "FROM auth_events WHERE event_type = 'ROLE_BREAK_GLASS_GRANT' AND tenant_id = ?",
        toBytes(tenantId));
  }

  private void assertSingleRefusal(UUID tenantId, String reason) {
    List<Map<String, Object>> rows = auditRows(tenantId);
    assertThat(rows).hasSize(1);
    assertThat(rows.get(0)).containsEntry("outcome", "FAILURE").containsEntry("reason", reason);
    assertThat(pagedMessages()).singleElement().asString().contains("reason=" + reason);
  }

  private List<String> pagedMessages() {
    return alertLog.list.stream()
        .filter(event -> event.getLevel() == Level.ERROR)
        .map(ILoggingEvent::getFormattedMessage)
        .filter(message -> message.startsWith("RBAC_BREAK_GLASS_USED"))
        .toList();
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
