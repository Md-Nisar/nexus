package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.domain.LastAdminRoleException;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

/**
 * US-012 T-018 (04-tasks.md; 03-design.md §5.2 M1/§3.2; 03b-threat-model.md T-D3): the AC5
 * last-admin lockout guard in {@link RoleAssignmentService#revoke}, permanently codifying the
 * threat model's empirical finding that M1's locking read confines the {@code FOR UPDATE} lock
 * scope to one tenant's {@code TENANT_ADMIN} rows (driven by the {@code fk_user_roles_role} FK
 * index, never a full table scan) and that revocations of the same tenant's admin assignments
 * therefore serialize correctly under concurrency.
 *
 * <p><strong>Concurrency-harness note</strong> (mirrors the discrepancy flagged in {@link
 * ActiveAssignmentIT}'s own Javadoc): {@code SecureEventServiceConcurrencyTest} is a single-
 * threaded Mockito unit test with no {@code ExecutorService}/{@code CyclicBarrier} and no
 * Testcontainers — it is not a real concurrency harness. {@link #should_allowExactlyOneWinner_when_eightConcurrentRevokesRaceAcrossTwoAdmins()}
 * below instead mirrors {@code RefreshTokenRotationIT#concurrent_rotation_single_winner} /
 * {@code ActiveAssignmentIT#should_allowExactlyOneWinner_when_eightConcurrentActiveInsertsRace}:
 * an 8-thread pool, a {@link CyclicBarrier}, and {@link Future} collection against a live
 * Testcontainers MySQL instance — an actual multi-thread race, not a sequential simulation.
 *
 * <p><strong>Bootstrap-tenant fixture choice, deliberate:</strong> the first two scenarios
 * reuse the migration-seeded bootstrap tenant ({@code 00000000-0000-7000-8000-000000000001})
 * and its real seeded {@code TENANT_ADMIN} role ({@code 019f6839-1810-…-00000000000a}) —
 * on purpose, per 04-tasks.md T-018's own reasoning: a hardcoded-bootstrap-role-id
 * implementation bug would pass both of these scenarios by accident, since they happen to run
 * in that exact tenant. {@link #should_blockRevocation_when_nonBootstrapTenantHasOnlyOneActiveAdmin()}
 * is the scenario that actually catches that class of bug, using a freshly generated tenant and
 * a freshly created {@code TENANT_ADMIN}-named role that the resolve-by-{@code (tenant, name)}
 * path must reach correctly. Because the bootstrap tenant's admin-role row count is shared,
 * mutable state across this whole IT suite, {@link #cleanUpBootstrapTenantFixtures()} force-
 * revokes (via raw JDBC, bypassing the guard under test) every row this class creates there, so
 * each bootstrap-tenant test starts from a verified zero baseline ({@link
 * #assertBootstrapTenantAdminBaselineIsZero()}) regardless of execution order.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class LastAdminLockoutIT {

  private static final UUID BOOTSTRAP_TENANT_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final UUID BOOTSTRAP_TENANT_ADMIN_ROLE_ID =
      UUID.fromString("019f6839-1810-7000-8000-00000000000a");

  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  /** Rows created against the shared bootstrap-tenant admin role, force-revoked in {@link #cleanUpBootstrapTenantFixtures()}. */
  private final List<UUID> bootstrapAdminAssignmentIdsToClean = new ArrayList<>();

  @AfterEach
  void cleanUpBootstrapTenantFixtures() {
    for (UUID id : bootstrapAdminAssignmentIdsToClean) {
      forceRevokeDirectly(id);
    }
    bootstrapAdminAssignmentIdsToClean.clear();
  }

  // ── Scenario 1: last admin in the tenant, self-revocation ──────────────────────────────

  @Test
  void should_blockRevocationAndKeepRowActive_when_revokingTenantsOnlyActiveAdminAssignment() {
    assertBootstrapTenantAdminBaselineIsZero();

    User admin = seedUser(BOOTSTRAP_TENANT_ID, "solo");
    UserRole assignment = seedActiveAdminAssignment(BOOTSTRAP_TENANT_ID,
        BOOTSTRAP_TENANT_ADMIN_ROLE_ID, admin.getId(), admin.getId());
    bootstrapAdminAssignmentIdsToClean.add(assignment.getId());

    RoleChangeActor actor = new RoleChangeActor(admin.getId(), BOOTSTRAP_TENANT_ID);

    assertThatThrownBy(
            () ->
                roleAssignmentService.revoke(
                    actor, admin.getId(), BOOTSTRAP_TENANT_ADMIN_ROLE_ID, requestContext()))
        .isInstanceOf(LastAdminRoleException.class)
        .extracting(e -> ((LastAdminRoleException) e).code())
        .isEqualTo("RBAC_002");

    assertThat(isActive(assignment.getId()))
        .as("the tenant's only active TENANT_ADMIN assignment must remain active after a"
            + " blocked revoke — the row must never be silently touched on a 409 path")
        .isTrue();
  }

  // ── Scenario 2: actor-agnostic — a different caller revoking, not self-revocation ──────

  @Test
  void should_blockRevocation_when_differentAdminAttemptsTheRevocation() {
    assertBootstrapTenantAdminBaselineIsZero();

    User targetAdmin = seedUser(BOOTSTRAP_TENANT_ID, "target");
    // Deliberately NOT itself an active TENANT_ADMIN — the guard must fire based purely on the
    // TARGET assignment being the tenant's last one, never on any relationship between actor
    // and target (Gate 1 Resolution 5 / AC5's actor-agnostic reading).
    User differentCaller = seedUser(BOOTSTRAP_TENANT_ID, "caller");
    UserRole assignment = seedActiveAdminAssignment(BOOTSTRAP_TENANT_ID,
        BOOTSTRAP_TENANT_ADMIN_ROLE_ID, targetAdmin.getId(), targetAdmin.getId());
    bootstrapAdminAssignmentIdsToClean.add(assignment.getId());

    RoleChangeActor actor = new RoleChangeActor(differentCaller.getId(), BOOTSTRAP_TENANT_ID);

    assertThatThrownBy(
            () ->
                roleAssignmentService.revoke(
                    actor, targetAdmin.getId(), BOOTSTRAP_TENANT_ADMIN_ROLE_ID, requestContext()))
        .isInstanceOf(LastAdminRoleException.class)
        .extracting(e -> ((LastAdminRoleException) e).code())
        .isEqualTo("RBAC_002");

    assertThat(isActive(assignment.getId()))
        .as("a revocation attempted by someone other than the target admin must be blocked"
            + " identically to self-revocation")
        .isTrue();
  }

  // ── Scenario 3: the concurrency test — highest-value test in this task ────────────────

  /**
   * Seeds a fresh (non-bootstrap) tenant with exactly two active {@code TENANT_ADMIN}
   * assignments held by two different users, then launches 8 threads that race to revoke
   * either one, synchronized via a {@link CyclicBarrier} so they fire as close to
   * simultaneously as possible.
   *
   * <p>Because M1's lock ({@code SELECT … WHERE role_id = :roleId AND tenant_id = :tenantId …
   * FOR UPDATE}) covers <em>both</em> admin rows regardless of which specific one a caller
   * targets, all 8 attempts fully serialize against each other. Whichever thread's M1 read
   * executes first sees both rows still active (size 2), passes the guard, and revokes its
   * own target. Every subsequent thread's M1 read is a current (locking) read that observes
   * the now-committed state: a thread targeting the row that is now the last remaining active
   * admin gets {@link LastAdminRoleException} (409, the guard genuinely firing under
   * concurrency); a thread targeting the row the winner already revoked instead loses the M6
   * affected-row race and gets {@link ResourceNotFoundException} (404, "already revoked" — Res.
   * 7's contract, not a guard failure). Both are legitimate, safe outcomes; a raw {@code
   * DataAccessException} or any other exception type is not, and fails the test. Splitting the
   * 8 threads 4/4 across the two admins guarantees at least one thread lands in the genuine
   * lockout branch, so the test does not merely re-prove M6's ordinary lost-race guard — it
   * proves the AC5 guard itself fires correctly under a real race (03-design.md §3.2 / threat
   * model T-D3).
   */
  @Test
  void should_allowExactlyOneWinner_when_eightConcurrentRevokesRaceAcrossTwoAdmins()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "conc");
    User caller = seedUser(tenantId, "conc-caller");
    User admin1 = seedUser(tenantId, "conc-admin1");
    User admin2 = seedUser(tenantId, "conc-admin2");
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin1.getId(), caller.getId());
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin2.getId(), caller.getId());

    RoleChangeActor actor = new RoleChangeActor(caller.getId(), tenantId);
    int threadCount = 8;
    CyclicBarrier barrier = new CyclicBarrier(threadCount);
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    List<Future<String>> futures = new ArrayList<>();

    for (int i = 0; i < threadCount; i++) {
      UUID target = (i % 2 == 0) ? admin1.getId() : admin2.getId();
      futures.add(
          executor.submit(
              (Callable<String>)
                  () -> {
                    barrier.await(5, TimeUnit.SECONDS);
                    try {
                      roleAssignmentService.revoke(
                          actor, target, adminRole.getId(), requestContext());
                      return "SUCCESS";
                    } catch (LastAdminRoleException e) {
                      return "LOCKOUT";
                    } catch (ResourceNotFoundException e) {
                      return "LOST_RACE";
                    }
                  }));
    }

    executor.shutdown();
    boolean terminated = executor.awaitTermination(15, TimeUnit.SECONDS);
    assertThat(terminated).as("all 8 threads must complete within the timeout").isTrue();

    int successCount = 0;
    int lockoutCount = 0;
    int lostRaceCount = 0;
    for (Future<String> future : futures) {
      // future.get() rethrows unwrapped for anything NOT already caught above — an unexpected
      // exception type (e.g. a raw DataAccessException) fails this loop loudly rather than
      // being silently absorbed.
      String outcome = future.get();
      switch (outcome) {
        case "SUCCESS" -> successCount++;
        case "LOCKOUT" -> lockoutCount++;
        case "LOST_RACE" -> lostRaceCount++;
        default -> throw new IllegalStateException("Unexpected outcome: " + outcome);
      }
    }

    assertThat(successCount).as("exactly one concurrent revocation must win").isEqualTo(1);
    assertThat(lockoutCount)
        .as("at least one thread must observe the genuine AC5 lockout guard firing")
        .isGreaterThanOrEqualTo(1);
    assertThat(successCount + lockoutCount + lostRaceCount)
        .as("every thread must resolve to one of the three safe outcomes")
        .isEqualTo(threadCount);
    assertThat(countActiveAdminAssignments(tenantId, adminRole.getId()))
        .as("the tenant must retain exactly one active TENANT_ADMIN assignment after the race")
        .isEqualTo(1);
  }

  // ── Scenario 4: second, non-bootstrap tenant (R-9 regression) ──────────────────────────

  /**
   * Uses a freshly generated tenant id and a freshly created {@code TENANT_ADMIN}-named role
   * whose id is nothing like the bootstrap tenant's seeded literal. A hardcoded-bootstrap-role-
   * id implementation would fail to recognize this role as {@code TENANT_ADMIN} at all (or
   * would evaluate the guard against the wrong, unrelated tenant's admin rows), letting this
   * revoke incorrectly succeed instead of throwing — exactly the regression 04-tasks.md T-018
   * calls out scenario 1 as unable to catch on its own.
   */
  @Test
  void should_blockRevocation_when_nonBootstrapTenantHasOnlyOneActiveAdmin() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "nonbootstrap");
    User admin = seedUser(tenantId, "nonbootstrap-solo");
    UserRole assignment =
        seedActiveAdminAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    RoleChangeActor actor = new RoleChangeActor(admin.getId(), tenantId);

    assertThatThrownBy(
            () ->
                roleAssignmentService.revoke(
                    actor, admin.getId(), adminRole.getId(), requestContext()))
        .isInstanceOf(LastAdminRoleException.class)
        .extracting(e -> ((LastAdminRoleException) e).code())
        .isEqualTo("RBAC_002");

    assertThat(isActive(assignment.getId()))
        .as("a non-bootstrap tenant's own last active admin assignment must remain active"
            + " after a blocked revoke")
        .isTrue();
  }

  // ── Scenario 5: EXPLAIN pinning M1's query plan + "for update" in the emitted SQL ─────

  /**
   * Pins M1's plan two ways: (1) an {@code EXPLAIN} of the reconstructed native-SQL equivalent
   * of {@code JpaUserRoleRepository#lockActiveAssignmentsByRole} (03-design.md §5.2 M1),
   * asserting {@code key = fk_user_roles_role} (the FK index name — confirmed against
   * {@code V5__rbac_schema.sql}'s {@code CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id)}
   * and the threat model's own live-MySQL verification) and {@code type = ref}, never {@code
   * ALL}; (2) a Hibernate SQL-logging capture around the REAL production call path ({@link
   * RoleAssignmentService#revoke}, with two active admins so the call succeeds without
   * throwing) asserting the actually-emitted statement contains {@code for update}.
   */
  @Test
  void should_pinQueryPlanToFkIndex_and_emitForUpdate_when_lockingTenantAdminAssignments()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "explain");
    User admin1 = seedUser(tenantId, "explain-admin1");
    User admin2 = seedUser(tenantId, "explain-admin2");
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin1.getId(), admin1.getId());
    seedActiveAdminAssignment(tenantId, adminRole.getId(), admin2.getId(), admin2.getId());

    List<Map<String, Object>> plan =
        jdbc.queryForList(
            "EXPLAIN SELECT id FROM user_roles WHERE role_id = ? AND tenant_id = ? AND"
                + " revoked_at IS NULL FOR UPDATE",
            toBytes(adminRole.getId()),
            toBytes(tenantId));

    assertThat(plan).hasSize(1);
    Map<String, Object> row = plan.get(0);
    assertThat(String.valueOf(row.get("key")))
        .as("M1 must drive off the FK index on role_id, never a full table scan: " + row)
        .isEqualTo("fk_user_roles_role");
    assertThat(String.valueOf(row.get("type")))
        .as("M1's access type must be an index lookup (ref), never ALL: " + row)
        .isEqualTo("ref");

    RoleChangeActor actor = new RoleChangeActor(admin1.getId(), tenantId);
    List<String> emittedSql =
        captureHibernateSql(
            () ->
                roleAssignmentService.revoke(
                    actor, admin1.getId(), adminRole.getId(), requestContext()));

    assertThat(emittedSql)
        .as("emitted SQL captured during the revoke call: " + emittedSql)
        .anyMatch(sql -> sql.toLowerCase(Locale.ROOT).contains("for update"));
  }

  // ── Shared seeding / assertion helpers ─────────────────────────────────────────────────

  private void assertBootstrapTenantAdminBaselineIsZero() {
    assertThat(countActiveAdminAssignments(BOOTSTRAP_TENANT_ID, BOOTSTRAP_TENANT_ADMIN_ROLE_ID))
        .as("bootstrap tenant must have zero active TENANT_ADMIN assignments before this test"
            + " seeds its own — a stray leftover row here (e.g. from another *IT not cleaning"
            + " up) would silently invalidate this test's 'the only active admin' premise")
        .isZero();
  }

  private User seedUser(UUID tenantId, String tag) {
    String email = "lal-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }

  /** A tenant-scoped role literally named {@code TENANT_ADMIN} (matches {@code RbacRoleNames}). */
  private Role seedTenantAdminRole(UUID tenantId, String tag) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, "TENANT_ADMIN", tag, false));
  }

  private UserRole seedActiveAdminAssignment(
      UUID tenantId, UUID roleId, UUID assigneeId, UUID assignedById) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), assigneeId, roleId, tenantId, assignedById));
  }

  private RequestContext requestContext() {
    return RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "LastAdminLockoutIT");
  }

  private int countActiveAdminAssignments(UUID tenantId, UUID roleId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE role_id = ? AND tenant_id = ? AND revoked_at"
                + " IS NULL",
            Integer.class,
            toBytes(roleId),
            toBytes(tenantId));
    return count == null ? 0 : count;
  }

  private boolean isActive(UUID userRoleId) {
    Timestamp revokedAt =
        jdbc.queryForObject(
            "SELECT revoked_at FROM user_roles WHERE id = ?", Timestamp.class, toBytes(userRoleId));
    return revokedAt == null;
  }

  /**
   * Test-cleanup-only bypass of the guard under test: force-revokes a row directly via JDBC so
   * bootstrap-tenant fixtures don't leak an active admin count into later tests. Never used to
   * assert production behavior.
   */
  private void forceRevokeDirectly(UUID userRoleId) {
    jdbc.update(
        "UPDATE user_roles SET revoked_at = NOW(6) WHERE id = ? AND revoked_at IS NULL",
        toBytes(userRoleId));
  }

  private List<String> captureHibernateSql(Runnable action) {
    Logger sqlLogger = (Logger) LoggerFactory.getLogger("org.hibernate.SQL");
    Level originalLevel = sqlLogger.getLevel();
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    sqlLogger.addAppender(appender);
    sqlLogger.setLevel(Level.DEBUG);
    try {
      action.run();
    } finally {
      sqlLogger.detachAppender(appender);
      sqlLogger.setLevel(originalLevel);
      appender.stop();
    }
    return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
