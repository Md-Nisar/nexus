package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import java.nio.ByteBuffer;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * T-017 (04-tasks.md; 03-design.md §3.1-§3.3, §5.2 M1-M6, §5.4): happy-path and near-happy-path
 * integration coverage for {@link RoleAssignmentService#assign}/{@link
 * RoleAssignmentService#revoke}, against real Testcontainers MySQL (never H2 — {@code
 * docs/TESTING.md}).
 *
 * <p><b>Tested at the SERVICE layer, not through HTTP.</b> {@link RoleAssignmentService} is
 * autowired directly against the real {@link JpaUserRoleAssignmentAdapter}/{@link
 * com.example.nexus.identity.infrastructure.persistence.JpaUserDirectoryAdapter} beans wired to
 * Testcontainers MySQL. Every assertion this class needs to make is about persisted DB state
 * (revoked_at, the M6 microsecond precision, user_id/assigned_by/tenant_id provenance) or about
 * which domain exception/response value the service returns — none of it depends on HTTP
 * status-code translation, path/body UUID string parsing, or JWT/{@code Authentication}
 * unwrapping, all of which are already the dedicated concerns of {@code UserRoleControllerTest}
 * (T-011, MockMvc slice) and {@code RoleAssignmentSecurityIT} (T-019, full HTTP). Testing here at
 * the service layer keeps this class focused on the DB-interaction assertions T-017 actually asks
 * for, and avoids re-minting JWTs purely to reach assertions that never touch the HTTP layer.
 *
 * <p><b>Shared-schema caveat</b> (see {@link ActiveAssignmentIT}'s Javadoc): every {@code *IT}
 * class combining {@code @SpringBootTest} + {@code @Import(TestcontainersConfiguration.class)}
 * shares one cached Spring context/MySQL schema for the whole test run. Every fixture below uses a
 * freshly generated tenant id per test, randomized role names, and {@code is_system_role=false} —
 * never the seeded bootstrap tenant/role literals {@code RbacSchemaMigrationIT}'s scoped
 * seed-count assertions depend on.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RoleAssignmentIT {

  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  // ── Fixtures ─────────────────────────────────────────────────────────

  private User seedUser(String tag, UUID tenantId) {
    String email = "ra-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }

  private Role seedRole(String tag, UUID tenantId) {
    // is_system_role=false: keeps RbacSchemaMigrationIT's scoped seed-role count stable
    // regardless of test execution order (see ActiveAssignmentIT's seedRole Javadoc).
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "RA-" + tag + "-" + UUID.randomUUID(), null, false));
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

  // ── Scenario 1: assign → active row ─────────────────────────────────

  @Test
  void should_createActiveAssignment_when_assigningValidRoleInSameTenant() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("assign-actor", tenantId);
    User target = seedUser("assign-target", tenantId);
    Role role = seedRole("ASSIGN", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);

    ActiveRoleAssignment result =
        roleAssignmentService.assign(actor, target.getId(), role.getId(), RequestContext.UNKNOWN);

    assertThat(result.userId()).isEqualTo(target.getId());
    Integer activeCount =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ? AND revoked_at IS"
                + " NULL",
            Integer.class,
            toBytes(target.getId()),
            toBytes(role.getId()));
    assertThat(activeCount).as("assignment must persist as an active (revoked_at IS NULL) row").isEqualTo(1);
  }

  // ── Scenario 2: revoke → soft-deleted, row retained ─────────────────

  @Test
  void should_setRevokedAtAndKeepRowPresent_when_revokingActiveAssignment() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("revoke-actor", tenantId);
    User target = seedUser("revoke-target", tenantId);
    Role role = seedRole("REVOKE", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    roleAssignmentService.assign(actor, target.getId(), role.getId(), RequestContext.UNKNOWN);

    roleAssignmentService.revoke(actor, target.getId(), role.getId(), RequestContext.UNKNOWN);

    Integer rowCount =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ?",
            Integer.class,
            toBytes(target.getId()),
            toBytes(role.getId()));
    assertThat(rowCount).as("revocation must be a soft delete — the row must never be hard-deleted").isEqualTo(1);

    Integer revokedCount =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ? AND revoked_at IS"
                + " NOT NULL",
            Integer.class,
            toBytes(target.getId()),
            toBytes(role.getId()));
    assertThat(revokedCount).isEqualTo(1);
  }

  // ── Scenario 3: reassign after revoke ────────────────────────────────

  @Test
  void should_allowReassignment_when_sameUserRolePairPreviouslyRevoked() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("reassign-actor", tenantId);
    User target = seedUser("reassign-target", tenantId);
    Role role = seedRole("REASSIGN", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    roleAssignmentService.assign(actor, target.getId(), role.getId(), RequestContext.UNKNOWN);
    roleAssignmentService.revoke(actor, target.getId(), role.getId(), RequestContext.UNKNOWN);

    ActiveRoleAssignment reassigned =
        roleAssignmentService.assign(actor, target.getId(), role.getId(), RequestContext.UNKNOWN);

    assertThat(reassigned.userId()).isEqualTo(target.getId());
    Integer totalRows =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ?",
            Integer.class,
            toBytes(target.getId()),
            toBytes(role.getId()));
    assertThat(totalRows)
        .as("reassignment after revocation is a plain second INSERT, never a resurrect of the"
            + " original row (active_key is NULL for revoked rows, so there is no uniqueness"
            + " conflict)")
        .isEqualTo(2);
    Integer activeCount =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ? AND revoked_at IS"
                + " NULL",
            Integer.class,
            toBytes(target.getId()),
            toBytes(role.getId()));
    assertThat(activeCount).isEqualTo(1);
  }

  // ── Scenario 4: duplicate active assignment ──────────────────────────

  @Test
  void should_throwDuplicateRoleAssignmentException_when_userAlreadyActivelyHoldsRole() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("dup-actor", tenantId);
    User target = seedUser("dup-target", tenantId);
    Role role = seedRole("DUP", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    roleAssignmentService.assign(actor, target.getId(), role.getId(), RequestContext.UNKNOWN);

    assertThatThrownBy(
            () ->
                roleAssignmentService.assign(
                    actor, target.getId(), role.getId(), RequestContext.UNKNOWN))
        .isInstanceOf(DuplicateRoleAssignmentException.class)
        .satisfies(
            e -> assertThat(((DuplicateRoleAssignmentException) e).code()).isEqualTo("RBAC_004"));
  }

  // ── Scenario 4b: concurrent duplicate-assignment race (TOCTOU backstop) ─────

  /**
   * Gap identified in Phase 8 test-validate: {@code
   * JpaUserRoleAssignmentAdapter#assign}'s {@code catch (DataIntegrityViolationException) ->
   * throw DuplicateRoleAssignmentException} is the design's documented "TOCTOU backstop" behind
   * {@link RoleAssignmentService}'s M2 pre-check (03-design.md §4.3) — but until this test, no
   * test exercised it end-to-end through the real service+adapter. {@code
   * should_throwDuplicateRoleAssignmentException_when_userAlreadyActivelyHoldsRole} above only
   * exercises the M2 pre-check itself (sequential calls, second one short-circuits before ever
   * reaching the adapter's insert). {@code ActiveAssignmentIT}'s own concurrent-insert test calls
   * {@code JpaUserRoleRepository#save} directly, bypassing the adapter and service entirely, so it
   * proves the DB constraint exists but not that the service ever sees a clean 409 rather than an
   * unhandled 500 under a genuine race.
   *
   * <p>Here, 8 threads race {@link RoleAssignmentService#assign} for the exact same (user, role)
   * pair via a {@link CyclicBarrier}, so multiple threads can pass the M2 pre-check (which is not
   * itself locking) before either commits — forcing at least one loser to hit the unique-index
   * violation on the actual {@code INSERT} and prove the adapter's translation fires for real.
   */
  @Test
  void should_allowExactlyOneWinner_when_eightConcurrentAssignsRaceForSameUserAndRole()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("conc-dup-actor", tenantId);
    User target = seedUser("conc-dup-target", tenantId);
    Role role = seedRole("CONC-DUP", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);

    int threadCount = 8;
    CyclicBarrier barrier = new CyclicBarrier(threadCount);
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    List<Future<String>> futures = new ArrayList<>();

    for (int i = 0; i < threadCount; i++) {
      futures.add(
          executor.submit(
              (Callable<String>)
                  () -> {
                    barrier.await(5, TimeUnit.SECONDS);
                    try {
                      roleAssignmentService.assign(
                          actor, target.getId(), role.getId(), RequestContext.UNKNOWN);
                      return "SUCCESS";
                    } catch (DuplicateRoleAssignmentException e) {
                      return "DUPLICATE";
                    }
                  }));
    }

    executor.shutdown();
    boolean terminated = executor.awaitTermination(15, TimeUnit.SECONDS);
    assertThat(terminated).as("all 8 threads must complete within the timeout").isTrue();

    int successCount = 0;
    int duplicateCount = 0;
    for (Future<String> future : futures) {
      // future.get() rethrows unwrapped for anything NOT already caught above -- an unhandled
      // DataAccessException (i.e. the adapter's catch NOT firing) fails this loop loudly rather
      // than being silently absorbed as a false "duplicate" outcome.
      String outcome = future.get();
      switch (outcome) {
        case "SUCCESS" -> successCount++;
        case "DUPLICATE" -> duplicateCount++;
        default -> throw new IllegalStateException("Unexpected outcome: " + outcome);
      }
    }

    assertThat(successCount).as("exactly one concurrent assign must win").isEqualTo(1);
    assertThat(duplicateCount)
        .as("every loser must resolve to a clean DuplicateRoleAssignmentException (409 RBAC_004),"
            + " never an unhandled DataAccessException")
        .isEqualTo(threadCount - 1);

    Integer activeCount =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ? AND revoked_at IS"
                + " NULL",
            Integer.class,
            toBytes(target.getId()),
            toBytes(role.getId()));
    assertThat(activeCount)
        .as("exactly one active assignment must exist after the race")
        .isEqualTo(1);
  }

  // ── Scenario 5: 404-equivalent paths ─────────────────────────────────

  @Test
  void should_throwResourceNotFound_when_assigningRoleToNonexistentUser() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("404-user-actor", tenantId);
    Role role = seedRole("404-USER", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    UUID nonexistentUserId = uuidGenerator.newId();

    assertThatThrownBy(
            () ->
                roleAssignmentService.assign(
                    actor, nonexistentUserId, role.getId(), RequestContext.UNKNOWN))
        .isInstanceOf(ResourceNotFoundException.class)
        .satisfies(
            e -> assertThat(((ResourceNotFoundException) e).code()).isEqualTo("USER_NOT_FOUND"));
  }

  @Test
  void should_throwResourceNotFound_when_assigningNonexistentRole() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("404-role-actor", tenantId);
    User target = seedUser("404-role-target", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    UUID nonexistentRoleId = uuidGenerator.newId();

    assertThatThrownBy(
            () ->
                roleAssignmentService.assign(
                    actor, target.getId(), nonexistentRoleId, RequestContext.UNKNOWN))
        .isInstanceOf(ResourceNotFoundException.class)
        .satisfies(
            e -> assertThat(((ResourceNotFoundException) e).code()).isEqualTo("ROLE_NOT_FOUND"));
  }

  @Test
  void should_throwResourceNotFound_when_revokingRoleFromNonexistentUser() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("404-revoke-user-actor", tenantId);
    Role role = seedRole("404-REVOKE-USER", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    UUID nonexistentUserId = uuidGenerator.newId();

    assertThatThrownBy(
            () ->
                roleAssignmentService.revoke(
                    actor, nonexistentUserId, role.getId(), RequestContext.UNKNOWN))
        .isInstanceOf(ResourceNotFoundException.class)
        .satisfies(
            e -> assertThat(((ResourceNotFoundException) e).code()).isEqualTo("USER_NOT_FOUND"));
  }

  @Test
  void should_throwResourceNotFound_when_revokingNonexistentRole() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("404-revoke-role-actor", tenantId);
    User target = seedUser("404-revoke-role-target", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    UUID nonexistentRoleId = uuidGenerator.newId();

    assertThatThrownBy(
            () ->
                roleAssignmentService.revoke(
                    actor, target.getId(), nonexistentRoleId, RequestContext.UNKNOWN))
        .isInstanceOf(ResourceNotFoundException.class)
        .satisfies(
            e -> assertThat(((ResourceNotFoundException) e).code()).isEqualTo("ROLE_NOT_FOUND"));
  }

  @Test
  void should_throwResourceNotFound_notSilentlySucceed_when_revokingAlreadyRevokedAssignment() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("404-already-revoked-actor", tenantId);
    User target = seedUser("404-already-revoked-target", tenantId);
    Role role = seedRole("404-ALREADY-REVOKED", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    roleAssignmentService.assign(actor, target.getId(), role.getId(), RequestContext.UNKNOWN);
    roleAssignmentService.revoke(actor, target.getId(), role.getId(), RequestContext.UNKNOWN);

    // Res. 7 / 03-design.md §3.2: revoking an already-revoked assignment must NOT be a silently
    // idempotent success — it must be indistinguishable from "never assigned", i.e. 404.
    assertThatThrownBy(
            () ->
                roleAssignmentService.revoke(
                    actor, target.getId(), role.getId(), RequestContext.UNKNOWN))
        .isInstanceOf(ResourceNotFoundException.class)
        .satisfies(
            e ->
                assertThat(((ResourceNotFoundException) e).code())
                    .isEqualTo("ROLE_ASSIGNMENT_NOT_FOUND"));
  }

  // ── Scenario 6: microsecond-precision assertion (M6, FUNCTION('now', 6)) ─────

  @Test
  void should_setRevokedAtWithMicrosecondPrecision_when_revokingImmediatelyAfterAssigning() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("microsecond-actor", tenantId);
    User target = seedUser("microsecond-target", tenantId);
    Role role = seedRole("MICROSECOND", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);
    roleAssignmentService.assign(actor, target.getId(), role.getId(), RequestContext.UNKNOWN);

    // No artificial delay — the whole point of this test is same-instant assign-then-revoke.
    roleAssignmentService.revoke(actor, target.getId(), role.getId(), RequestContext.UNKNOWN);

    Map<String, Object> row =
        jdbc.queryForMap(
            "SELECT assigned_at, revoked_at, MICROSECOND(revoked_at) AS revoked_micros FROM"
                + " user_roles WHERE user_id = ? AND role_id = ?",
            toBytes(target.getId()),
            toBytes(role.getId()));
    // MySQL Connector/J returns DATETIME(6) columns as java.time.LocalDateTime via
    // JdbcTemplate#queryForMap's default getObject() mapping, never java.sql.Timestamp.
    LocalDateTime assignedAt = (LocalDateTime) row.get("assigned_at");
    LocalDateTime revokedAt = (LocalDateTime) row.get("revoked_at");
    Number revokedMicros = (Number) row.get("revoked_micros");

    assertThat(revokedAt)
        .as("revoked_at must never precede assigned_at (chk_user_roles_revoked_not_before_assigned)")
        .isAfterOrEqualTo(assignedAt);
    // Proves the M6 app-side clamp (max(now, assignedAt) -- 03-design.md §5.2 M6/R-8, adopted
    // after FUNCTION('now', 6) was found to fail HQL parsing on this codebase's pinned Hibernate
    // version) preserves microsecond precision end-to-end through java.time.Instant -> MySQL
    // DATETIME(6), rather than silently truncating to whole seconds the way a naive
    // current_timestamp-style write would.
    assertThat(revokedMicros.intValue())
        .as("MICROSECOND(revoked_at) must be nonzero on this run, proving microsecond precision"
            + " was preserved rather than truncated to whole seconds")
        .isNotZero();
  }

  // ── Scenario 7: 201-equivalent result carries a non-null assignedAt ──

  @Test
  void should_returnNonNullAssignedAt_when_assignmentSucceeds() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("assignedat-actor", tenantId);
    User target = seedUser("assignedat-target", tenantId);
    Role role = seedRole("ASSIGNEDAT", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);

    ActiveRoleAssignment result =
        roleAssignmentService.assign(actor, target.getId(), role.getId(), RequestContext.UNKNOWN);

    // Proves the M4a projection re-read works (03-design.md §5.4): an entity re-read would
    // resolve to the just-persisted session instance, whose assignedAt would still be null in
    // memory — only a projection reads DB-generated values through.
    assertThat(result.assignedAt()).isNotNull();
  }

  // ── Scenario 8: T-S3 provenance, four distinct UUIDs ─────────────────

  @Test
  void should_persistCorrectProvenance_when_actorTargetRoleAndTenantAreAllDistinct() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser("provenance-actor", tenantId);
    User target = seedUser("provenance-target", tenantId);
    Role role = seedRole("PROVENANCE", tenantId);
    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);

    // T-S3: four genuinely DISTINCT UUIDs -- actor, target, role, tenant -- none of them reused
    // across two of these roles. A positional-argument transposition bug would not be caught by
    // the type system, only by asserting the persisted row's columns individually below. Using
    // distinct().count() rather than Set.of(...) so an accidental collision fails as a clean
    // assertion mismatch, not an IllegalArgumentException from Set.of's own duplicate rejection.
    long distinctIdCount =
        List.of(actorUser.getId(), target.getId(), role.getId(), tenantId).stream()
            .distinct()
            .count();
    assertThat(distinctIdCount)
        .as("actor, target, role, and tenant ids must be four genuinely distinct values")
        .isEqualTo(4);

    roleAssignmentService.assign(actor, target.getId(), role.getId(), RequestContext.UNKNOWN);

    Map<String, Object> row =
        jdbc.queryForMap(
            "SELECT user_id, assigned_by, tenant_id FROM user_roles WHERE user_id = ? AND"
                + " role_id = ?",
            toBytes(target.getId()),
            toBytes(role.getId()));

    assertThat(toUuid((byte[]) row.get("user_id")))
        .as("user_id must be the TARGET user, never transposed with the actor")
        .isEqualTo(target.getId());
    assertThat(toUuid((byte[]) row.get("assigned_by")))
        .as("assigned_by must be the ACTOR, sourced only from actor.userId() — never the target")
        .isEqualTo(actorUser.getId());
    assertThat(toUuid((byte[]) row.get("tenant_id")))
        .as("tenant_id must be the actor's tenant")
        .isEqualTo(tenantId);
  }
}
