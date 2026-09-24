package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.LastAdminRoleException;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
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
import org.springframework.test.context.ActiveProfiles;

/**
 * US-017 T-007(a)/(e) (04-tasks.md; 03-design.md §11.3, A-4): a dedicated class (per A-4, not an
 * extension of the already-1000+-line {@link LastAdminLockoutIT}) exercising D5's cross-role,
 * distinct-HOLDER (not distinct-ROW) counting under a genuine concurrent race — the story's
 * central risk — and (e) proving M11's lock set never crosses a tenant boundary, even when fed a
 * deliberately cross-tenant role-id list.
 *
 * <p>Reuses {@link LastAdminLockoutIT}'s {@link CyclicBarrier}/{@link Future}/outcome-counting
 * harness shape and its "any unexpected exception type fails loudly" rule verbatim (A-4) — the
 * seeding helpers below are deliberately duplicated, not inherited, per A-4's own resolution.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class AdminEquivalentLockoutIT {

  // Seeded literals — V5__rbac_schema.sql header comment (same constants used elsewhere in this
  // package, e.g. LastAdminLockoutIT/RoleRevocationSymmetryIT).
  private static final UUID TENANT_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1801-7000-8000-000000000002");
  private static final UUID USER_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1803-7000-8000-000000000004");
  private static final UUID ROLE_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1805-7000-8000-000000000006");

  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private UserRoleAssignmentPort userRoleAssignmentPort;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  // ── (a) The story's central risk: cross-role distinct-holder counting under real concurrency ──

  /**
   * Seeds ONE tenant with exactly TWO distinct admin-equivalent holders across TWO DIFFERENT
   * admin-equivalent roles: {@code admin} holds the literal {@code TENANT_ADMIN} role, and {@code
   * dangerousHolder} holds a separate custom role carrying ALL THREE dangerous permissions. No
   * other admin-equivalent holder exists in this tenant. Two threads fire concurrently via a
   * {@link CyclicBarrier}, EACH a SELF-revocation ({@code admin} revoking their own {@code
   * TENANT_ADMIN} row; {@code dangerousHolder} revoking their own dangerous-role row) —
   * deliberately not one actor revoking the other, so that each thread's caller-gate check
   * (M5b, which runs INSIDE the transaction, after M11's lock) depends only on that thread's OWN
   * actor's OWN row, never on whether the OTHER thread has already committed. (An earlier version
   * of this fixture had {@code admin} perform both revokes; once {@code admin}'s own row was
   * revoked by the winning thread, the LOSING thread's caller-gate check legitimately denied
   * {@code admin} as no-longer-an-admin (403), which is correct production behaviour but made
   * this test's outcome order-dependent between a 403 and a 409 — not the property this test
   * exists to pin. Self-revocation on both sides removes that dependency.)
   *
   * <p>A single-role, single-user fixture (Harness A/B in {@code LastAdminLockoutIT}) cannot
   * distinguish row-counting from holder-counting — D5's defect is specifically that a naive
   * per-role {@code size() <= 1} check would see "role A has 1 holder" and "role B has 1 holder"
   * independently and let BOTH revocations through, zeroing the tenant. M11's shared union lock is
   * built from the SAME tenant-wide admin-equivalent role-id set (§7.2) regardless of which
   * specific role either thread targets, so these two transactions genuinely contend for the same
   * lock range: exactly ONE thread's {@code wouldLeaveTenantWithoutAdminEquivalentHolder} check
   * must see the OTHER holder still active (succeeds) and the other must see the holder count
   * would drop to zero (blocked, 409 {@code RBAC_002}) — deterministic regardless of which thread
   * wins the lock race, since both lock the SAME two-row range in the SAME acquisition order (no
   * deadlock is possible here; this is pure serialization, exactly Harness A's shape). Any other
   * exception type fails this test loudly, exactly as {@code LastAdminLockoutIT}'s harnesses do.
   */
  @Test
  void
      should_blockExactlyOneOfTwoConcurrentRevokes_when_theyWouldJointlyZeroTheTenantsDistinctAdminEquivalentHolders()
          throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "cross-role");
    User admin = seedUser(tenantId, "cross-role-admin");
    seedActiveAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    // Carries ALL THREE dangerous permissions -- not just role:write -- so dangerousHolder
    // qualifies for the caller gate via callerHoldsFullyAdminEquivalent and can self-revoke.
    Role dangerousRole = seedRole(tenantId, "CROSS-ROLE-DANGEROUS", "cross-role");
    grantPermission(dangerousRole.getId(), ROLE_WRITE_PERMISSION_ID);
    grantPermission(dangerousRole.getId(), USER_WRITE_PERMISSION_ID);
    grantPermission(dangerousRole.getId(), TENANT_WRITE_PERMISSION_ID);
    User dangerousHolder = seedUser(tenantId, "cross-role-dangerous-holder");
    seedActiveAssignment(tenantId, dangerousRole.getId(), dangerousHolder.getId(), admin.getId());

    RoleChangeActor adminActor = new RoleChangeActor(admin.getId(), tenantId);
    RoleChangeActor dangerousHolderActor = new RoleChangeActor(dangerousHolder.getId(), tenantId);

    CyclicBarrier barrier = new CyclicBarrier(2);
    ExecutorService executor = Executors.newFixedThreadPool(2);

    Future<String> revokeAdminOwnRow =
        executor.submit(
            (Callable<String>)
                () -> {
                  barrier.await(5, TimeUnit.SECONDS);
                  try {
                    roleAssignmentService.revoke(
                        adminActor, admin.getId(), adminRole.getId(), requestContext());
                    return "SUCCESS";
                  } catch (LastAdminRoleException e) {
                    return "LOCKOUT";
                  }
                });
    Future<String> revokeDangerousHolderOwnRow =
        executor.submit(
            (Callable<String>)
                () -> {
                  barrier.await(5, TimeUnit.SECONDS);
                  try {
                    roleAssignmentService.revoke(
                        dangerousHolderActor,
                        dangerousHolder.getId(),
                        dangerousRole.getId(),
                        requestContext());
                    return "SUCCESS";
                  } catch (LastAdminRoleException e) {
                    return "LOCKOUT";
                  }
                });

    executor.shutdown();
    boolean terminated = executor.awaitTermination(15, TimeUnit.SECONDS);
    assertThat(terminated).as("both threads must complete within the timeout").isTrue();

    // future.get() rethrows for anything NOT already caught above -- any unexpected exception
    // type (e.g. a raw DataAccessException) fails this test loudly.
    String outcome1 = revokeAdminOwnRow.get();
    String outcome2 = revokeDangerousHolderOwnRow.get();
    List<String> outcomes = List.of(outcome1, outcome2);

    assertThat(outcomes.stream().filter("SUCCESS"::equals).count())
        .as("exactly one of the two revokes must win the lock race and succeed: " + outcomes)
        .isEqualTo(1L);
    assertThat(outcomes.stream().filter("LOCKOUT"::equals).count())
        .as(
            "the other must be blocked -- revoking BOTH would zero the tenant's distinct"
                + " admin-equivalent holders across two DIFFERENT roles, exactly the defect D5's"
                + " cross-role holder counting exists to prevent: "
                + outcomes)
        .isEqualTo(1L);
    assertThat(
            countDistinctAdminEquivalentHolders(
                tenantId, List.of(adminRole.getId(), dangerousRole.getId())))
        .as("the tenant must retain exactly one distinct admin-equivalent holder after the race")
        .isEqualTo(1);
  }

  // ── H-1 regression (06-code-review.md, 2026-09-24): an ANY-only holder must never count ──

  /**
   * Reproduces the exact H-1 finding against a real database. {@code admin} is the tenant's SOLE
   * literal {@code TENANT_ADMIN}; {@code anyOnlyHolder} holds a SEPARATE custom role carrying only
   * ONE dangerous permission ({@code user:write}) -- ANY-qualifying (so it's part of M11's lock
   * set and the pre-fix distinct-holder count), but NOT caller-qualifying (it can never pass {@code
   * requireCallerHoldsAdminEquivalentRole}). Before the fix, {@code anyOnlyHolder} counted as a
   * "remaining admin" for the lockout guard, so {@code admin}'s self-revocation of the tenant's
   * ONLY caller-qualifying role would have SUCCEEDED (204) -- silently bricking the tenant's
   * ability to ever administer itself again, while {@code RbacZeroActiveAdminsHealthIndicator}
   * (also ANY-based, pre-fix) kept reporting healthy. After the fix, the lockout guard restricts
   * the distinct-holder check to the caller-qualifying subset of what M11 locked, so this
   * self-revocation must now be BLOCKED (409 {@code RBAC_002}).
   */
  @Test
  void should_blockSelfRevoke_when_onlyRemainingHolderIsAnyQualifyingButNotCallerQualifying_H1()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "h1");
    User admin = seedUser(tenantId, "h1-admin");
    seedActiveAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    // ONE dangerous permission only -- ANY-qualifying, NOT caller-qualifying (H-1).
    Role anyOnlyRole = seedRole(tenantId, "H1-ANY-ONLY", "h1");
    grantPermission(anyOnlyRole.getId(), USER_WRITE_PERMISSION_ID);
    User anyOnlyHolder = seedUser(tenantId, "h1-any-only-holder");
    seedActiveAssignment(tenantId, anyOnlyRole.getId(), anyOnlyHolder.getId(), admin.getId());

    RoleChangeActor adminActor = new RoleChangeActor(admin.getId(), tenantId);

    assertThat(
            org.assertj.core.api.Assertions.catchThrowable(
                () ->
                    roleAssignmentService.revoke(
                        adminActor, admin.getId(), adminRole.getId(), requestContext())))
        .as("admin is the tenant's sole CALLER-QUALIFYING holder -- the ANY-only holder must not"
            + " count as a remaining admin, so this self-revocation must be blocked")
        .isInstanceOf(LastAdminRoleException.class);

    assertThat(
            countDistinctAdminEquivalentHolders(
                tenantId, List.of(adminRole.getId(), anyOnlyRole.getId())))
        .as("both rows must remain active -- the blocked revoke must not have committed")
        .isEqualTo(2);
  }

  // ── (e) Cross-tenant: M11's union lock never crosses a tenant boundary ──────────────────

  /**
   * US-017 T-007(e) (T-S1, T-I16): M11 carries no {@code Role} join and is driven off a role-id
   * IN-list the caller builds from a TENANT-SCOPED M10 read (§7.2) — tenant containment is
   * therefore NOT a property of the role-id set alone, but of the role-id set being tenant-derived
   * PLUS {@code tenant_id} remaining a residual predicate in M11's own SQL. This test proves the
   * residual predicate is real, not decorative: it deliberately constructs the adversarial input a
   * hypothetical application-layer tenant-scoping bug would produce — a role-id list spanning TWO
   * tenants — and calls the port method M11 directly (never the service, which would never
   * construct such a list itself), confirming the returned holders stay bounded to the ONE tenant
   * id passed in, never leaking the other tenant's row.
   */
  @Test
  void should_neverLockOrCountAnotherTenantsRow_when_m11sRoleIdSetSpansTenants() {
    UUID tenantA = uuidGenerator.newId();
    Role dangerousRoleA = seedRole(tenantA, "XTENANT-DANGEROUS-A", "xtenant");
    grantPermission(dangerousRoleA.getId(), ROLE_WRITE_PERMISSION_ID);
    User holderA = seedUser(tenantA, "xtenant-holder-a");
    seedActiveAssignment(tenantA, dangerousRoleA.getId(), holderA.getId(), holderA.getId());

    UUID tenantB = uuidGenerator.newId();
    Role dangerousRoleB = seedRole(tenantB, "XTENANT-DANGEROUS-B", "xtenant");
    grantPermission(dangerousRoleB.getId(), ROLE_WRITE_PERMISSION_ID);
    User holderB = seedUser(tenantB, "xtenant-holder-b");
    seedActiveAssignment(tenantB, dangerousRoleB.getId(), holderB.getId(), holderB.getId());

    // Deliberately adversarial: a role-id list spanning BOTH tenants, passed with tenantA as the
    // bound tenant id -- exactly what a hypothetical tenant-scoping bug upstream could produce.
    List<ActiveAssignmentHolder> lockedHolders =
        userRoleAssignmentPort.lockActiveAssignmentHolders(
            tenantA, List.of(dangerousRoleA.getId(), dangerousRoleB.getId()));

    assertThat(lockedHolders)
        .as(
            "M11 must never return tenant B's row when bound to tenant A's id, even though"
                + " tenant B's role id was included in the roleIds list: "
                + lockedHolders)
        .extracting(ActiveAssignmentHolder::userId)
        .containsExactly(holderA.getId());
  }

  // ── Shared seeding helpers (mirrors LastAdminLockoutIT's identically-named helpers) ──────

  private User seedUser(UUID tenantId, String tag) {
    String email = "ael-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }

  private Role seedTenantAdminRole(UUID tenantId, String tag) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, "TENANT_ADMIN", tag, false));
  }

  private Role seedRole(UUID tenantId, String name, String tag) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, name, tag, false));
  }

  private void grantPermission(UUID roleId, UUID permissionId) {
    rolePermissionRepository.save(new RolePermission(roleId, permissionId));
  }

  private UserRole seedActiveAssignment(
      UUID tenantId, UUID roleId, UUID assigneeId, UUID assignedById) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), assigneeId, roleId, tenantId, assignedById));
  }

  private RequestContext requestContext() {
    return RequestContext.of(
        "127.0.0.1", "trace-" + UUID.randomUUID(), "AdminEquivalentLockoutIT");
  }

  private int countDistinctAdminEquivalentHolders(UUID tenantId, List<UUID> roleIds) {
    String placeholders = String.join(",", Collections.nCopies(roleIds.size(), "?"));
    List<Object> params = new ArrayList<>();
    roleIds.forEach(id -> params.add(toBytes(id)));
    params.add(toBytes(tenantId));
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(DISTINCT user_id) FROM user_roles WHERE role_id IN (" + placeholders
                + ") AND tenant_id = ? AND revoked_at IS NULL",
            Integer.class,
            params.toArray());
    return count == null ? 0 : count;
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
