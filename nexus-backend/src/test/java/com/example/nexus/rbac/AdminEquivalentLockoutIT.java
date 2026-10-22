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
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
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
 * US-017 T-007(a)/(e) (04-tasks.md; 03-design.md §11.3, A-4), re-cast by US-018 T-016 (ledger row
 * 3, 04-tasks.md "AdminEquivalentLockoutIT becomes admin-defining cases"): a dedicated class (per
 * A-4, not an extension of the already-1000+-line {@link LastAdminLockoutIT}) exercising the
 * cross-role, distinct-HOLDER (not distinct-ROW) counting under a genuine concurrent race — the
 * story's central risk — and (e) proving M11's lock set never crosses a tenant boundary, even when
 * fed a deliberately cross-tenant role-id list.
 *
 * <p><b>The population is now admin-defining roles</b> (ADR-0021 D6): a role is in the lockout
 * population iff it carries every permission of the catalogue. The former H-1 case (a role with
 * one dangerous permission must not count) is re-cast as "a role one permission short of the
 * catalogue must not count"; the former "caller-qualifying via all three dangerous permissions"
 * custom role is a custom admin-defining role.
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
   * Seeds ONE tenant with exactly TWO distinct administrators across TWO DIFFERENT admin-defining
   * roles: {@code admin} holds {@code TENANT_ADMIN}, and {@code customHolder} holds a separate
   * custom role that also carries the whole catalogue. No other administrator exists in this
   * tenant. Two threads fire concurrently via a {@link CyclicBarrier}, EACH a SELF-revocation
   * ({@code admin} revoking their own {@code TENANT_ADMIN} row; {@code customHolder} revoking their
   * own custom-role row) — deliberately not one actor revoking the other, so that each thread's
   * administrator requirement (decided from M11's rows, inside the lock) depends only on that
   * thread's OWN row, never on whether the OTHER thread has already committed.
   *
   * <p>A single-role, single-user fixture (Harness A/B in {@code LastAdminLockoutIT}) cannot
   * distinguish row-counting from holder-counting — the defect is specifically that a naive
   * per-role {@code size() <= 1} check would see "role A has 1 holder" and "role B has 1 holder"
   * independently and let BOTH revocations through, zeroing the tenant. M11's set lock is built
   * from the SAME tenant-wide admin-defining role-id set regardless of which specific role either
   * thread targets, so these two transactions genuinely contend for the same lock range: exactly
   * ONE thread's lockout check must see the OTHER holder still active (succeeds) and the other
   * must see the holder count would drop to zero (blocked, 409 {@code RBAC_002}) — deterministic
   * regardless of which thread wins the lock race, since both lock the SAME two-row range in the
   * SAME acquisition order (no deadlock is possible here; this is pure serialization, exactly
   * Harness A's shape). Any other exception type fails this test loudly, exactly as {@code
   * LastAdminLockoutIT}'s harnesses do.
   */
  @Test
  void
      should_blockExactlyOneOfTwoConcurrentRevokes_when_theyWouldJointlyZeroTheTenantsDistinctAdministrators()
          throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "cross-role");
    User admin = seedUser(tenantId, "cross-role-admin");
    seedActiveAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    // A custom role carrying the whole catalogue: admin-defining by its permissions alone.
    Role dangerousRole = seedRole(tenantId, "CROSS-ROLE-CUSTOM-ADMIN", "cross-role");
    grantWholeCatalogue(dangerousRole.getId());
    User dangerousHolder = seedUser(tenantId, "cross-role-custom-holder");
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
                + " administrators across two DIFFERENT roles, exactly the defect the cross-role"
                + " holder counting exists to prevent: "
                + outcomes)
        .isEqualTo(1L);
    assertThat(
            countDistinctAdminEquivalentHolders(
                tenantId, List.of(adminRole.getId(), dangerousRole.getId())))
        .as("the tenant must retain exactly one distinct administrator after the race")
        .isEqualTo(1);
  }

  // ── Re-cast H-1: a holder of a role one permission short must never count ────────────────

  /**
   * The former H-1 regression, re-cast for the one definition of "administrator". {@code admin} is
   * the tenant's SOLE holder of an admin-defining role ({@code TENANT_ADMIN}); {@code
   * almostHolder} holds a SEPARATE custom role carrying every catalogue permission except one. That
   * role is not admin-defining, so it is outside the lockout population: {@code admin}'s
   * self-revocation of the tenant's ONLY admin-defining assignment must be BLOCKED (409 {@code
   * RBAC_002}), not allowed because "someone with nearly everything remains".
   */
  @Test
  void should_blockSelfRevoke_when_theOnlyOtherHolderHoldsARoleOnePermissionShortOfTheCatalogue()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedTenantAdminRole(tenantId, "h1");
    User admin = seedUser(tenantId, "h1-admin");
    seedActiveAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    Role almostRole = seedRole(tenantId, "H1-ALMOST-ADMIN", "h1");
    grantWholeCatalogueExceptOne(almostRole.getId());
    User almostHolder = seedUser(tenantId, "h1-almost-holder");
    seedActiveAssignment(tenantId, almostRole.getId(), almostHolder.getId(), admin.getId());

    RoleChangeActor adminActor = new RoleChangeActor(admin.getId(), tenantId);

    assertThat(
            org.assertj.core.api.Assertions.catchThrowable(
                () ->
                    roleAssignmentService.revoke(
                        adminActor, admin.getId(), adminRole.getId(), requestContext())))
        .as("admin is the tenant's sole administrator -- a holder of a role one permission short"
            + " of the catalogue must not count as a remaining one, so this self-revocation must"
            + " be blocked")
        .isInstanceOf(LastAdminRoleException.class);

    assertThat(
            countDistinctAdminEquivalentHolders(
                tenantId, List.of(adminRole.getId(), almostRole.getId())))
        .as("both rows must remain active -- the blocked revoke must not have committed")
        .isEqualTo(2);
  }

  /**
   * Names do not matter: a tenant whose only administrator holds a CUSTOM admin-defining role is
   * protected exactly like one whose administrator holds {@code TENANT_ADMIN}. (Before M3 the
   * custom role had to carry all three dangerous permissions to be in the population at all.)
   */
  @Test
  void should_blockSelfRevoke_when_theOnlyAdministratorHoldsACustomAdminDefiningRole() {
    UUID tenantId = uuidGenerator.newId();
    Role customAdminRole = seedRole(tenantId, "ONLY-CUSTOM-ADMIN", "custom-only");
    grantWholeCatalogue(customAdminRole.getId());
    User admin = seedUser(tenantId, "custom-only-admin");
    seedActiveAssignment(tenantId, customAdminRole.getId(), admin.getId(), admin.getId());
    RoleChangeActor adminActor = new RoleChangeActor(admin.getId(), tenantId);

    assertThat(
            org.assertj.core.api.Assertions.catchThrowable(
                () ->
                    roleAssignmentService.revoke(
                        adminActor, admin.getId(), customAdminRole.getId(), requestContext())))
        .isInstanceOf(LastAdminRoleException.class);

    assertThat(countDistinctAdminEquivalentHolders(tenantId, List.of(customAdminRole.getId())))
        .isEqualTo(1);
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

  /**
   * A role literally named {@code TENANT_ADMIN} that carries the whole permission catalogue, as the
   * real one does (V5 seed plus the B7 footer from V6 on): admin-defining by its permissions, and
   * it includes {@code user:role:assign}, which the revoking caller's fresh M13 holdings must still
   * contain (07-security-review.md L-1).
   */
  private Role seedTenantAdminRole(UUID tenantId, String tag) {
    Role role =
        roleRepository.save(new Role(uuidGenerator.newId(), tenantId, "TENANT_ADMIN", tag, false));
    grantWholeCatalogue(role.getId());
    return role;
  }

  /** Makes {@code roleId} admin-defining (ADR-0021 D3): attaches every catalogue permission. */
  private void grantWholeCatalogue(UUID roleId) {
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions",
        roleId.toString());
  }

  /** Attaches every catalogue permission except one: one permission short of admin-defining. */
  private void grantWholeCatalogueExceptOne(UUID roleId) {
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions "
            + "WHERE id <> UUID_TO_BIN(?)",
        roleId.toString(),
        RbacSeededPermissionIds.ROLE_WRITE.toString());
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
