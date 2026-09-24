package com.example.nexus.rbac.infrastructure.health;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.RbacAdminEquivalence;
import com.example.nexus.rbac.domain.RbacDangerousPermissions;
import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

/**
 * US-017 T-006(g): MC-I (design §11.2 MC-I, RC-18.2, RES-23) -- the mechanical proof that D12's
 * inline SQL (FR-2's {@code r.name = :adminRoleName OR (COUNT(DISTINCT p.name) = :count)}) and the
 * Java combinator ({@code RbacAdminEquivalence.isFullyAdminEquivalent} /
 * {@code RbacDangerousPermissions.carriesAll}) have not silently drifted apart. The shared origin
 * {@code RbacDangerousPermissions.NAMES} crosses into SQL as a bind parameter and propagates
 * automatically; the *combinator* (the OR / COUNT shape itself) does not -- this is what stands in
 * for it.
 *
 * <p><b>Re-scoped post-06-code-review.md H-1 (2026-09-24)</b> from the ANY-admin-equivalent
 * predicate ({@code isAdminEquivalent}/{@code carriesAny}) to the caller-qualifying ALL predicate
 * ({@code isFullyAdminEquivalent}/{@code carriesAll}) -- FR-2's queries themselves moved to this
 * predicate (see {@code ZeroAdminTenantReader}'s Javadoc), so this equivalence proof must track
 * the same population the shipped SQL now actually computes.
 *
 * <p>Fixture matrix, one role per tenant (tenant-scoped isolation, so this test's own fixtures are
 * never polluted by another test's tenants): zero permissions; one/two dangerous permissions
 * (ANY-only, must stay INVISIBLE under the new ALL predicate); all-three dangerous permissions,
 * with and without a holder; only a benign permission; the literal {@code TENANT_ADMIN} with zero
 * permissions; and a case-variant permission-name equivalence proof (see {@link
 * #should_agreeOnCaseInsensitiveMembership_whenDangerousNamesAreCaseVaried_MCI()}'s own Javadoc
 * for why that case cannot be exercised via a genuinely case-differing STORED permission row).
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class AdminEquivalenceSqlJavaEquivalenceIT {

  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private UuidGenerator uuidGenerator;

  private static final UUID TENANT_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1801-7000-8000-000000000002");
  private static final UUID USER_READ_PERMISSION_ID =
      UUID.fromString("019f6839-1802-7000-8000-000000000003");
  private static final UUID USER_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1803-7000-8000-000000000004");
  private static final UUID ROLE_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1805-7000-8000-000000000006");

  /**
   * MC-I main fixture matrix: for each tenant below, the SQL-computed "caller-qualifying role with
   * NO active holder" verdict (FR-2's two queries, differenced) must equal the Java-computed
   * verdict ({@code RbacAdminEquivalence.isFullyAdminEquivalent} combined with an independent,
   * directly-queried active-holder check) -- computed independently, never by calling one from
   * the other.
   */
  @Test
  void should_agreeWithJavaCombinator_acrossFixtureMatrix_MCI() {
    // Tenant 1: zero-permission role, no holder -- invisible to BOTH sides (D11): never in the
    // driving set at all, so it is neither UP nor DOWN, and must not appear in either query's
    // result.
    UUID tenantZeroPerm = uuidGenerator.newId();
    Role roleZeroPerm = seedRole(tenantZeroPerm, "MCI-ZERO-PERM");
    User holderZeroPerm = seedUser(tenantZeroPerm, "mci-zero");
    seedActiveAssignment(tenantZeroPerm, roleZeroPerm.getId(), holderZeroPerm.getId());

    // Tenant 2 (H-1): ONE dangerous permission only -- ANY-qualifying, NOT caller-qualifying.
    // Must stay INVISIBLE under the new ALL predicate, active holder or not.
    UUID tenantOneDangerousAnyOnly = uuidGenerator.newId();
    Role roleOneDangerous = seedRole(tenantOneDangerousAnyOnly, "MCI-ONE-DANGEROUS");
    grantPermission(roleOneDangerous.getId(), ROLE_WRITE_PERMISSION_ID);
    User holderOneDangerous = seedUser(tenantOneDangerousAnyOnly, "mci-one");
    seedActiveAssignment(tenantOneDangerousAnyOnly, roleOneDangerous.getId(), holderOneDangerous.getId());

    // Tenant 3 (H-1): TWO of three dangerous permissions -- still ANY-only, not ALL. Must also
    // stay INVISIBLE under the new predicate, even though its one assignment is revoked (it was
    // never in the driving set to begin with, so "revoked" is irrelevant to this tenant's verdict).
    UUID tenantTwoDangerousAnyOnly = uuidGenerator.newId();
    Role roleTwoDangerous = seedRole(tenantTwoDangerousAnyOnly, "MCI-TWO-DANGEROUS");
    grantPermission(roleTwoDangerous.getId(), ROLE_WRITE_PERMISSION_ID);
    grantPermission(roleTwoDangerous.getId(), USER_WRITE_PERMISSION_ID);
    User revokedHolder = seedUser(tenantTwoDangerousAnyOnly, "mci-two");
    seedRevokedAssignment(tenantTwoDangerousAnyOnly, roleTwoDangerous.getId(), revokedHolder.getId());

    // Tenant 4: all three dangerous permissions, active holder present -- UP.
    UUID tenantAllDangerousUp = uuidGenerator.newId();
    Role roleAllDangerous = seedRole(tenantAllDangerousUp, "MCI-ALL-DANGEROUS-UP");
    grantPermission(roleAllDangerous.getId(), ROLE_WRITE_PERMISSION_ID);
    grantPermission(roleAllDangerous.getId(), USER_WRITE_PERMISSION_ID);
    grantPermission(roleAllDangerous.getId(), TENANT_WRITE_PERMISSION_ID);
    User holderAllDangerous = seedUser(tenantAllDangerousUp, "mci-all-up");
    seedActiveAssignment(tenantAllDangerousUp, roleAllDangerous.getId(), holderAllDangerous.getId());

    // Tenant 4b: all three dangerous permissions, NO active holder (revoked) -- DOWN. This is now
    // the DOWN fixture (tenants 2/3 no longer qualify for DOWN since they never enter the driving
    // set at all post-H-1).
    UUID tenantAllDangerousDown = uuidGenerator.newId();
    Role roleAllDangerousDown = seedRole(tenantAllDangerousDown, "MCI-ALL-DANGEROUS-DOWN");
    grantPermission(roleAllDangerousDown.getId(), ROLE_WRITE_PERMISSION_ID);
    grantPermission(roleAllDangerousDown.getId(), USER_WRITE_PERMISSION_ID);
    grantPermission(roleAllDangerousDown.getId(), TENANT_WRITE_PERMISSION_ID);
    User revokedAllHolder = seedUser(tenantAllDangerousDown, "mci-all-down");
    seedRevokedAssignment(tenantAllDangerousDown, roleAllDangerousDown.getId(), revokedAllHolder.getId());

    // Tenant 5: only a benign permission (user:read) -- never caller-qualifying, invisible.
    UUID tenantBenignOnly = uuidGenerator.newId();
    Role roleBenign = seedRole(tenantBenignOnly, "MCI-BENIGN-ONLY");
    grantPermission(roleBenign.getId(), USER_READ_PERMISSION_ID);
    User holderBenign = seedUser(tenantBenignOnly, "mci-benign");
    seedActiveAssignment(tenantBenignOnly, roleBenign.getId(), holderBenign.getId());

    // Tenant 6: the literal TENANT_ADMIN, zero permissions, active holder -- UP via name-match,
    // not permission content (D9's other half).
    UUID tenantLiteralAdminUp = uuidGenerator.newId();
    Role roleLiteralAdmin = seedRole(tenantLiteralAdminUp, RbacRoleNames.TENANT_ADMIN);
    User holderLiteralAdmin = seedUser(tenantLiteralAdminUp, "mci-literal");
    seedActiveAssignment(tenantLiteralAdminUp, roleLiteralAdmin.getId(), holderLiteralAdmin.getId());

    // Tenant 7: the tenant-level UP case FR-2's two-query design exists to get right -- the
    // literal TENANT_ADMIN has a holder, a SEPARATE fully-dangerous (ALL THREE) custom role does
    // not. A role-level NOT EXISTS would (wrongly) call this DOWN for the custom role; the
    // tenant-level question must say UP.
    UUID tenantMixedUp = uuidGenerator.newId();
    Role literalWithHolder = seedRole(tenantMixedUp, RbacRoleNames.TENANT_ADMIN);
    User literalHolder = seedUser(tenantMixedUp, "mci-mixed-literal");
    seedActiveAssignment(tenantMixedUp, literalWithHolder.getId(), literalHolder.getId());
    Role customWithoutHolder = seedRole(tenantMixedUp, "MCI-MIXED-CUSTOM");
    grantPermission(customWithoutHolder.getId(), ROLE_WRITE_PERMISSION_ID);
    grantPermission(customWithoutHolder.getId(), USER_WRITE_PERMISSION_ID);
    grantPermission(customWithoutHolder.getId(), TENANT_WRITE_PERMISSION_ID);
    User revokedMixedHolder = seedUser(tenantMixedUp, "mci-mixed-custom");
    seedRevokedAssignment(tenantMixedUp, customWithoutHolder.getId(), revokedMixedHolder.getId());

    Set<UUID> ourTenants =
        Set.of(
            tenantZeroPerm,
            tenantOneDangerousAnyOnly,
            tenantTwoDangerousAnyOnly,
            tenantAllDangerousUp,
            tenantAllDangerousDown,
            tenantBenignOnly,
            tenantLiteralAdminUp,
            tenantMixedUp);

    // ── SQL side: FR-2's two queries, restricted to OUR fixture tenants only ─────────────────
    long dangerousNamesCount = RbacDangerousPermissions.NAMES.size();
    Set<UUID> sqlDrivingSet =
        new HashSet<>(
            userRoleRepository.findTenantsWithAFullyAdminEquivalentRole(
                RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, dangerousNamesCount));
    sqlDrivingSet.retainAll(ourTenants);
    Set<UUID> sqlHasHolderSet =
        new HashSet<>(
            userRoleRepository.findTenantsWithActiveFullyAdminEquivalentHolders(
                RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, dangerousNamesCount));
    sqlHasHolderSet.retainAll(ourTenants);
    Set<UUID> sqlAffected = new HashSet<>(sqlDrivingSet);
    sqlAffected.removeAll(sqlHasHolderSet);

    // ── Java side: independently computed from the same fixture, via RbacAdminEquivalence,
    // never by reusing the SQL result above ────────────────────────────────────────────────
    Set<UUID> javaDrivingSet = new HashSet<>();
    Set<UUID> javaHasHolderSet = new HashSet<>();
    for (UUID tenantId : ourTenants) {
      for (var roleView : roleRepository.findRoleViewsByTenantId(tenantId)) {
        List<String> permissionNames = roleRepository.findPermissionNamesByRole(roleView.id());
        if (!RbacAdminEquivalence.isFullyAdminEquivalent(roleView.name(), permissionNames)) {
          continue;
        }
        javaDrivingSet.add(tenantId);
        boolean hasActiveHolder =
            userRoleRepository.findActiveUserIdsByRole(roleView.id()).stream().findAny().isPresent();
        if (hasActiveHolder) {
          javaHasHolderSet.add(tenantId);
        }
      }
    }
    Set<UUID> javaAffected = new HashSet<>(javaDrivingSet);
    javaAffected.removeAll(javaHasHolderSet);

    assertThat(sqlDrivingSet)
        .as("SQL's driving set (FR-2(a)) must equal the Java-computed driving set")
        .isEqualTo(javaDrivingSet)
        .as("and must be exactly the four tenants carrying a caller-qualifying role -- the two"
            + " ANY-only tenants (2, 3) must NOT appear, post-H-1")
        .isEqualTo(
            Set.of(
                tenantAllDangerousUp,
                tenantAllDangerousDown,
                tenantLiteralAdminUp,
                tenantMixedUp));
    assertThat(sqlAffected)
        .as("SQL's affected (DOWN) set must equal the Java-computed affected set")
        .isEqualTo(javaAffected)
        .as("and must be exactly the tenant whose only caller-qualifying role was zeroed")
        .isEqualTo(Set.of(tenantAllDangerousDown));
  }

  /**
   * MC-I's case-variant sub-proof (Risk (g)). A genuinely case-differing STORED permission row
   * (e.g. {@code "Role:Write"} alongside the seeded {@code "role:write"}) cannot be created: {@code
   * uq_permissions_name} is declared under this table's {@code utf8mb4_0900_ai_ci} collation, so
   * MySQL itself would reject the insert as a duplicate of the seeded row -- the two are
   * genuinely unreachable as DISTINCT stored rows, exactly as the design's own threat model
   * states. What CAN drift is the two independent CASE-INSENSITIVITY MECHANISMS themselves: MySQL
   * IN-list membership under {@code _ai_ci} collation, versus Java's {@code equalsIgnoreCase}. This
   * proves both mechanisms still agree that a case-varied name list ({@code "ROLE:WRITE"} in
   * place of {@code "role:write"}) matches the ACTUAL, standard-cased stored permission -- the
   * exact residual divergence T-T15 names (Java {@code equalsIgnoreCase} vs. {@code
   * utf8mb4_0900_ai_ci}'s ADDITIONAL accent-insensitivity) would surface here first if a future
   * schema or NAMES-set change ever made it reachable.
   */
  @Test
  void should_agreeOnCaseInsensitiveMembership_whenDangerousNamesAreCaseVaried_MCI() {
    UUID tenantId = uuidGenerator.newId();
    Role role = seedRole(tenantId, "MCI-CASE-VARIANT");
    // ALL THREE, standard case, stored as "role:write"/"user:write"/"tenant:write" -- the query
    // now requires ALL three (COUNT(DISTINCT) = 3), so this fixture must carry all three for the
    // case-varied literal list below to find it at all.
    grantPermission(role.getId(), ROLE_WRITE_PERMISSION_ID);
    grantPermission(role.getId(), USER_WRITE_PERMISSION_ID);
    grantPermission(role.getId(), TENANT_WRITE_PERMISSION_ID);
    User holder = seedUser(tenantId, "mci-case-variant");
    seedActiveAssignment(tenantId, role.getId(), holder.getId());

    Set<String> caseVariedNames = Set.of("ROLE:WRITE", "USER:WRITE", "TENANT:WRITE");
    List<String> storedPermissionNames = roleRepository.findPermissionNamesByRole(role.getId());

    // SQL side: the query is handed the UPPER-case literal list; the stored permissions are the
    // standard lower-case names -- membership must still be found (all three) under this table's
    // utf8mb4_0900_ai_ci collation.
    List<UUID> sqlResult =
        userRoleRepository.findTenantsWithAFullyAdminEquivalentRole(
            RbacRoleNames.TENANT_ADMIN, caseVariedNames, caseVariedNames.size());

    // Java side: the SAME upper-case literal, checked against the actual stored names via
    // equalsIgnoreCase -- the mechanism RbacDangerousPermissions.carriesAll() itself uses.
    boolean javaAgrees =
        caseVariedNames.stream()
            .allMatch(
                name -> storedPermissionNames.stream().anyMatch(name::equalsIgnoreCase));

    assertThat(storedPermissionNames)
        .containsExactlyInAnyOrder("role:write", "user:write", "tenant:write");
    assertThat(sqlResult)
        .as("MySQL's IN-list membership under utf8mb4_0900_ai_ci must match all three stored"
            + " lower-case permissions against an upper-case literal list")
        .contains(tenantId);
    assertThat(javaAgrees)
        .as("Java's equalsIgnoreCase must agree with MySQL's collation on the same case pairs")
        .isTrue();
  }

  private Role seedRole(UUID tenantId, String name) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, name, "mci", false));
  }

  private void grantPermission(UUID roleId, UUID permissionId) {
    rolePermissionRepository.save(new RolePermission(roleId, permissionId));
  }

  private User seedUser(UUID tenantId, String tag) {
    String email = "mci-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }

  private void seedActiveAssignment(UUID tenantId, UUID roleId, UUID userId) {
    userRoleRepository.save(new UserRole(uuidGenerator.newId(), userId, roleId, tenantId, userId));
  }

  private void seedRevokedAssignment(UUID tenantId, UUID roleId, UUID userId) {
    // assigned_at is DB-generated (CURRENT_TIMESTAMP(6) at INSERT) -- it must be committed via a
    // flush before revoke() sets revoked_at, or chk_user_roles_revoked_not_before_assigned can
    // fail: revoked_at would be stamped from Instant.now() before the DB-side assigned_at exists.
    UserRole userRole = new UserRole(uuidGenerator.newId(), userId, roleId, tenantId, userId);
    userRoleRepository.saveAndFlush(userRole);
    userRole.revoke(java.time.Instant.now());
    userRoleRepository.saveAndFlush(userRole);
  }
}
