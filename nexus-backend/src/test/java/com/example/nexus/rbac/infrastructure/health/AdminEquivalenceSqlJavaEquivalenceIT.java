package com.example.nexus.rbac.infrastructure.health;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.RbacAdministrators;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaPermissionCatalogueRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

/**
 * US-018 T-019 (row 15, row 17): MC-I, re-targeted. The mechanical proof that the zero-admin
 * indicator's inline SQL (a role is admin-defining iff {@code COUNT(DISTINCT permission)} equals the
 * catalogue count) and the Java definition ({@link RbacAdministrators#adminDefiningRoleIds} over
 * M10' and M15) have not silently drifted apart. Both are computed independently from the same
 * fixture, never by calling one from the other.
 *
 * <p>This replaces the US-017 equivalence of {@code RbacAdminEquivalence.isFullyAdminEquivalent}
 * with the name-or-three-permissions SQL, and the case-variant sub-proof, which compared two
 * case-insensitivity mechanisms for permission NAMES: no name reaches the SQL or the definition
 * any more, so that divergence cannot exist (ADR-0021 D3).
 *
 * <p>Fixture matrix, one tenant each (so another test's tenants never pollute the verdict): a
 * zero-permission role; a role one permission short, with and without an active holder; the whole
 * catalogue with an active holder; the whole catalogue with only a revoked holder; a benign role;
 * a role literally named {@code TENANT_ADMIN} that carries nothing; and a tenant with two
 * admin-defining roles of which only one has a holder.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class AdminEquivalenceSqlJavaEquivalenceIT {

  private static final UUID USER_READ_PERMISSION_ID =
      UUID.fromString("019f6839-1802-7000-8000-000000000003");

  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaPermissionCatalogueRepository permissionCatalogueRepository;
  @Autowired private UuidGenerator uuidGenerator;

  @Test
  void should_agreeWithJavaDefinition_acrossFixtureMatrix_MCI() {
    Set<UUID> catalogue = permissionCatalogueRepository.findCatalogueIds();
    assertThat(catalogue).as("the catalogue must be readable and non-empty").isNotEmpty();

    UUID tenantZeroPerm = uuidGenerator.newId();
    Role roleZeroPerm = seedRole(tenantZeroPerm, "MCI-ZERO-PERM");
    seedActiveAssignment(tenantZeroPerm, roleZeroPerm.getId(), seedUser(tenantZeroPerm, "zero"));

    UUID tenantOneShortActive = uuidGenerator.newId();
    Role roleOneShort = seedRole(tenantOneShortActive, "MCI-ONE-SHORT");
    grantAllBut(roleOneShort.getId(), catalogue, 1);
    seedActiveAssignment(
        tenantOneShortActive, roleOneShort.getId(), seedUser(tenantOneShortActive, "short"));

    UUID tenantOneShortRevoked = uuidGenerator.newId();
    Role roleOneShortRevoked = seedRole(tenantOneShortRevoked, "MCI-ONE-SHORT-REVOKED");
    grantAllBut(roleOneShortRevoked.getId(), catalogue, 1);
    seedRevokedAssignment(
        tenantOneShortRevoked,
        roleOneShortRevoked.getId(),
        seedUser(tenantOneShortRevoked, "short-revoked"));

    UUID tenantWholeUp = uuidGenerator.newId();
    Role roleWhole = seedRole(tenantWholeUp, "MCI-WHOLE-UP");
    grantAllBut(roleWhole.getId(), catalogue, 0);
    seedActiveAssignment(tenantWholeUp, roleWhole.getId(), seedUser(tenantWholeUp, "whole-up"));

    UUID tenantWholeDown = uuidGenerator.newId();
    Role roleWholeDown = seedRole(tenantWholeDown, "MCI-WHOLE-DOWN");
    grantAllBut(roleWholeDown.getId(), catalogue, 0);
    seedRevokedAssignment(
        tenantWholeDown, roleWholeDown.getId(), seedUser(tenantWholeDown, "whole-down"));

    UUID tenantBenign = uuidGenerator.newId();
    Role roleBenign = seedRole(tenantBenign, "MCI-BENIGN");
    grantPermission(roleBenign.getId(), USER_READ_PERMISSION_ID);
    seedActiveAssignment(tenantBenign, roleBenign.getId(), seedUser(tenantBenign, "benign"));

    UUID tenantNamedOnly = uuidGenerator.newId();
    Role roleNamedOnly = seedRole(tenantNamedOnly, "TENANT_ADMIN");
    seedActiveAssignment(tenantNamedOnly, roleNamedOnly.getId(), seedUser(tenantNamedOnly, "named"));

    UUID tenantMixed = uuidGenerator.newId();
    Role mixedWithHolder = seedRole(tenantMixed, "MCI-MIXED-A");
    grantAllBut(mixedWithHolder.getId(), catalogue, 0);
    seedActiveAssignment(tenantMixed, mixedWithHolder.getId(), seedUser(tenantMixed, "mixed-a"));
    Role mixedWithoutHolder = seedRole(tenantMixed, "MCI-MIXED-B");
    grantAllBut(mixedWithoutHolder.getId(), catalogue, 0);
    seedRevokedAssignment(
        tenantMixed, mixedWithoutHolder.getId(), seedUser(tenantMixed, "mixed-b"));

    Set<UUID> ourTenants =
        Set.of(
            tenantZeroPerm,
            tenantOneShortActive,
            tenantOneShortRevoked,
            tenantWholeUp,
            tenantWholeDown,
            tenantBenign,
            tenantNamedOnly,
            tenantMixed);

    // SQL side: the indicator's two queries, restricted to OUR fixture tenants only.
    Set<UUID> sqlDrivingSet = new HashSet<>(userRoleRepository.findTenantsWithAnAdminDefiningRole());
    sqlDrivingSet.retainAll(ourTenants);
    Set<UUID> sqlHasHolderSet =
        new HashSet<>(userRoleRepository.findTenantsWithActiveAdminDefiningHolders());
    sqlHasHolderSet.retainAll(ourTenants);
    Set<UUID> sqlAffected = new HashSet<>(sqlDrivingSet);
    sqlAffected.removeAll(sqlHasHolderSet);

    // Java side: RbacAdministrators over M10' and the catalogue, plus an independent holder query.
    Set<UUID> javaDrivingSet = new HashSet<>();
    Set<UUID> javaHasHolderSet = new HashSet<>();
    for (UUID tenantId : ourTenants) {
      Set<UUID> adminDefiningRoleIds =
          RbacAdministrators.adminDefiningRoleIds(
              roleRepository.findRolePermissionIdsByTenantRoles(tenantId), catalogue);
      if (adminDefiningRoleIds.isEmpty()) {
        continue;
      }
      javaDrivingSet.add(tenantId);
      boolean hasActiveHolder =
          adminDefiningRoleIds.stream()
              .anyMatch(
                  roleId -> !userRoleRepository.findActiveUserIdsByRole(roleId).isEmpty());
      if (hasActiveHolder) {
        javaHasHolderSet.add(tenantId);
      }
    }
    Set<UUID> javaAffected = new HashSet<>(javaDrivingSet);
    javaAffected.removeAll(javaHasHolderSet);

    assertThat(sqlDrivingSet)
        .as("SQL's driving set must equal the Java-computed driving set")
        .isEqualTo(javaDrivingSet)
        .as("and must be exactly the tenants with a role carrying the whole catalogue: a role one"
            + " permission short, a benign role and a role merely NAMED TENANT_ADMIN do not count")
        .isEqualTo(Set.of(tenantWholeUp, tenantWholeDown, tenantMixed));
    assertThat(sqlHasHolderSet).isEqualTo(javaHasHolderSet);
    assertThat(sqlAffected)
        .as("SQL's affected (DOWN) set must equal the Java-computed affected set")
        .isEqualTo(javaAffected)
        .as("and must be exactly the tenant whose only admin-defining role has no active holder")
        .isEqualTo(Set.of(tenantWholeDown));
  }

  /** Grants every catalogue permission except the first {@code skip} (by id order). */
  private void grantAllBut(UUID roleId, Set<UUID> catalogue, int skip) {
    List<UUID> ordered = new ArrayList<>(catalogue);
    ordered.sort(null);
    ordered.subList(skip, ordered.size()).forEach(id -> grantPermission(roleId, id));
  }

  private Role seedRole(UUID tenantId, String name) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, name, "mci", false));
  }

  private void grantPermission(UUID roleId, UUID permissionId) {
    rolePermissionRepository.save(new RolePermission(roleId, permissionId));
  }

  private UUID seedUser(UUID tenantId, String tag) {
    String email = "mci-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user).getId();
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
