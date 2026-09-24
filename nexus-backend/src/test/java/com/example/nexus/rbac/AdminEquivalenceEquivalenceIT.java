package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.rbac.domain.RbacDangerousPermissions;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.RolePermissionName;
import com.example.nexus.rbac.domain.RoleView;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

/**
 * US-017 T-006(f): MC-H's equivalence half (design §11.2 MC-H, §9.3, RC-17 part 2) -- the
 * canary-independence half of MC-H is proved at the unit level ({@code
 * RoleAssignmentServiceTest}'s MC-G tests, since the canary code path is only ever reachable via
 * {@code RoleAssignmentService}, not via the port directly).
 *
 * <p>Proves, over a fixture matrix of a tenant's roles (none / one / two / all three dangerous
 * permissions; a zero-permission role; the literal {@code TENANT_ADMIN}; a foreign-tenant role),
 * that the admin-equivalence partition computed from ONE M10 call ({@code
 * JpaRoleRepository#findPermissionNamesByTenantRoles}) equals the partition computed by calling
 * the shipped, separately-tested M7 ({@code findPermissionNamesByRole}) per role. M7 is the
 * incumbent, already covered by US-016's tests; making the new bulk read prove itself against it
 * is the cheapest bound on the single most load-bearing new statement in this story.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class AdminEquivalenceEquivalenceIT {

  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private UuidGenerator uuidGenerator;

  private static final UUID TENANT_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1801-7000-8000-000000000002");
  private static final UUID USER_READ_PERMISSION_ID =
      UUID.fromString("019f6839-1802-7000-8000-000000000003");
  private static final UUID USER_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1803-7000-8000-000000000004");
  private static final UUID ROLE_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1805-7000-8000-000000000006");

  @Test
  void should_agreeWithM7PerRole_when_computingAdminEquivalencePartitionFromM10_MCH() {
    UUID tenantId = uuidGenerator.newId();
    UUID foreignTenantId = uuidGenerator.newId();

    Role roleNone = seedRole(tenantId, "MCH-NONE"); // one non-dangerous permission
    grantPermission(roleNone.getId(), USER_READ_PERMISSION_ID);

    Role roleOne = seedRole(tenantId, "MCH-ONE"); // one dangerous permission
    grantPermission(roleOne.getId(), ROLE_WRITE_PERMISSION_ID);

    Role roleTwo = seedRole(tenantId, "MCH-TWO"); // two of the three dangerous permissions
    grantPermission(roleTwo.getId(), ROLE_WRITE_PERMISSION_ID);
    grantPermission(roleTwo.getId(), USER_WRITE_PERMISSION_ID);

    Role roleAll = seedRole(tenantId, "MCH-ALL"); // all three dangerous permissions
    grantPermission(roleAll.getId(), ROLE_WRITE_PERMISSION_ID);
    grantPermission(roleAll.getId(), USER_WRITE_PERMISSION_ID);
    grantPermission(roleAll.getId(), TENANT_WRITE_PERMISSION_ID);

    Role roleZeroPermissions = seedRole(tenantId, "MCH-ZERO-PERMS"); // no permissions at all

    Role roleTenantAdminLiteral =
        seedRole(tenantId, "TENANT_ADMIN"); // literal name, zero permissions -- M10/M7 are
    // permission-driven only; the name-match half is M8's job, not M10/M7's.

    // Foreign-tenant role, fully dangerous -- must never leak into THIS tenant's M10 partition.
    Role foreignRole = seedRole(foreignTenantId, "MCH-FOREIGN-ALL");
    grantPermission(foreignRole.getId(), ROLE_WRITE_PERMISSION_ID);
    grantPermission(foreignRole.getId(), USER_WRITE_PERMISSION_ID);
    grantPermission(foreignRole.getId(), TENANT_WRITE_PERMISSION_ID);

    // ── M10: ONE tenant-scoped bulk read ──────────────────────────────────────────────────
    List<RolePermissionName> m10Rows = roleRepository.findPermissionNamesByTenantRoles(tenantId);
    var m10PermissionsByRole =
        m10Rows.stream()
            .collect(
                Collectors.groupingBy(
                    RolePermissionName::roleId,
                    Collectors.mapping(RolePermissionName::permissionName, Collectors.toList())));
    Set<UUID> m10AdminEquivalentIds =
        m10PermissionsByRole.entrySet().stream()
            .filter(e -> RbacDangerousPermissions.carriesAny(e.getValue()))
            .map(java.util.Map.Entry::getKey)
            .collect(Collectors.toSet());
    Set<UUID> m10FullyAdminEquivalentIds =
        m10PermissionsByRole.entrySet().stream()
            .filter(e -> RbacDangerousPermissions.carriesAll(e.getValue()))
            .map(java.util.Map.Entry::getKey)
            .collect(Collectors.toSet());

    // ── M7: the shipped, separately-tested per-role read, called once per role in TENANT'S OWN
    // roster only (never the foreign role) ──────────────────────────────────────────────────
    List<RoleView> tenantRoles = roleRepository.findRoleViewsByTenantId(tenantId);
    Set<UUID> m7AdminEquivalentIds = new HashSet<>();
    Set<UUID> m7FullyAdminEquivalentIds = new HashSet<>();
    for (RoleView role : tenantRoles) {
      List<String> permissionNames = roleRepository.findPermissionNamesByRole(role.id());
      if (RbacDangerousPermissions.carriesAny(permissionNames)) {
        m7AdminEquivalentIds.add(role.id());
      }
      if (RbacDangerousPermissions.carriesAll(permissionNames)) {
        m7FullyAdminEquivalentIds.add(role.id());
      }
    }

    assertThat(m10AdminEquivalentIds)
        .as("M10's ANY-partition must equal M7-per-role's ANY-partition")
        .isEqualTo(m7AdminEquivalentIds)
        .as("and must be exactly {roleOne, roleTwo, roleAll}")
        .isEqualTo(Set.of(roleOne.getId(), roleTwo.getId(), roleAll.getId()));
    assertThat(m10FullyAdminEquivalentIds)
        .as("M10's ALL-partition must equal M7-per-role's ALL-partition")
        .isEqualTo(m7FullyAdminEquivalentIds)
        .as("and must be exactly {roleAll}")
        .isEqualTo(Set.of(roleAll.getId()));
    assertThat(m10AdminEquivalentIds)
        .as("the foreign tenant's fully-dangerous role must never appear in this tenant's"
            + " M10 partition (T-S1)")
        .doesNotContain(foreignRole.getId());
    assertThat(m10AdminEquivalentIds)
        .as("a zero-permission role (even literally named TENANT_ADMIN) never appears in M10's"
            + " partition -- name-match is M8's job, not M10's")
        .doesNotContain(roleZeroPermissions.getId(), roleTenantAdminLiteral.getId());
  }

  private Role seedRole(UUID tenantId, String name) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, name, "mch", false));
  }

  private void grantPermission(UUID roleId, UUID permissionId) {
    rolePermissionRepository.save(new RolePermission(roleId, permissionId));
  }
}
