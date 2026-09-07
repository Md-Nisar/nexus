package com.example.nexus.rbac.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.domain.DuplicateRoleNameException;
import com.example.nexus.rbac.domain.DuplicateRolePermissionException;
import com.example.nexus.rbac.domain.IdGenerator;
import com.example.nexus.rbac.domain.Permission;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.RolePermissionId;
import com.example.nexus.rbac.domain.RoleView;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Sort;

/**
 * Unit tests for {@link JpaRoleManagementAdapter} — pure Mockito, no Spring context, per
 * `docs/TESTING.md`'s unit-test convention, mirroring {@code JpaUserRoleAssignmentAdapterTest}'s
 * shape (03-design.md §4.5, 04-tasks.md T-003).
 *
 * <p>The two non-mechanical branches this adapter owns — {@link DataIntegrityViolationException}
 * translation on {@code createRole} and {@code attachPermission} — are the specific failure mode
 * that turns a clean 409 into a 500 in production only (every {@code *IT} runs as the
 * Testcontainers superuser, which has no privilege restrictions to trigger the path).
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class JpaRoleManagementAdapterTest {

  @Mock private JpaRoleRepository roleRepository;
  @Mock private JpaRolePermissionRepository rolePermissionRepository;
  @Mock private JpaPermissionRepository permissionRepository;
  @Mock private IdGenerator idGenerator;

  private JpaRoleManagementAdapter adapter;

  private UUID roleId;
  private UUID tenantId;
  private UUID permissionId;

  @BeforeEach
  void setUp() {
    adapter =
        new JpaRoleManagementAdapter(
            roleRepository, rolePermissionRepository, permissionRepository, idGenerator);
    roleId = UUID.randomUUID();
    tenantId = UUID.randomUUID();
    permissionId = UUID.randomUUID();
  }

  @Test
  void should_saveAndFlushNewRoleAndReturnItsId_when_createRoleSucceeds() {
    UUID generatedId = UUID.randomUUID();
    when(idGenerator.newId()).thenReturn(generatedId);
    Role saved = new Role(generatedId, tenantId, "Billing Manager", "desc", false);
    when(roleRepository.saveAndFlush(any(Role.class))).thenReturn(saved);

    UUID result = adapter.createRole(tenantId, "Billing Manager", "desc");

    assertThat(result).isEqualTo(generatedId);
    ArgumentCaptor<Role> captor = ArgumentCaptor.forClass(Role.class);
    org.mockito.Mockito.verify(roleRepository).saveAndFlush(captor.capture());
    assertThat(captor.getValue().getId()).isEqualTo(generatedId);
    assertThat(captor.getValue().getTenantId()).isEqualTo(tenantId);
    assertThat(captor.getValue().getName()).isEqualTo("Billing Manager");
    assertThat(captor.getValue().getDescription()).isEqualTo("desc");
    assertThat(captor.getValue().isSystemRole()).isFalse();
  }

  @Test
  void should_throwDuplicateRoleNameException_when_createRoleViolatesUniqueConstraint() {
    when(idGenerator.newId()).thenReturn(UUID.randomUUID());
    when(roleRepository.saveAndFlush(any(Role.class)))
        .thenThrow(new DataIntegrityViolationException("uq_roles_tenant_name violated"));

    assertThatThrownBy(() -> adapter.createRole(tenantId, "Billing Manager", "desc"))
        .isInstanceOf(DuplicateRoleNameException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_006");
  }

  @Test
  void should_returnEmpty_when_roleNotFoundById() {
    when(roleRepository.findRoleViewById(roleId)).thenReturn(Optional.empty());

    assertThat(adapter.findRole(roleId)).isEmpty();
  }

  @Test
  void should_returnRoleView_when_roleFoundById() {
    RoleView view = new RoleView(roleId, tenantId, "MEMBER", "desc", true, Instant.now());
    when(roleRepository.findRoleViewById(roleId)).thenReturn(Optional.of(view));

    assertThat(adapter.findRole(roleId)).contains(view);
  }

  @Test
  void should_delegateToRepository_when_listingRolesInTenant() {
    RoleView view = new RoleView(roleId, tenantId, "MEMBER", null, false, Instant.now());
    when(roleRepository.findRoleViewsByTenantId(tenantId)).thenReturn(List.of(view));

    assertThat(adapter.findRolesInTenant(tenantId)).containsExactly(view);
  }

  @Test
  void should_returnRoleId_when_findRoleIdByNameMatches() {
    when(roleRepository.findIdByTenantIdAndName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));

    assertThat(adapter.findRoleIdByName(tenantId, "TENANT_ADMIN")).contains(roleId);
  }

  @Test
  void should_returnEmpty_when_findRoleIdByNameHasNoMatch() {
    when(roleRepository.findIdByTenantIdAndName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.empty());

    assertThat(adapter.findRoleIdByName(tenantId, "TENANT_ADMIN")).isEmpty();
  }

  @Test
  void should_returnCount_when_countingRolesInTenant() {
    when(roleRepository.countByTenantId(tenantId)).thenReturn(3L);

    assertThat(adapter.countRolesInTenant(tenantId)).isEqualTo(3L);
  }

  @Test
  void should_returnEmpty_when_permissionNotFoundById() {
    when(permissionRepository.findById(permissionId)).thenReturn(Optional.empty());

    assertThat(adapter.findPermission(permissionId)).isEmpty();
  }

  @Test
  void should_returnPermissionView_when_permissionFoundById() {
    Permission permission = new Permission(permissionId, "role:write", "desc");
    when(permissionRepository.findById(permissionId)).thenReturn(Optional.of(permission));

    Optional<PermissionView> result = adapter.findPermission(permissionId);

    assertThat(result).contains(new PermissionView(permissionId, "role:write", "desc"));
  }

  @Test
  void should_delegateToRepositorySortedByName_when_listingAllPermissions() {
    Permission p1 = new Permission(UUID.randomUUID(), "role:read", "desc1");
    Permission p2 = new Permission(UUID.randomUUID(), "role:write", "desc2");
    when(permissionRepository.findAll(Sort.by("name"))).thenReturn(List.of(p1, p2));

    List<PermissionView> result = adapter.findAllPermissions();

    assertThat(result)
        .containsExactly(
            new PermissionView(p1.getId(), "role:read", "desc1"),
            new PermissionView(p2.getId(), "role:write", "desc2"));
  }

  @Test
  void should_delegateToRepository_when_listingPermissionsForRole() {
    PermissionView view = new PermissionView(permissionId, "role:read", "desc");
    when(rolePermissionRepository.findPermissionViewsForRole(roleId)).thenReturn(List.of(view));

    assertThat(adapter.findPermissionsForRole(roleId)).containsExactly(view);
  }

  @Test
  void should_returnTrue_when_hasPermissionExists() {
    when(rolePermissionRepository.existsById(new RolePermissionId(roleId, permissionId)))
        .thenReturn(true);

    assertThat(adapter.hasPermission(roleId, permissionId)).isTrue();
  }

  @Test
  void should_returnFalse_when_hasPermissionDoesNotExist() {
    when(rolePermissionRepository.existsById(new RolePermissionId(roleId, permissionId)))
        .thenReturn(false);

    assertThat(adapter.hasPermission(roleId, permissionId)).isFalse();
  }

  @Test
  void should_saveAndFlushNewRolePermission_when_attachPermissionSucceeds() {
    adapter.attachPermission(roleId, permissionId);

    ArgumentCaptor<RolePermission> captor = ArgumentCaptor.forClass(RolePermission.class);
    org.mockito.Mockito.verify(rolePermissionRepository).saveAndFlush(captor.capture());
    assertThat(captor.getValue().getRoleId()).isEqualTo(roleId);
    assertThat(captor.getValue().getPermissionId()).isEqualTo(permissionId);
  }

  @Test
  void should_throwDuplicateRolePermissionException_when_attachPermissionViolatesConstraint() {
    when(rolePermissionRepository.saveAndFlush(any(RolePermission.class)))
        .thenThrow(new DataIntegrityViolationException("pk_role_permissions violated"));

    assertThatThrownBy(() -> adapter.attachPermission(roleId, permissionId))
        .isInstanceOf(DuplicateRolePermissionException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_005");
  }

  @Test
  void should_returnOne_when_detachPermissionRemovesExistingRow() {
    when(rolePermissionRepository.deleteByRoleIdAndPermissionId(roleId, permissionId))
        .thenReturn(1);

    assertThat(adapter.detachPermission(roleId, permissionId)).isEqualTo(1);
  }

  @Test
  void should_returnZero_when_detachPermissionRemovesNothing() {
    when(rolePermissionRepository.deleteByRoleIdAndPermissionId(roleId, permissionId))
        .thenReturn(0);

    assertThat(adapter.detachPermission(roleId, permissionId)).isZero();
  }
}
