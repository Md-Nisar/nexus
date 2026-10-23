package com.example.nexus.rbac.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.domain.DuplicateRoleNameException;
import com.example.nexus.rbac.domain.DuplicateRolePermissionException;
import com.example.nexus.rbac.domain.IdGenerator;
import com.example.nexus.rbac.domain.PageResult;
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
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
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
  @Mock private JpaUserRoleRepository userRoleRepository;
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
            roleRepository,
            userRoleRepository,
            rolePermissionRepository,
            permissionRepository,
            idGenerator);
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
  void should_delegateTheSoftDeleteToTheTargetedUpdate_when_softDeletingARole() {
    UUID roleId = UUID.randomUUID();
    Instant at = Instant.now();
    when(roleRepository.softDelete(roleId, tenantId, at)).thenReturn(1);

    assertThat(adapter.softDeleteRole(roleId, tenantId, at)).isEqualTo(1);
  }

  @Test
  void should_delegateTheRenameToTheTwoColumnUpdate_when_updatingARole() {
    UUID roleId = UUID.randomUUID();
    when(roleRepository.updateNameAndDescription(roleId, tenantId, "New", "desc")).thenReturn(1);

    assertThat(adapter.updateRole(roleId, tenantId, "New", "desc")).isEqualTo(1);
  }

  @Test
  void should_throwDuplicateRoleNameWithAFixedMessage_when_theRenameViolatesAUniqueKey() {
    when(roleRepository.updateNameAndDescription(any(), any(), any(), any()))
        .thenThrow(new DataIntegrityViolationException("Duplicate entry 'x' for key 'uq_roles'"));

    assertThatThrownBy(() -> adapter.updateRole(UUID.randomUUID(), tenantId, "Taken", null))
        .isInstanceOf(DuplicateRoleNameException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_006")
        .hasMessage("A role with this name already exists in this tenant");
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
    when(roleRepository.findRoleViewsByTenantId(tenantId, PageRequest.of(1, 10)))
        .thenReturn(new PageImpl<>(List.of(view), PageRequest.of(1, 10), 11));

    PageResult<RoleView> result = adapter.findRolesInTenant(tenantId, 1, 10);

    assertThat(result.items()).containsExactly(view);
    assertThat(result.totalElements()).isEqualTo(11);
    assertThat(result.page()).isEqualTo(1);
    assertThat(result.size()).isEqualTo(10);
    assertThat(result.totalPages()).isEqualTo(2);
  }

  @Test
  void should_returnTheLiveRoleCount_when_countingRolesInTenant() {
    // T-026: the cap counts live roles only, so the adapter must use the live-only count.
    when(roleRepository.countByTenantIdAndDeletedAtIsNull(tenantId)).thenReturn(3L);

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
    PageRequest request = PageRequest.of(0, 2, Sort.by("name"));
    when(permissionRepository.findAll(request))
        .thenReturn(new PageImpl<>(List.of(p1, p2), request, 5));

    PageResult<PermissionView> result = adapter.findAllPermissions(0, 2);

    assertThat(result.items())
        .containsExactly(
            new PermissionView(p1.getId(), "role:read", "desc1"),
            new PermissionView(p2.getId(), "role:write", "desc2"));
    assertThat(result.totalElements()).isEqualTo(5);
    assertThat(result.totalPages()).isEqualTo(3);
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
  // ── US-019 B8 replace ───────────────────────────────────────────────────

  private static byte[] bytesOf(UUID id) {
    return java.nio.ByteBuffer.allocate(16)
        .putLong(id.getMostSignificantBits())
        .putLong(id.getLeastSignificantBits())
        .array();
  }

  @Test
  void should_bindIdsAsBytesAndReportTheLock_when_theLiveRoleRowIsLocked() {
    when(roleRepository.lockLiveRoleRow(any(byte[].class), any(byte[].class)))
        .thenAnswer(
            inv ->
                java.util.Arrays.equals(inv.getArgument(0), bytesOf(roleId))
                        && java.util.Arrays.equals(inv.getArgument(1), bytesOf(tenantId))
                    ? List.<byte[]>of(bytesOf(roleId))
                    : List.<byte[]>of());

    assertThat(adapter.lockRoleRow(roleId, tenantId)).isTrue();
  }

  @Test
  void should_reportGone_when_noLiveRoleRowMatches() {
    when(roleRepository.lockLiveRoleRow(any(byte[].class), any(byte[].class)))
        .thenReturn(List.of());

    assertThat(adapter.lockRoleRow(roleId, tenantId)).isFalse();
  }

  @Test
  void should_decodeTheLockedPermissionIds_when_readingTheCurrentSet() {
    UUID other = UUID.fromString("ffffffff-0000-7000-8000-000000000001");
    when(rolePermissionRepository.lockPermissionIdsByRoleId(any(byte[].class)))
        .thenReturn(List.of(bytesOf(permissionId), bytesOf(other)));

    assertThat(adapter.lockPermissionIdsForRole(roleId)).containsExactlyInAnyOrder(permissionId, other);
  }

  @Test
  void should_returnTheBulkDeleteCount_when_detachingSeveralPermissions() {
    List<UUID> ids = List.of(permissionId, UUID.randomUUID());
    when(rolePermissionRepository.deleteByRoleIdAndPermissionIdIn(roleId, ids)).thenReturn(2);

    assertThat(adapter.detachPermissions(roleId, ids)).isEqualTo(2);
  }

  @Test
  void should_issueNoStatement_when_detachingNoPermissions() {
    assertThat(adapter.detachPermissions(roleId, List.of())).isZero();
    org.mockito.Mockito.verifyNoInteractions(rolePermissionRepository);
  }

  @Test
  @SuppressWarnings("unchecked")
  void should_saveAllAndFlushOneRowPerId_when_attachingSeveralPermissions() {
    UUID other = UUID.randomUUID();
    ArgumentCaptor<List<RolePermission>> rows = ArgumentCaptor.forClass(List.class);

    adapter.attachPermissions(roleId, List.of(permissionId, other));

    org.mockito.Mockito.verify(rolePermissionRepository).saveAllAndFlush(rows.capture());
    assertThat(rows.getValue())
        .extracting(RolePermission::getRoleId, RolePermission::getPermissionId)
        .containsExactly(
            org.assertj.core.groups.Tuple.tuple(roleId, permissionId),
            org.assertj.core.groups.Tuple.tuple(roleId, other));
  }

  @Test
  void should_translateAKeyViolation_when_attachingSeveralPermissions() {
    when(rolePermissionRepository.saveAllAndFlush(any()))
        .thenThrow(new DataIntegrityViolationException("duplicate key secret-detail"));

    assertThatThrownBy(() -> adapter.attachPermissions(roleId, List.of(permissionId)))
        .isInstanceOf(DuplicateRolePermissionException.class)
        .hasMessageNotContaining("secret-detail");
  }
}
