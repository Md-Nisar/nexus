package com.example.nexus.rbac.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.ActiveAssignmentRef;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.HolderProvenance;
import com.example.nexus.rbac.domain.IdGenerator;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermissionRef;
import com.example.nexus.rbac.domain.UserRole;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.repository.CrudRepository;

/**
 * Unit tests for {@link JpaUserRoleAssignmentAdapter} — pure Mockito, no Spring context, per
 * `docs/TESTING.md`'s unit-test convention.
 *
 * <p>Closes a genuine coverage gap identified in US-012 Phase 8 (test-validate): the JaCoCo report
 * showed this adapter at 12% unit line coverage (88 missed / 12 covered) with its 4 branches
 * entirely uncovered. Reading every existing *IT confirms none of them actually exercises this
 * class's one piece of real logic — the {@link DataIntegrityViolationException} → {@link
 * DuplicateRoleAssignmentException} translation in {@link
 * JpaUserRoleAssignmentAdapter#assign}. {@code RoleAssignmentIT}'s duplicate-assignment test goes
 * through {@code RoleAssignmentService#assign}, whose M2 pre-check (`hasActiveAssignment`) already
 * throws before this adapter's {@code assign(...)} is ever called; {@code ActiveAssignmentIT}'s
 * concurrent-insert test calls {@code JpaUserRoleRepository#save} directly, bypassing this adapter
 * entirely. This class is the only place the catch-and-translate itself — the design's documented
 * "TOCTOU backstop behind step 4" (03-design.md §4.3) — is exercised at all.
 *
 * <p>The remaining methods are one-line delegations to {@link JpaUserRoleRepository}/{@link
 * JpaRoleRepository}; each gets a short delegation test both to close the JaCoCo gap and to pin
 * the exact repository method + argument each port method maps to (a transposition here would be a
 * silent security bug — e.g. swapping M1's tenantId/roleId argument order).
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class JpaUserRoleAssignmentAdapterTest {

  @Mock private JpaUserRoleRepository userRoleRepository;
  @Mock private JpaRoleRepository roleRepository;
  @Mock private JpaPermissionCatalogueRepository permissionCatalogueRepository;
  @Mock private IdGenerator idGenerator;

  private JpaUserRoleAssignmentAdapter adapter;

  private UUID userId;
  private UUID roleId;
  private UUID tenantId;
  private UUID assignedBy;

  @BeforeEach
  void setUp() {
    adapter = new JpaUserRoleAssignmentAdapter(
            userRoleRepository, roleRepository, permissionCatalogueRepository, idGenerator);
    userId = UUID.randomUUID();
    roleId = UUID.randomUUID();
    tenantId = UUID.randomUUID();
    assignedBy = UUID.randomUUID();
  }

  @Test
  void should_delegateToRoleRepository_when_findingRoleById() {
    Role role = new Role(roleId, tenantId, "MEMBER", null, false);
    when(roleRepository.findById(roleId)).thenReturn(Optional.of(role));

    Optional<Role> result = adapter.findRole(roleId);

    assertThat(result).contains(role);
  }

  @Test
  void should_returnEmpty_when_roleNotFound() {
    when(roleRepository.findById(roleId)).thenReturn(Optional.empty());

    assertThat(adapter.findRole(roleId)).isEmpty();
  }

  @Test
  void should_returnTrue_when_activeAssignmentCountIsPositive() {
    when(userRoleRepository.countActiveByUserAndRole(userId, roleId)).thenReturn(1L);

    assertThat(adapter.hasActiveAssignment(userId, roleId)).isTrue();
  }

  @Test
  void should_returnFalse_when_activeAssignmentCountIsZero() {
    when(userRoleRepository.countActiveByUserAndRole(userId, roleId)).thenReturn(0L);

    assertThat(adapter.hasActiveAssignment(userId, roleId)).isFalse();
  }

  @Test
  void should_delegateToRoleRepository_when_findingRolePermissionIdsForTenantRoles_M10prime() {
    RolePermissionRef pair = new RolePermissionRef(roleId, UUID.randomUUID());
    when(roleRepository.findRolePermissionIdsByTenantRoles(tenantId)).thenReturn(List.of(pair));

    List<RolePermissionRef> result = adapter.findRolePermissionIdsForTenantRoles(tenantId);

    assertThat(result).containsExactly(pair);
    verify(roleRepository).findRolePermissionIdsByTenantRoles(tenantId);
  }

  @Test
  void should_mapEntitiesToIdsOnlyHolders_when_lockingActiveAssignmentHolders() {
    // M11 is native (MC-C fix), like M5b: the repository returns entities, and the adapter must
    // map them down to ActiveAssignmentHolder (ids only, including roleId per H-1) before they
    // escape this adapter.
    UUID assignmentId = UUID.randomUUID();
    List<UUID> roleIds = List.of(roleId);
    UserRole row = mock(UserRole.class);
    when(row.getId()).thenReturn(assignmentId);
    when(row.getUserId()).thenReturn(userId);
    when(row.getRoleId()).thenReturn(roleId);
    when(userRoleRepository.lockActiveAssignmentHoldersByRoles(any(), any(byte[].class)))
        .thenReturn(List.of(row));

    List<ActiveAssignmentHolder> result = adapter.lockActiveAssignmentHolders(tenantId, roleIds);

    assertThat(result).containsExactly(new ActiveAssignmentHolder(assignmentId, userId, roleId));
  }

  @Test
  void should_delegateToUserRoleRepository_when_findingHeldRolePermissionIdsForAuthorization() {
    RolePermissionRef ref = new RolePermissionRef(roleId, UUID.randomUUID());
    when(userRoleRepository.findHeldRolePermissionIdsForAuthorization(userId, tenantId))
        .thenReturn(List.of(ref));

    List<RolePermissionRef> result =
        adapter.findHeldRolePermissionIdsForAuthorization(userId, tenantId);

    assertThat(result).containsExactly(ref);
    verify(userRoleRepository).findHeldRolePermissionIdsForAuthorization(userId, tenantId);
  }

  @Test
  void should_returnPermissionIds_when_roleInTenantHasPermissions() {
    UUID p1 = UUID.randomUUID();
    UUID p2 = UUID.randomUUID();
    when(roleRepository.findPermissionIdsByRoleAndTenantId(roleId, tenantId))
        .thenReturn(List.of(p1, p2));

    assertThat(adapter.findPermissionIdsForRole(roleId, tenantId))
        .hasValueSatisfying(ids -> assertThat(ids).containsExactlyInAnyOrder(p1, p2));
    verify(roleRepository).findPermissionIdsByRoleAndTenantId(roleId, tenantId);
  }

  /** L-2: the LEFT JOIN's single null row means "in tenant, no permissions" -- present and empty. */
  @Test
  void should_returnPresentEmptySet_when_roleInTenantHasNoPermissions() {
    List<UUID> nullRow = new ArrayList<>();
    nullRow.add(null);
    when(roleRepository.findPermissionIdsByRoleAndTenantId(roleId, tenantId)).thenReturn(nullRow);

    assertThat(adapter.findPermissionIdsForRole(roleId, tenantId))
        .hasValueSatisfying(ids -> assertThat(ids).isEmpty());
  }

  /** L-2: no row at all means the role is not in this tenant -- empty, which callers deny. */
  @Test
  void should_returnEmptyOptional_when_roleNotInTenant() {
    when(roleRepository.findPermissionIdsByRoleAndTenantId(roleId, tenantId))
        .thenReturn(List.of());

    assertThat(adapter.findPermissionIdsForRole(roleId, tenantId)).isEmpty();
  }

  @Test
  void should_delegateToPermissionCatalogueRepository_when_findingCatalogueIds_M15() {
    UUID permissionId = UUID.randomUUID();
    when(permissionCatalogueRepository.findCatalogueIds()).thenReturn(Set.of(permissionId));

    assertThat(adapter.findCatalogueIds()).containsExactly(permissionId);
    verify(permissionCatalogueRepository).findCatalogueIds();
  }

  /** L-5: the catalogue dependency is read-only -- it exposes no save/delete at all. */
  @Test
  void should_exposeOnlyFindCatalogueIds_when_inspectingCatalogueRepository() {
    assertThat(JpaPermissionCatalogueRepository.class.getMethods())
        .extracting(Method::getName)
        .containsExactly("findCatalogueIds");
    assertThat(CrudRepository.class.isAssignableFrom(JpaPermissionCatalogueRepository.class))
        .isFalse();
  }

  @Test
  void should_delegateToRepository_when_findingActiveAssignmentRef() {
    ActiveAssignmentRef ref = new ActiveAssignmentRef(UUID.randomUUID(), Instant.now());
    when(userRoleRepository.findActiveAssignmentRef(userId, roleId, tenantId))
        .thenReturn(Optional.of(ref));

    assertThat(adapter.findActiveAssignmentRef(userId, roleId, tenantId)).contains(ref);
  }

  @Test
  void should_delegateToRepository_when_findingActiveAssignmentView() {
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(userId, roleId, "MEMBER", Instant.now(), assignedBy);
    when(userRoleRepository.findActiveAssignmentView(userId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    assertThat(adapter.findActiveAssignmentView(userId, roleId, tenantId)).contains(view);
  }

  @Test
  void should_delegateToRepository_when_findingActiveAssignmentViews() {
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(userId, roleId, "MEMBER", Instant.now(), assignedBy);
    when(userRoleRepository.findActiveAssignmentViews(userId, tenantId, PageRequest.of(2, 5)))
        .thenReturn(new PageImpl<>(List.of(view), PageRequest.of(2, 5), 11));

    PageResult<ActiveRoleAssignment> result =
        adapter.findActiveAssignmentViews(userId, tenantId, 2, 5);

    assertThat(result.items()).containsExactly(view);
    assertThat(result.totalElements()).isEqualTo(11);
    assertThat(result.page()).isEqualTo(2);
    assertThat(result.totalPages()).isEqualTo(3);
  }

  @Test
  void should_insertConditionallyAndReturnTheGeneratedId_when_roleIsLive() {
    UUID generatedId = UUID.randomUUID();
    when(idGenerator.newId()).thenReturn(generatedId);
    when(userRoleRepository.assignIfRoleLive(
            any(byte[].class), any(byte[].class), any(byte[].class), any(byte[].class),
            any(byte[].class)))
        .thenReturn(1);

    UUID result = adapter.assign(userId, roleId, tenantId, assignedBy);

    assertThat(result).isEqualTo(generatedId);
    verify(userRoleRepository)
        .assignIfRoleLive(
            toBytes(generatedId), toBytes(userId), toBytes(roleId), toBytes(tenantId),
            toBytes(assignedBy));
  }

  /** RC-36.1: zero rows means the role is deleted or foreign, the same 404 as a missing role. */
  @Test
  void should_throwRoleNotFound_when_conditionalInsertInsertsNothing() {
    when(idGenerator.newId()).thenReturn(UUID.randomUUID());
    when(userRoleRepository.assignIfRoleLive(
            any(byte[].class), any(byte[].class), any(byte[].class), any(byte[].class),
            any(byte[].class)))
        .thenReturn(0);

    assertThatThrownBy(() -> adapter.assign(userId, roleId, tenantId, assignedBy))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND")
        .hasMessage("No such role");
  }

  /**
   * The TOCTOU-backstop test: {@code uq_user_role_active} rejecting a concurrent duplicate insert
   * surfaces to this adapter as a {@link DataIntegrityViolationException} from the INSERT, which is
   * executed synchronously inside this method (a deferred flush would let it escape the translation
   * as a 500; a real 8-thread concurrency IT caught exactly that bug against MySQL). It must be
   * translated into a clean {@link DuplicateRoleAssignmentException}.
   */
  @Test
  void should_throwDuplicateRoleAssignmentException_when_insertThrowsDataIntegrityViolation() {
    when(idGenerator.newId()).thenReturn(UUID.randomUUID());
    when(userRoleRepository.assignIfRoleLive(
            any(byte[].class), any(byte[].class), any(byte[].class), any(byte[].class),
            any(byte[].class)))
        .thenThrow(new DataIntegrityViolationException("uq_user_role_active violated"));

    assertThatThrownBy(() -> adapter.assign(userId, roleId, tenantId, assignedBy))
        .isInstanceOf(DuplicateRoleAssignmentException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_004");
  }

  private static byte[] toBytes(UUID uuid) {
    return java.nio.ByteBuffer.allocate(16)
        .putLong(uuid.getMostSignificantBits())
        .putLong(uuid.getLeastSignificantBits())
        .array();
  }

  @Test
  void should_delegateToRoleRepositoryFindIdByTenantIdAndName_when_findingRoleIdByName() {
    when(roleRepository.findIdByTenantIdAndName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));

    Optional<UUID> result = adapter.findRoleIdByName(tenantId, "TENANT_ADMIN");

    assertThat(result).contains(roleId);
    verify(roleRepository).findIdByTenantIdAndName(tenantId, "TENANT_ADMIN");
  }

  @Test
  void should_returnEmpty_when_roleIdByNameNotFound() {
    when(roleRepository.findIdByTenantIdAndName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.empty());

    assertThat(adapter.findRoleIdByName(tenantId, "TENANT_ADMIN")).isEmpty();
  }

  @Test
  void should_delegateToRepositoryRevokeById_when_revoking() {
    UUID userRoleId = UUID.randomUUID();
    Instant revokedAt = Instant.now();
    when(userRoleRepository.revokeById(userRoleId, revokedAt)).thenReturn(1);

    int affected = adapter.revoke(userRoleId, revokedAt);

    assertThat(affected).isEqualTo(1);
    verify(userRoleRepository, never()).save(any());
    verify(userRoleRepository, never()).saveAndFlush(any());
  }

  @Test
  void should_returnZero_when_revokeByIdAffectsNoRows() {
    UUID userRoleId = UUID.randomUUID();
    Instant revokedAt = Instant.now();
    when(userRoleRepository.revokeById(userRoleId, revokedAt)).thenReturn(0);

    assertThat(adapter.revoke(userRoleId, revokedAt)).isZero();
  }

  @Test
  void should_delegateToRepository_when_findingActiveUserIdsForRole() {
    UUID user1 = UUID.randomUUID();
    UUID user2 = UUID.randomUUID();
    when(userRoleRepository.findActiveUserIdsByRole(roleId)).thenReturn(List.of(user1, user2));

    List<UUID> result = adapter.findActiveUserIdsForRole(roleId);

    assertThat(result).containsExactly(user1, user2);
  }

  @Test
  void should_delegateToUserRoleRepository_when_findingHeldAdminDefiningRoleIds_M16() {
    when(userRoleRepository.findHeldAdminDefiningRoleIds(userId, tenantId))
        .thenReturn(List.of(roleId));

    assertThat(adapter.findHeldAdminDefiningRoleIds(userId, tenantId)).containsExactly(roleId);
  }

  @Test
  void should_delegateToUserRoleRepository_when_findingActiveHoldersForRole() {
    HolderProvenance holder = new HolderProvenance(userId, assignedBy);
    when(userRoleRepository.findActiveHoldersByRole(roleId, tenantId))
        .thenReturn(List.of(holder));

    assertThat(adapter.findActiveHoldersForRole(roleId, tenantId)).containsExactly(holder);
  }

  @Test
  void should_returnDistinctUserIds_when_findingActiveHolderUserIdsForRoles() {
    when(userRoleRepository.findActiveHolderUserIdsByRoles(List.of(roleId), tenantId))
        .thenReturn(List.of(userId, assignedBy));

    assertThat(adapter.findActiveHolderUserIdsForRoles(tenantId, List.of(roleId)))
        .containsExactlyInAnyOrder(userId, assignedBy);
  }

  @Test
  void should_notReadAndReturnEmpty_when_findingActiveHolderUserIdsForNoRoles() {
    assertThat(adapter.findActiveHolderUserIdsForRoles(tenantId, List.of())).isEmpty();

    verify(userRoleRepository, never()).findActiveHolderUserIdsByRoles(any(), any());
  }
}
