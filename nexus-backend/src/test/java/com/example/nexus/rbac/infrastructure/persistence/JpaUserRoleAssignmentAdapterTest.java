package com.example.nexus.rbac.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.domain.ActiveAssignmentRef;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.IdGenerator;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.UserRole;
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
  @Mock private IdGenerator idGenerator;

  private JpaUserRoleAssignmentAdapter adapter;

  private UUID userId;
  private UUID roleId;
  private UUID tenantId;
  private UUID assignedBy;

  @BeforeEach
  void setUp() {
    adapter = new JpaUserRoleAssignmentAdapter(userRoleRepository, roleRepository, idGenerator);
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
  void should_returnTrue_when_lockActiveAdminAssignmentReturnsNonEmptyList() {
    UserRole row = mock(UserRole.class);
    when(userRoleRepository.lockActiveAdminAssignment(userId, roleId, tenantId))
        .thenReturn(List.of(row));

    assertThat(adapter.hasActiveAdminAssignment(userId, roleId, tenantId)).isTrue();
  }

  @Test
  void should_returnFalse_when_lockActiveAdminAssignmentReturnsEmptyList() {
    when(userRoleRepository.lockActiveAdminAssignment(userId, roleId, tenantId))
        .thenReturn(List.of());

    assertThat(adapter.hasActiveAdminAssignment(userId, roleId, tenantId)).isFalse();
  }

  @Test
  void should_mapLockedRowsToTheirIds_when_lockingActiveAssignmentIds() {
    UUID rowId1 = UUID.randomUUID();
    UUID rowId2 = UUID.randomUUID();
    UserRole row1 = new UserRole(rowId1, userId, roleId, tenantId, assignedBy);
    UserRole row2 = new UserRole(rowId2, UUID.randomUUID(), roleId, tenantId, assignedBy);
    when(userRoleRepository.lockActiveAssignmentsByRole(tenantId, roleId))
        .thenReturn(List.of(row1, row2));

    List<UUID> result = adapter.lockActiveAssignmentIds(tenantId, roleId);

    assertThat(result).containsExactly(rowId1, rowId2);
  }

  @Test
  void should_delegateWithTenantThenRoleArgumentOrder_when_lockingActiveAssignmentIds() {
    // Pins the M1 argument order: a transposition of (tenantId, roleId) would compile fine but
    // silently scope the lock to the wrong tenant/role pair (R-3/T-D3).
    when(userRoleRepository.lockActiveAssignmentsByRole(any(), any())).thenReturn(List.of());

    adapter.lockActiveAssignmentIds(tenantId, roleId);

    verify(userRoleRepository).lockActiveAssignmentsByRole(tenantId, roleId);
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
    when(userRoleRepository.findActiveAssignmentViews(userId, tenantId))
        .thenReturn(List.of(view));

    assertThat(adapter.findActiveAssignmentViews(userId, tenantId)).containsExactly(view);
  }

  @Test
  void should_saveAndFlushNewUserRoleAndReturnItsId_when_noConstraintViolation() {
    UUID generatedId = UUID.randomUUID();
    UUID savedId = UUID.randomUUID();
    when(idGenerator.newId()).thenReturn(generatedId);
    UserRole saved = new UserRole(savedId, userId, roleId, tenantId, assignedBy);
    when(userRoleRepository.saveAndFlush(any(UserRole.class))).thenReturn(saved);

    UUID result = adapter.assign(userId, roleId, tenantId, assignedBy);

    assertThat(result).isEqualTo(savedId);
    ArgumentCaptor<UserRole> captor = ArgumentCaptor.forClass(UserRole.class);
    verify(userRoleRepository).saveAndFlush(captor.capture());
    assertThat(captor.getValue().getId()).isEqualTo(generatedId);
    assertThat(captor.getValue().getUserId()).isEqualTo(userId);
    assertThat(captor.getValue().getRoleId()).isEqualTo(roleId);
    assertThat(captor.getValue().getTenantId()).isEqualTo(tenantId);
    assertThat(captor.getValue().getAssignedBy()).isEqualTo(assignedBy);
  }

  /**
   * The TOCTOU-backstop test (see class Javadoc): {@code uq_user_role_active} rejecting a
   * concurrent duplicate insert surfaces to this adapter as a {@link
   * DataIntegrityViolationException} from {@code saveAndFlush(...)} — this must be translated into
   * a clean {@link DuplicateRoleAssignmentException}, never left to propagate as an untranslated
   * 500-shaped exception.
   *
   * <p>{@code saveAndFlush}, deliberately not {@code save}, is what this test pins: a plain {@code
   * save()} only queues the INSERT in Hibernate's persistence context, so the constraint violation
   * would not actually surface until some LATER auto-flush-triggering call (e.g. {@code
   * RoleAssignmentService#assign}'s own M4a re-read immediately afterwards) — outside this
   * method's {@code try/catch} entirely. A real 8-thread concurrency IT ({@code
   * RoleAssignmentIT#should_allowExactlyOneWinner_when_eightConcurrentAssignsRaceForSameUserAndRole})
   * caught exactly that bug against real MySQL before this fix.
   */
  @Test
  void should_throwDuplicateRoleAssignmentException_when_saveAndFlushThrowsDataIntegrityViolation() {
    when(idGenerator.newId()).thenReturn(UUID.randomUUID());
    when(userRoleRepository.saveAndFlush(any(UserRole.class)))
        .thenThrow(new DataIntegrityViolationException("uq_user_role_active violated"));

    assertThatThrownBy(() -> adapter.assign(userId, roleId, tenantId, assignedBy))
        .isInstanceOf(DuplicateRoleAssignmentException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_004");
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
}
