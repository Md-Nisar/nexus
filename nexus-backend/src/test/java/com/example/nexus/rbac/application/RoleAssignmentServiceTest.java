package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.application.port.out.RbacAuditEvent;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.RoleChangeThrottlePort;
import com.example.nexus.rbac.application.port.out.ThrottleStatus;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.ActiveAssignmentRef;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.HolderProvenance;
import com.example.nexus.rbac.domain.LastAdminRoleException;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleChangeThrottledException;
import com.example.nexus.rbac.domain.RoleClassificationChangedException;
import com.example.nexus.rbac.domain.RolePermissionRef;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Unit tests for {@link RoleAssignmentService} — the only place tenant isolation, the grant-subset
 * rules (A2, A4, revoke-subset), the last-admin lockout and the set lock are enforced (ADR-0021).
 *
 * <p>US-018 M3 (T-016, T-018) rewrote this class around the one definition of "administrator" (a
 * role carrying every permission of the catalogue). The name-based and ANY/ALL tests, the canary
 * tests built on the non-locking user read, and the retired counters' tests are retired here, each
 * against the control that now enforces its assertion and a test of that control in this class;
 * the mapping is in {@code docs/features/US-018/15-threat-model-repass-M3.md}.
 *
 * <p>Fixture catalogue: two permissions, {@link #P1} and {@link #P2}. A role carrying both is
 * admin-defining. The baseline (set up for every test, lenient) is the narrowest state in which a
 * test not about a given rule still reaches the rule it exercises: the caller holds only {@code
 * user:role:assign} (L-1), the target role is in the tenant and carries no permissions (EC7).
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class RoleAssignmentServiceTest {

  // The assigner of a locked holder row; irrelevant to every test here except where named.
  private static final UUID ANY_ASSIGNER = UUID.randomUUID();

  private static final int MAX_DENIALS = 5;
  private static final int WINDOW_SECONDS = 60;
  private static final long RETRY_AFTER_SECONDS = 37;
  private static final ThrottleStatus THROTTLED = new ThrottleStatus(true, RETRY_AFTER_SECONDS);

  private static final UUID USER_ROLE_ASSIGN_ID = RbacSeededPermissionIds.USER_ROLE_ASSIGN;
  private static final UUID P1 = UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final UUID P2 = UUID.fromString("00000000-0000-7000-8000-000000000002");
  private static final Set<UUID> CATALOGUE = Set.of(P1, P2);

  @Mock private UserRoleAssignmentPort userRoleAssignmentPort;
  @Mock private UserDirectoryPort userDirectoryPort;
  @Mock private RbacAuditPort rbacAuditPort;
  @Mock private PermissionCachePort permissionCachePort;
  @Mock private PermissionFreshnessService permissionFreshness;
  @Mock private RoleChangeThrottlePort throttlePort;
  @Mock private PlatformTransactionManager transactionManager;

  private SimpleMeterRegistry meterRegistry;
  private RoleAssignmentService service;

  private UUID actorId;
  private UUID tenantId;
  private UUID otherTenantId;
  private UUID targetUserId;
  private UUID roleId;
  private RoleChangeActor actor;
  private RequestContext ctx;

  @BeforeEach
  void setUp() {
    meterRegistry = new SimpleMeterRegistry();
    service =
        new RoleAssignmentService(
            userRoleAssignmentPort, userDirectoryPort, rbacAuditPort, permissionCachePort,
            permissionFreshness, transactionManager, meterRegistry, throttlePort,
            new PiiPermissionGrantRule(true, meterRegistry), MAX_DENIALS, WINDOW_SECONDS);

    actorId = UUID.randomUUID();
    tenantId = UUID.randomUUID();
    otherTenantId = UUID.randomUUID();
    targetUserId = UUID.randomUUID();
    roleId = UUID.randomUUID();
    actor = new RoleChangeActor(actorId, tenantId);
    ctx = RequestContext.UNKNOWN;

    Mockito.lenient()
        .when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(any(), any()))
        .thenReturn(List.of(new RolePermissionRef(UUID.randomUUID(), USER_ROLE_ASSIGN_ID)));
    Mockito.lenient()
        .when(userRoleAssignmentPort.findPermissionIdsForRole(any(), any()))
        .thenReturn(Optional.of(Set.of()));
    Mockito.lenient().when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(CATALOGUE);
    Mockito.lenient().when(userRoleAssignmentPort.lockRoleRow(any(), any())).thenReturn(true);
  }

  // ---------------------------------------------------------------------------------------
  // Fixtures
  // ---------------------------------------------------------------------------------------

  /** {@code refs} plus the caller's {@code user:role:assign} grant (L-1), through its own role. */
  private static List<RolePermissionRef> withUserRoleAssign(List<RolePermissionRef> refs) {
    List<RolePermissionRef> all = new ArrayList<>(refs);
    all.add(new RolePermissionRef(UUID.randomUUID(), USER_ROLE_ASSIGN_ID));
    return all;
  }

  private Role role(String name) {
    return new Role(roleId, tenantId, name, "desc", false);
  }

  private Role memberRole() {
    return role("MEMBER");
  }

  private static RolePermissionRef ref(UUID roleId, UUID permissionId) {
    return new RolePermissionRef(roleId, permissionId);
  }

  private static List<RolePermissionRef> wholeCatalogue(UUID roleId) {
    return List.of(ref(roleId, P1), ref(roleId, P2));
  }

  private static DenialReason reasonOf(Throwable e) {
    return ((InsufficientPermissionException) e).getReason();
  }

  private void stubTargetUserAndRole(UUID target, Role role) {
    when(userDirectoryPort.findTenantId(target)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
  }

  private void stubBenignAssignTarget() {
    stubTargetUserAndRole(targetUserId, memberRole());
  }

  private void stubBenignSelfAssignTarget() {
    stubTargetUserAndRole(actorId, memberRole());
  }

  private void stubSuccessfulInsert() {
    stubSuccessfulInsertFor(targetUserId);
  }

  private void stubSuccessfulSelfInsert() {
    stubSuccessfulInsertFor(actorId);
  }

  private void stubSuccessfulInsertFor(UUID target) {
    when(userRoleAssignmentPort.hasActiveAssignment(target, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(target, roleId, tenantId, actorId))
        .thenReturn(UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveAssignmentView(target, roleId, tenantId))
        .thenReturn(
            Optional.of(new ActiveRoleAssignment(target, roleId, "MEMBER", Instant.now(), actorId)));
  }

  /** M13: the caller holds one role carrying the whole catalogue (an administrator) plus assign. */
  private void stubCallerIsAdministrator() {
    UUID adminDefiningRoleId = UUID.randomUUID();
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(withUserRoleAssign(wholeCatalogue(adminDefiningRoleId)));
  }

  /** M13: the caller holds the whole catalogue only across two partial roles (a union-holder). */
  private void stubCallerIsUnionHolder() {
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(
            withUserRoleAssign(
                List.of(ref(UUID.randomUUID(), P1), ref(UUID.randomUUID(), P2))));
  }

  /** Like {@link #stubCallerIsAdministrator()}, for tests where the read must not be required. */
  private void lenientCallerIsAdministrator() {
    UUID adminDefiningRoleId = UUID.randomUUID();
    Mockito.lenient()
        .when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(withUserRoleAssign(wholeCatalogue(adminDefiningRoleId)));
  }

  /** Like {@link #stubCallerIsUnionHolder()}, for tests where the read must not be required. */
  private void lenientCallerIsUnionHolder() {
    Mockito.lenient()
        .when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(
            withUserRoleAssign(
                List.of(ref(UUID.randomUUID(), P1), ref(UUID.randomUUID(), P2))));
  }

  /** M13: the caller holds {@code P1} only (not an administrator, not a union-holder). */
  private void stubCallerHoldsP1Only() {
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(withUserRoleAssign(List.of(ref(UUID.randomUUID(), P1))));
  }

  /**
   * The target role (id {@link #roleId}) carries the whole catalogue, so it is admin-defining. M10'
   * lists it plus {@code otherAdminDefiningRoleIds}, each carrying the whole catalogue, and M11
   * returns {@code lockedHolders}. The locked current read (RC-57.2) agrees with M10' unless a test
   * overrides it with {@link #stubCurrentReadUnderTheSetLock}.
   */
  private void stubAdminDefiningTarget(
      List<ActiveAssignmentHolder> lockedHolders, UUID... otherAdminDefiningRoleIds) {
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(CATALOGUE));
    List<RolePermissionRef> tenantRows = new ArrayList<>(wholeCatalogue(roleId));
    for (UUID other : otherAdminDefiningRoleIds) {
      tenantRows.addAll(wholeCatalogue(other));
    }
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId))
        .thenReturn(tenantRows);
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(lockedHolders);
    stubCurrentReadUnderTheSetLock(tenantRows);
  }

  /** The locked {@code FOR SHARE} read of the lock set's role permissions returns {@code rows}. */
  private void stubCurrentReadUnderTheSetLock(List<RolePermissionRef> rows) {
    Mockito.lenient()
        .doAnswer(
            invocation -> {
              Collection<UUID> requested = invocation.getArgument(1);
              return rows.stream().filter(row -> requested.contains(row.roleId())).toList();
            })
        .when(userRoleAssignmentPort)
        .lockRolePermissionsForRoles(eq(tenantId), any());
  }

  private static ActiveAssignmentHolder holder(UUID userId, UUID roleId) {
    return new ActiveAssignmentHolder(UUID.randomUUID(), userId, roleId, ANY_ASSIGNER);
  }

  private ActiveAssignmentRef stubRevokeTarget(Role role) {
    return stubRevokeTargetFor(targetUserId, role);
  }

  private ActiveAssignmentRef stubRevokeTargetFor(UUID target, Role role) {
    when(userDirectoryPort.findTenantId(target)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    ActiveAssignmentRef ref =
        new ActiveAssignmentRef(UUID.randomUUID(), Instant.now().minusSeconds(60));
    when(userRoleAssignmentPort.findActiveAssignmentRef(target, roleId, tenantId))
        .thenReturn(Optional.of(ref));
    return ref;
  }

  private ActiveAssignmentRef stubBenignRevokeTarget() {
    return stubRevokeTarget(memberRole());
  }

  // ---------------------------------------------------------------------------------------
  // assign(): tenant isolation, errors, side effects
  // ---------------------------------------------------------------------------------------

  @Test
  void should_insertReReadAndFireSideEffects_when_happyPath() {
    Instant assignedAt = Instant.now();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "MEMBER", assignedAt, actorId);
    stubBenignAssignTarget();
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    ActiveRoleAssignment result = service.assign(actor, targetUserId, roleId, ctx);

    assertThat(result).isEqualTo(view);
    // A6: the audit write happens INLINE, before the cache eviction.
    InOrder inOrder = Mockito.inOrder(rbacAuditPort, permissionCachePort);
    inOrder
        .verify(rbacAuditPort)
        .recordRoleAssigned(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "MEMBER", actorId, ctx));
    inOrder.verify(permissionCachePort).evict(tenantId, targetUserId);
    // MC-4 (RC-40.5): Group A fires and Group B never does within one successful call.
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any(), any());
  }

  // Load-bearing (US-014 Decision 2): this and the other 404/409 negative assertions in this file
  // are proof of the 403-only ROLE_ASSIGNMENT_DENIED scope, not incidental. Do not weaken --
  // defense-in-depth only, the catch type in RoleAssignmentService is the structural control.
  @Test
  void should_throwResourceNotFound_when_targetUserNotFound() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "USER_NOT_FOUND");

    verify(userRoleAssignmentPort, never()).findRole(any());
    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  @Test
  void should_throwSameNotFoundAndWriteNoDenialRow_when_assignTargetTenantMismatch() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(otherTenantId));

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "USER_NOT_FOUND")
        .hasMessage("No such user");

    verify(userRoleAssignmentPort, never()).findRole(any());
    verifyNoInteractions(permissionCachePort, rbacAuditPort);
    assertThat(
            meterRegistry
                .get("nexus.rbac.permission_denied")
                .tag("permission", "user:role:assign")
                .tag("reason", "CROSS_TENANT_TARGET")
                .counter()
                .count())
        .isEqualTo(1.0);
  }

  @Test
  void should_stillThrowOriginalDenialException_when_rbacAuditPortViolatesNeverThrowContract() {
    stubBenignSelfAssignTarget();
    stubCallerHoldsP1Only();
    doThrow(new RuntimeException("audit port broke its never-throw contract"))
        .when(rbacAuditPort)
        .recordRoleAssignmentDenied(any(), any(), any());

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.SELF_ASSIGNMENT));
  }

  @Test
  void should_logErrorWithCallSiteFailedMarker_when_rbacAuditPortViolatesNeverThrowContract() {
    stubBenignSelfAssignTarget();
    stubCallerHoldsP1Only();
    doThrow(new RuntimeException("audit port broke its never-throw contract"))
        .when(rbacAuditPort)
        .recordRoleAssignmentDenied(any(), any(), any());

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);

      var errorEvents = appender.list.stream().filter(e -> e.getLevel() == Level.ERROR).toList();
      assertThat(errorEvents).hasSize(1);
      assertThat(keyValueMap(errorEvents.get(0)))
          .containsEntry("event", "RBAC_AUDIT_DENIAL_CALL_SITE_FAILED")
          .containsEntry("tenantId", tenantId)
          .containsEntry("targetUserId", actorId);
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_throwResourceNotFound_when_assignRoleNotFound() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");

    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  @Test
  void should_throwSameNotFoundAndWriteNoDenialRow_when_assignRoleTenantMismatch() {
    Role foreignRole = new Role(roleId, otherTenantId, "MEMBER", "desc", false);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(foreignRole));

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND")
        .hasMessage("No such role");

    verify(userRoleAssignmentPort, never()).hasActiveAssignment(any(), any());
    verifyNoInteractions(permissionCachePort, rbacAuditPort);
    assertThat(
            meterRegistry
                .get("nexus.rbac.permission_denied")
                .tag("permission", "user:role:assign")
                .tag("reason", "CROSS_TENANT_TARGET")
                .counter()
                .count())
        .isEqualTo(1.0);
  }

  @Test
  void should_throwDuplicateRoleAssignment_when_activeAssignmentAlreadyExists() {
    stubBenignAssignTarget();
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(true);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(DuplicateRoleAssignmentException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_004");

    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  /**
   * Inline-vs-afterCommit fallback: a plain Mockito unit test has no active Spring transaction
   * synchronization, so the cache-evict side effect must run inline before {@code assign(...)}
   * returns.
   */
  @Test
  void should_fireSideEffectsInlineSynchronously_when_noActiveTransactionSynchronization() {
    assertThat(TransactionSynchronizationManager.isSynchronizationActive())
        .as("sanity check: a plain unit test has no active transaction synchronization")
        .isFalse();
    stubBenignAssignTarget();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    verify(permissionCachePort, times(1)).evict(tenantId, targetUserId);
    verify(rbacAuditPort, times(1)).recordRoleAssigned(any());
  }

  /** The audit fires inline, inside the transaction; only the eviction waits for afterCommit. */
  @Test
  void should_deferOnlyCacheEvictionUntilAfterCommit_when_transactionSynchronizationActive() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();

    TransactionSynchronizationManager.initSynchronization();
    try {
      service.assign(actor, targetUserId, roleId, ctx);

      verify(rbacAuditPort).recordRoleAssigned(any());
      verifyNoInteractions(permissionCachePort);

      for (TransactionSynchronization synchronization :
          TransactionSynchronizationManager.getSynchronizations()) {
        synchronization.afterCommit();
      }

      verify(permissionCachePort).evict(tenantId, targetUserId);
    } finally {
      TransactionSynchronizationManager.clearSynchronization();
    }
  }

  @Test
  void should_neverInvalidate_when_assignSucceeds() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    verifyNoInteractions(permissionFreshness);
  }

  // ---------------------------------------------------------------------------------------
  // T-016 (rows 1, 4, 6): classification and the set lock on assign
  // ---------------------------------------------------------------------------------------

  /** Row 4: a benign target takes no lock and does not read the tenant's roles (M10'). */
  @Test
  void should_takeNoLockAndReadNoTenantRoles_when_targetIsNotAdminDefining() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P1)));
    stubCallerHoldsP1Only();

    service.assign(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(userRoleAssignmentPort, never()).findRolePermissionIdsForTenantRoles(any());
    assertThat(meterRegistry.find("nexus.rbac.privileged_revoke_lock_hold").timers()).isEmpty();
  }

  /** Row 1 and 4: an admin-defining target is classified, then M10' and M11 run before any decision. */
  @Test
  void should_throw404RoleNotFound_when_assigningToRoleSoftDeletedUnderLock() {
    stubTargetUserAndRole(targetUserId, role("NON_ADMIN"));
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(withUserRoleAssign(List.of(ref(UUID.randomUUID(), P1))));
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P1)));
    when(userRoleAssignmentPort.lockRoleRow(roleId, tenantId)).thenReturn(false);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");

    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
  }

  @Test
  void should_lockRoleRowsInAscendingOrderBeforeSetLock_when_targetIsAdminDefining() {
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(holder(actorId, roleId)));
    stubCallerIsAdministrator();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    InOrder inOrder = Mockito.inOrder(userRoleAssignmentPort);
    inOrder.verify(userRoleAssignmentPort).findRolePermissionIdsForTenantRoles(tenantId);
    inOrder.verify(userRoleAssignmentPort).lockRoleRow(eq(roleId), eq(tenantId));
    inOrder.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), any());
  }

  @Test
  void should_takeM10PrimeThenM11BeforeEveryDecisionRead_when_targetIsAdminDefining() {
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(holder(actorId, roleId)));
    stubCallerIsAdministrator();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    InOrder inOrder = Mockito.inOrder(userRoleAssignmentPort);
    inOrder.verify(userRoleAssignmentPort).findPermissionIdsForRole(roleId, tenantId);
    inOrder.verify(userRoleAssignmentPort).findCatalogueIds();
    inOrder.verify(userRoleAssignmentPort).findRolePermissionIdsForTenantRoles(tenantId);
    inOrder.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), any());
    inOrder
        .verify(userRoleAssignmentPort)
        .findHeldRolePermissionIdsForAuthorization(actorId, tenantId);
    inOrder.verify(userRoleAssignmentPort).hasActiveAssignment(targetUserId, roleId);
    inOrder.verify(userRoleAssignmentPort).assign(targetUserId, roleId, tenantId, actorId);
  }

  /** A role named TENANT_ADMIN that carries nothing is not admin-defining: no lock (row 1). */
  @Test
  void should_takeNoLock_when_roleIsNamedTenantAdminButCarriesNoPermissions() {
    stubTargetUserAndRole(targetUserId, role("TENANT_ADMIN"));
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
  }

  /** Row 1: a role one permission short of the catalogue is not admin-defining: no lock. */
  @Test
  void should_takeNoLock_when_roleIsOnePermissionShortOfTheCatalogue() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P1)));
    stubCallerHoldsP1Only();

    service.assign(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
  }

  /** An empty catalogue makes no role admin-defining (fail closed): no lock. */
  @Test
  void should_takeNoLock_when_catalogueReadReturnsEmpty() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(Set.of());
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P1)));
    stubCallerHoldsP1Only();

    service.assign(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
  }

  @Test
  void should_propagateAndWriteNothing_when_m10PrimeReadThrows() {
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(CATALOGUE));
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId))
        .thenThrow(new RuntimeException("db down"));

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RuntimeException.class)
        .hasMessage("db down");

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
  }

  @Test
  void should_propagateRecordErrorTimerAndWriteNothing_when_setLockedDecisionReadThrows() {
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(holder(actorId, roleId)));
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenThrow(new RuntimeException("db down"));

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RuntimeException.class)
        .hasMessage("db down");

    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    assertThat(
            meterRegistry
                .find("nexus.rbac.privileged_revoke_lock_hold")
                .tags("operation", "assign", "outcome", "error")
                .timer())
        .isNotNull();
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
  }

  /**
   * Row 1: a partial administrator may now propagate exactly what they hold. The caller holds the
   * whole catalogue across two roles (the union) and assigns an admin-defining role to ANOTHER
   * user: A2 passes. This is the intended loosening of ADR-0021, recorded as RES-27's snapshot
   * residual in the M3 re-pass.
   */
  @Test
  void should_assignAdminDefiningRoleToAnotherUser_when_callerHoldsTheWholeCatalogueThroughTheUnion() {
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of());
    stubCallerIsUnionHolder();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort).assign(targetUserId, roleId, tenantId, actorId);
  }

  // ---------------------------------------------------------------------------------------
  // T-016 (row 1, RC-25.1, RC-25.3): A4's administrator status comes from M11's rows
  // ---------------------------------------------------------------------------------------

  /**
   * RC-25.1: M13 (the snapshot) still says the caller is an administrator, but M11's locked rows
   * no longer contain the caller (the role was revoked while this request waited on the lock). A4
   * decides from M11: 403 SELF_ASSIGNMENT, the timer closes as denied, and nothing is written.
   */
  @Test
  void should_denySelfAssignment_when_m13SaysAdministratorButLockedRowsDoNot_RC25() {
    stubTargetUserAndRole(actorId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(holder(UUID.randomUUID(), roleId)));
    stubCallerIsAdministrator();

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.SELF_ASSIGNMENT));

    verify(rbacAuditPort, times(1))
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, actorId, roleId, "ADMIN_LIKE", actorId, ctx),
            DenialReason.SELF_ASSIGNMENT, "assign");
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verify(userRoleAssignmentPort, never()).findHeldAdminDefiningRoleIds(any(), any());
    assertThat(
            meterRegistry
                .find("nexus.rbac.privileged_revoke_lock_hold")
                .tags("operation", "assign", "outcome", "denied")
                .timer())
        .isNotNull();
  }

  /**
   * RC-25.1, the other direction: M13 says the caller is only a union-holder, but M11's current
   * rows show the caller as an active holder of an admin-defining role. The locked rows win, so
   * the self-assignment is allowed. (A2 still compares against M13's union.)
   */
  @Test
  void should_allowSelfAssignment_when_lockedRowsShowCallerAsAdministratorEvenThoughM13DoesNot() {
    UUID callersAdminRoleId = UUID.randomUUID();
    stubTargetUserAndRole(actorId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(holder(actorId, callersAdminRoleId)), callersAdminRoleId);
    stubCallerIsUnionHolder();
    stubSuccessfulSelfInsert();
    when(userRoleAssignmentPort.findHeldAdminDefiningRoleIds(actorId, tenantId))
        .thenReturn(List.of(callersAdminRoleId));

    service.assign(actor, actorId, roleId, ctx);

    verify(userRoleAssignmentPort).assign(actorId, roleId, tenantId, actorId);
  }

  /**
   * US-019 review R1-2 / S1-Medium (RC-57.2): the caller holds a locked row of a role that M10'
   * (read before the lock) still lists as admin-defining, but a demotion committed while this
   * self-assign waited on the set lock. The current read under the lock decides: the caller is no
   * longer an administrator, so A4 denies with 403 SELF_ASSIGNMENT and nothing is written.
   */
  @Test
  void should_denySelfAssignment_when_theCallersAdminRoleWasDemotedWhileWaitingOnTheSetLock() {
    UUID callersAdminRoleId = UUID.randomUUID();
    stubTargetUserAndRole(actorId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(holder(actorId, callersAdminRoleId)), callersAdminRoleId);
    stubCallerIsUnionHolder();
    stubCurrentReadUnderTheSetLock(
        List.of(
            ref(callersAdminRoleId, P1),
            ref(roleId, P1),
            ref(roleId, P2)));

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.SELF_ASSIGNMENT));

    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
  }

  /** The current read is taken after the set lock, as revoke does (RC-46: no lock before it). */
  @Test
  void should_readTheLockedRolesPermissionsAfterTheSetLock_when_assigningAnAdminDefiningRole() {
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(holder(UUID.randomUUID(), roleId)));
    stubCallerIsAdministrator();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    InOrder order = Mockito.inOrder(userRoleAssignmentPort);
    order.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), any());
    order.verify(userRoleAssignmentPort).lockRolePermissionsForRoles(eq(tenantId), any());
  }

  /** A holder of the TARGET role (itself admin-defining) counts: the target is in the lock set. */
  @Test
  void should_treatTheCallerAsAdministrator_when_callerHoldsTheAdminDefiningTargetRoleItself() {
    stubTargetUserAndRole(actorId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(holder(actorId, roleId)));
    stubCallerIsAdministrator();
    stubSuccessfulSelfInsert();
    when(userRoleAssignmentPort.findHeldAdminDefiningRoleIds(actorId, tenantId))
        .thenReturn(List.of(roleId));

    service.assign(actor, actorId, roleId, ctx);

    verify(userRoleAssignmentPort).assign(actorId, roleId, tenantId, actorId);
  }

  // ---------------------------------------------------------------------------------------
  // A4 on a benign target (the caller's status comes from M13's per-role rows)
  // ---------------------------------------------------------------------------------------

  @Test
  void should_assign_when_administratorSelfAssignsABenignRole() {
    stubBenignSelfAssignTarget();
    stubSuccessfulSelfInsert();
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.findHeldAdminDefiningRoleIds(actorId, tenantId))
        .thenReturn(List.of(UUID.randomUUID()));

    ActiveRoleAssignment result = service.assign(actor, actorId, roleId, ctx);

    assertThat(result.userId()).isEqualTo(actorId);
    verify(userRoleAssignmentPort).assign(actorId, roleId, tenantId, actorId);
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
  }

  @Test
  void should_denySelfAssignmentWithOneDenialRow_when_callerIsNotAnAdministrator() {
    stubBenignSelfAssignTarget();
    stubCallerHoldsP1Only();

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.SELF_ASSIGNMENT));

    verify(rbacAuditPort, times(1))
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, actorId, roleId, "MEMBER", actorId, ctx),
            DenialReason.SELF_ASSIGNMENT, "assign");
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any(), any());
    verify(throttlePort, times(1)).recordDenial(tenantId, actorId);
    verify(userRoleAssignmentPort, never()).hasActiveAssignment(any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verifyNoInteractions(permissionCachePort);
  }

  /** §2.1: the union of two partial roles is NOT an administrator; per role fails closed. */
  @Test
  void should_denySelfAssignment_when_catalogueSplitAcrossTwoRoles() {
    stubBenignSelfAssignTarget();
    stubCallerIsUnionHolder();

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.SELF_ASSIGNMENT));

    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
  }

  @Test
  void should_denySelfAssignment_when_catalogueReadReturnsEmpty() {
    stubBenignSelfAssignTarget();
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(Set.of());
    stubCallerHoldsP1Only();

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.SELF_ASSIGNMENT));
  }

  @Test
  void should_propagateAndNotSave_when_catalogueReadThrows() {
    stubBenignSelfAssignTarget();
    IllegalStateException readFailure = new IllegalStateException("db down");
    when(userRoleAssignmentPort.findCatalogueIds()).thenThrow(readFailure);

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx)).isSameAs(readFailure);

    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
  }

  @Test
  void should_reportUserRoleAssignAsRequiredPermission_when_selfAssignmentDenied() {
    stubBenignSelfAssignTarget();
    stubCallerHoldsP1Only();

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getRequiredPermission())
                    .isEqualTo("user:role:assign"));
  }

  @Test
  void should_logWarnWithIdsOnly_when_selfAssignmentDenied() {
    stubBenignSelfAssignTarget();
    stubCallerHoldsP1Only();
    ListAppender<ILoggingEvent> logs = startLogCapture();

    try {
      assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);
    } finally {
      stopLogCapture(logs);
    }

    ILoggingEvent warn =
        logs.list.stream()
            .filter(e -> "RBAC_SELF_ASSIGNMENT_DENIED".equals(keyValueMap(e).get("event")))
            .findFirst()
            .orElseThrow();
    assertThat(warn.getLevel()).isEqualTo(Level.WARN);
    assertThat(keyValueMap(warn))
        .containsOnlyKeys("event", "tenantId", "actorUserId", "roleId")
        .containsEntry("tenantId", tenantId)
        .containsEntry("actorUserId", actorId)
        .containsEntry("roleId", roleId);
  }

  /** §4.4: A4 and A2 take their inputs from the same single M13 read. */
  @Test
  void should_readM13ExactlyOnce_when_selfTargetPassesA4AndA2() {
    stubBenignSelfAssignTarget();
    stubSuccessfulSelfInsert();
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P1)));
    when(userRoleAssignmentPort.findHeldAdminDefiningRoleIds(actorId, tenantId))
        .thenReturn(List.of(UUID.randomUUID()));

    service.assign(actor, actorId, roleId, ctx);

    verify(userRoleAssignmentPort, times(1))
        .findHeldRolePermissionIdsForAuthorization(actorId, tenantId);
  }

  /** The earlier gate wins and reports once: A4 before A2. */
  @Test
  void should_reportSelfAssignmentOnce_when_A4AndA2BothApply() {
    stubBenignSelfAssignTarget();
    stubCallerHoldsP1Only();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P2)));

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.SELF_ASSIGNMENT));

    verify(rbacAuditPort, times(1)).recordRoleAssignmentDenied(any(), any(), any());
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any(), any());
    verify(throttlePort, times(1)).recordDenial(tenantId, actorId);
  }

  // ---------------------------------------------------------------------------------------
  // A2 (grant-subset on assign)
  // ---------------------------------------------------------------------------------------

  @Test
  void should_deny403GrantExceedsCaller_when_targetRoleCarriesPermissionCallerLacks() {
    stubBenignAssignTarget();
    // Not admin-defining (the catalogue is P1 and P2): a plain A2 denial, no set lock.
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P1, UUID.randomUUID())));
    stubCallerHoldsP1Only();

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    verify(userRoleAssignmentPort, never()).hasActiveAssignment(any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(throttlePort).recordDenial(tenantId, actorId);
    verifyNoInteractions(permissionCachePort);
  }

  @Test
  void should_assign_when_targetPermissionsSubsetOfCallerUnion() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P1)));
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(
            withUserRoleAssign(
                List.of(ref(UUID.randomUUID(), P1), ref(UUID.randomUUID(), UUID.randomUUID()))));

    ActiveRoleAssignment result = service.assign(actor, targetUserId, roleId, ctx);

    assertThat(result.roleId()).isEqualTo(roleId);
    verify(userRoleAssignmentPort).assign(targetUserId, roleId, tenantId, actorId);
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any(), any());
  }

  @Test
  void should_assign_when_targetRoleHasNoPermissions() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    // EC7: an empty role grants nothing, so it passes even for a caller holding nothing else.
    verify(userRoleAssignmentPort).assign(targetUserId, roleId, tenantId, actorId);
  }

  @Test
  void should_propagateAndNotSave_when_heldPermissionReadThrows() {
    stubBenignAssignTarget();
    IllegalStateException readFailure = new IllegalStateException("db down");
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenThrow(readFailure);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isSameAs(readFailure);

    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
  }

  @Test
  void should_recordMissingCountAndNoIds_when_grantExceedsCaller() {
    UUID lackedA = UUID.randomUUID();
    UUID lackedB = UUID.randomUUID();
    stubBenignAssignTarget();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P1, lackedA, lackedB)));
    stubCallerHoldsP1Only();
    ListAppender<ILoggingEvent> logs = startLogCapture();

    try {
      assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);
    } finally {
      stopLogCapture(logs);
    }

    verify(rbacAuditPort, times(1))
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "MEMBER", actorId, ctx),
            DenialReason.GRANT_EXCEEDS_CALLER, "assign", 2);
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());

    ILoggingEvent warn =
        logs.list.stream()
            .filter(e -> "RBAC_GRANT_EXCEEDS_CALLER".equals(keyValueMap(e).get("event")))
            .findFirst()
            .orElseThrow();
    assertThat(warn.getLevel()).isEqualTo(Level.WARN);
    Map<String, Object> fields = keyValueMap(warn);
    assertThat(fields)
        .containsEntry("tenantId", tenantId)
        .containsEntry("actorUserId", actorId)
        .containsEntry("targetUserId", targetUserId)
        .containsEntry("roleId", roleId)
        .containsEntry("missingCount", 2);
    assertThat(fields.values()).doesNotContain(lackedA, lackedB, P1);
    assertThat(warn.getFormattedMessage())
        .doesNotContain(lackedA.toString())
        .doesNotContain(lackedB.toString());
  }

  @Test
  void should_reportUserRoleAssignAsRequiredPermission_when_grantExceedsCaller() {
    stubBenignAssignTarget();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(UUID.randomUUID())));

    // The endpoint permission, never the missing one: no oracle on the role's contents.
    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getRequiredPermission())
                    .isEqualTo("user:role:assign"));
  }

  @Test
  void should_reportGrantExceedsCallerOnceAndNeverCheckDuplicate_when_A2AndDuplicateBothApply() {
    stubBenignAssignTarget();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P1, UUID.randomUUID())));
    stubCallerHoldsP1Only();

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    verify(rbacAuditPort, times(1))
        .recordRoleAssignmentDenied(
            any(), eq(DenialReason.GRANT_EXCEEDS_CALLER), eq("assign"), eq(1));
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
    verify(throttlePort, times(1)).recordDenial(tenantId, actorId);
    verify(userRoleAssignmentPort, never()).hasActiveAssignment(any(), any());
  }

  // ---------------------------------------------------------------------------------------
  // L-1 (the endpoint permission must still be held, fresh M13) and L-2 (M14 fails closed)
  // ---------------------------------------------------------------------------------------

  @Test
  void should_deny403PermissionAbsentBeforeA2_when_assignCallerNoLongerHoldsUserRoleAssign() {
    stubBenignAssignTarget();
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(List.of(ref(UUID.randomUUID(), P1)));
    // A2 alone would pass: the target role carries only what the caller holds.
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P1)));

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> {
              assertThat(e.getReason()).isEqualTo(DenialReason.PERMISSION_ABSENT);
              assertThat(e.getRequiredPermission()).isEqualTo("user:role:assign");
            });

    verify(rbacAuditPort, times(1))
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "MEMBER", actorId, ctx),
            DenialReason.PERMISSION_ABSENT, "assign");
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any(), any());
    verify(throttlePort, times(1)).recordDenial(tenantId, actorId);
    verify(userRoleAssignmentPort, never()).hasActiveAssignment(any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verifyNoInteractions(permissionCachePort);
  }

  @Test
  void should_deny403PermissionAbsentBeforeA4_when_selfAssignWithoutUserRoleAssign() {
    stubBenignSelfAssignTarget();
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(List.of());

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.PERMISSION_ABSENT));

    verify(rbacAuditPort, times(1)).recordRoleAssignmentDenied(any(), any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
  }

  @Test
  void should_logEndpointPermissionNotHeldWarnWithIdsOnly_when_l1Denies() {
    stubBenignAssignTarget();
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(List.of());
    ListAppender<ILoggingEvent> logs = startLogCapture();

    try {
      assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);
    } finally {
      stopLogCapture(logs);
    }

    ILoggingEvent warn =
        logs.list.stream()
            .filter(e -> "RBAC_ENDPOINT_PERMISSION_NOT_HELD".equals(keyValueMap(e).get("event")))
            .findFirst()
            .orElseThrow();
    assertThat(warn.getLevel()).isEqualTo(Level.WARN);
    assertThat(keyValueMap(warn))
        .containsOnlyKeys("event", "tenantId", "actorUserId", "targetUserId", "roleId", "operation")
        .containsEntry("operation", "assign");
  }

  @Test
  void should_throwRoleNotFoundAndNotSave_when_m14ReportsRoleNotInTenantOnAssign() {
    stubBenignAssignTarget();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");

    verifyNoInteractions(rbacAuditPort);
    verify(userRoleAssignmentPort, never()).hasActiveAssignment(any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
  }

  // ---------------------------------------------------------------------------------------
  // T-018 (row 7, RC-28.1): the independent check on a successful self-target assignment
  // ---------------------------------------------------------------------------------------

  /** RC-28.1: A4 passed, the independent per-role statement says "not an administrator". */
  @Test
  void should_emitErrorAndCountDisagreement_when_independentCheckDisagreesWithA4() {
    stubBenignSelfAssignTarget();
    stubSuccessfulSelfInsert();
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.findHeldAdminDefiningRoleIds(actorId, tenantId))
        .thenReturn(List.of());
    ListAppender<ILoggingEvent> logs = startLogCapture();

    try {
      service.assign(actor, actorId, roleId, ctx);
    } finally {
      stopLogCapture(logs);
    }

    ILoggingEvent error =
        logs.list.stream()
            .filter(e -> "RBAC_SELF_ASSIGN_ADMIN_DISAGREEMENT".equals(keyValueMap(e).get("event")))
            .findFirst()
            .orElseThrow();
    assertThat(error.getLevel()).isEqualTo(Level.ERROR);
    assertThat(keyValueMap(error))
        .containsOnlyKeys("event", "tenantId", "actorUserId", "roleId")
        .containsEntry("tenantId", tenantId)
        .containsEntry("actorUserId", actorId)
        .containsEntry("roleId", roleId);
    Counter counter = meterRegistry.find("nexus.rbac.self_assign_admin_disagreement").counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
    // Never consulted for authorization: the request still succeeded.
    verify(userRoleAssignmentPort).assign(actorId, roleId, tenantId, actorId);
  }

  @Test
  void should_emitNothing_when_independentCheckAgreesWithA4() {
    stubBenignSelfAssignTarget();
    stubSuccessfulSelfInsert();
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.findHeldAdminDefiningRoleIds(actorId, tenantId))
        .thenReturn(List.of(UUID.randomUUID()));
    ListAppender<ILoggingEvent> logs = startLogCapture();

    try {
      service.assign(actor, actorId, roleId, ctx);
    } finally {
      stopLogCapture(logs);
    }

    assertThat(logs.list.stream().filter(e -> e.getLevel() == Level.ERROR)).isEmpty();
    assertThat(meterRegistry.find("nexus.rbac.self_assign_admin_disagreement").counter()).isNull();
  }

  /** US-017 RES-25's lesson: the read happens BEFORE the insert, never after. */
  @Test
  void should_runTheIndependentCheckBeforeTheInsert_notAfter() {
    stubBenignSelfAssignTarget();
    stubSuccessfulSelfInsert();
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.findHeldAdminDefiningRoleIds(actorId, tenantId))
        .thenReturn(List.of(UUID.randomUUID()));

    service.assign(actor, actorId, roleId, ctx);

    InOrder inOrder = Mockito.inOrder(userRoleAssignmentPort);
    inOrder.verify(userRoleAssignmentPort).findHeldAdminDefiningRoleIds(actorId, tenantId);
    inOrder.verify(userRoleAssignmentPort).assign(actorId, roleId, tenantId, actorId);
  }

  @Test
  void should_notRunTheIndependentCheck_when_targetIsAnotherUser() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort, never()).findHeldAdminDefiningRoleIds(any(), any());
  }

  /** It is never consulted for authorization: A4's denial happens without reading it. */
  @Test
  void should_notRunTheIndependentCheck_when_selfAssignmentIsDenied() {
    stubBenignSelfAssignTarget();
    stubCallerHoldsP1Only();

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verify(userRoleAssignmentPort, never()).findHeldAdminDefiningRoleIds(any(), any());
  }

  @Test
  void should_notRunTheIndependentCheck_when_assignmentIsADuplicate() {
    stubBenignSelfAssignTarget();
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.hasActiveAssignment(actorId, roleId)).thenReturn(true);

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .isInstanceOf(DuplicateRoleAssignmentException.class);

    verify(userRoleAssignmentPort, never()).findHeldAdminDefiningRoleIds(any(), any());
  }

  @Test
  void should_propagateAndNotInsert_when_independentCheckReadThrows() {
    stubBenignSelfAssignTarget();
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.hasActiveAssignment(actorId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.findHeldAdminDefiningRoleIds(actorId, tenantId))
        .thenThrow(new RuntimeException("db down"));

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .isInstanceOf(RuntimeException.class)
        .hasMessage("db down");

    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
  }

  // ---------------------------------------------------------------------------------------
  // T-018 (row 9): admin_role_assigned{selfTarget}, and the retired meters stay gone
  // ---------------------------------------------------------------------------------------

  @Test
  void should_countAdminRoleAssignedWithSelfTargetFalse_when_anAdminDefiningRoleIsAssignedToAnotherUser() {
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(holder(actorId, roleId)));
    stubCallerIsAdministrator();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    Counter counter =
        meterRegistry.find("nexus.rbac.admin_role_assigned").tag("selfTarget", "false").counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
  }

  @Test
  void should_countAdminRoleAssignedWithSelfTargetTrue_when_anAdministratorAssignsAnAdminDefiningRoleToSelf() {
    stubTargetUserAndRole(actorId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(holder(actorId, roleId)));
    stubCallerIsAdministrator();
    stubSuccessfulSelfInsert();
    when(userRoleAssignmentPort.findHeldAdminDefiningRoleIds(actorId, tenantId))
        .thenReturn(List.of(roleId));

    service.assign(actor, actorId, roleId, ctx);

    Counter counter =
        meterRegistry.find("nexus.rbac.admin_role_assigned").tag("selfTarget", "true").counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
  }

  @Test
  void should_notCountAdminRoleAssigned_when_targetRoleIsNotAdminDefining() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    assertThat(meterRegistry.find("nexus.rbac.admin_role_assigned").counter()).isNull();
  }

  @Test
  void should_notEmitAnyRetiredMeter_when_assigningAnAdminDefiningRole() {
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(holder(actorId, roleId)));
    stubCallerIsAdministrator();
    stubSuccessfulInsert();
    service.assign(actor, targetUserId, roleId, ctx);

    assertThat(
            meterRegistry.getMeters().stream()
                .map(meter -> meter.getId().getName())
                .filter(
                    name ->
                        name.equals("nexus.rbac.self_role_assignment")
                            || name.equals("nexus.rbac.privileged_role_change_allowed")
                            || name.equals("nexus.rbac.privileged_role_change_blocked")
                            || name.equals("nexus.rbac.admin_minted_by_non_named_admin")))
        .isEmpty();
  }

  // ---------------------------------------------------------------------------------------
  // revoke(): tenant isolation, errors, side effects
  // ---------------------------------------------------------------------------------------

  @Test
  void should_revokeAndFireSideEffectsWithRecordRoleRevoked_when_happyPathBenign() {
    ActiveAssignmentRef ref = stubBenignRevokeTarget();
    when(userRoleAssignmentPort.revoke(eq(ref.id()), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(userRoleAssignmentPort, never()).findRolePermissionIdsForTenantRoles(any());
    InOrder inOrder = Mockito.inOrder(rbacAuditPort, permissionCachePort);
    inOrder
        .verify(rbacAuditPort)
        .recordRoleRevoked(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "MEMBER", actorId, ctx));
    inOrder.verify(permissionCachePort).evict(tenantId, targetUserId);
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any(), any());
  }

  @Test
  void should_invalidateUserOnlyInsideAfterCommit_when_revokeInsideSynchronization() {
    stubHappyPathRevoke();
    boolean[] insideAfterCommit = {false};
    doAnswer(
            invocation -> {
              assertThat(insideAfterCommit[0])
                  .as("invalidateUser called with an active synchronization outside afterCommit")
                  .isTrue();
              return null;
            })
        .when(permissionFreshness)
        .invalidateUser(any(), any(), any());

    TransactionSynchronizationManager.initSynchronization();
    try {
      service.revoke(actor, targetUserId, roleId, ctx);

      verifyNoInteractions(permissionFreshness);
      insideAfterCommit[0] = true;
      for (TransactionSynchronization synchronization :
          TransactionSynchronizationManager.getSynchronizations()) {
        synchronization.afterCommit();
      }
    } finally {
      TransactionSynchronizationManager.clearSynchronization();
    }

    verify(permissionFreshness).invalidateUser(tenantId, targetUserId, "revoke");
  }

  @Test
  void should_neverInvalidate_when_transactionRollsBack() {
    stubHappyPathRevoke();

    TransactionSynchronizationManager.initSynchronization();
    try {
      service.revoke(actor, targetUserId, roleId, ctx);
      for (TransactionSynchronization synchronization :
          TransactionSynchronizationManager.getSynchronizations()) {
        synchronization.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK);
      }
    } finally {
      TransactionSynchronizationManager.clearSynchronization();
    }

    verifyNoInteractions(permissionFreshness);
  }

  @Test
  void should_neverInvalidate_when_revokeDenied() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(otherTenantId));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RuntimeException.class);

    verifyNoInteractions(permissionFreshness);
  }

  @Test
  void should_invalidateTargetNotActor_when_revokeSucceeds() {
    stubHappyPathRevoke();

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(permissionFreshness).invalidateUser(tenantId, targetUserId, "revoke");
    verify(permissionFreshness, never()).invalidateUser(tenantId, actorId, "revoke");
  }

  private void stubHappyPathRevoke() {
    ActiveAssignmentRef ref = stubBenignRevokeTarget();
    when(userRoleAssignmentPort.revoke(eq(ref.id()), any())).thenReturn(1);
  }

  @Test
  void should_throwResourceNotFound_when_revokeTargetUserNotFound() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "USER_NOT_FOUND");

    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  @Test
  void should_throwSameNotFoundAndWriteNoDenialRow_when_revokeTargetTenantMismatch() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(otherTenantId));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "USER_NOT_FOUND")
        .hasMessage("No such user");

    verifyNoInteractions(permissionCachePort, rbacAuditPort);
    assertThat(
            meterRegistry
                .get("nexus.rbac.permission_denied")
                .tag("permission", "user:role:assign")
                .tag("reason", "CROSS_TENANT_TARGET")
                .counter()
                .count())
        .isEqualTo(1.0);
  }

  @Test
  void should_logCrossTenantWarnWithoutForeignIds_when_revokeTargetCrossTenant() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(otherTenantId));

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
          .isInstanceOf(ResourceNotFoundException.class);

      var warns = appender.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
      assertThat(warns).hasSize(1);
      assertThat(keyValueMap(warns.get(0)))
          .containsOnlyKeys("event", "tenantId", "actorUserId", "targetKind", "operation")
          .containsEntry("event", "RBAC_CROSS_TENANT_TARGET")
          .containsEntry("targetKind", "user")
          .containsEntry("operation", "revoke");
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_throwResourceNotFound_when_revokeRoleNotFound() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");

    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  @Test
  void should_throwSameNotFoundAndWriteNoDenialRow_when_revokeRoleTenantMismatch() {
    Role foreignRole = new Role(roleId, otherTenantId, "MEMBER", "desc", false);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(foreignRole));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND")
        .hasMessage("No such role");

    verify(userRoleAssignmentPort, never()).findActiveAssignmentRef(any(), any(), any());
    verifyNoInteractions(permissionCachePort, rbacAuditPort);
    assertThat(
            meterRegistry
                .get("nexus.rbac.permission_denied")
                .tag("permission", "user:role:assign")
                .tag("reason", "CROSS_TENANT_TARGET")
                .counter()
                .count())
        .isEqualTo(1.0);
  }

  /**
   * The assignment lookup (M3) runs before the throttle and every authorization read: a missing
   * assignment is a 404 for a benign and an admin-defining role alike, and no lock is ever taken.
   */
  @Test
  void should_neverLockOrClassify_when_assignmentNotFound() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role("TENANT_ADMIN")));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_ASSIGNMENT_NOT_FOUND");

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(userRoleAssignmentPort, never()).findPermissionIdsForRole(any(), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  @Test
  void should_throwResourceNotFound_when_revokeLosesRaceAndZeroRowsAffected() {
    ActiveAssignmentRef ref = stubBenignRevokeTarget();
    when(userRoleAssignmentPort.revoke(eq(ref.id()), any())).thenReturn(0);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_ASSIGNMENT_NOT_FOUND");

    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  @Test
  void should_abortRevocationWithRoleClassificationChanged_when_rolePromotedConcurrentlyWhileRevoking() {
    ActiveAssignmentRef ref = stubBenignRevokeTarget();
    when(userRoleAssignmentPort.lockRolePermissionsForRoles(tenantId, List.of(roleId)))
        .thenReturn(wholeCatalogue(roleId));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RoleClassificationChangedException.class);

    verify(userRoleAssignmentPort, never()).revoke(eq(ref.id()), any());
    verifyNoInteractions(rbacAuditPort);
  }

  /** Fail closed on revoke: a failing classification read is never treated as "allow". */
  @Test
  void should_propagateAndWriteNothing_when_revokeClassificationReadThrows() {
    stubBenignRevokeTarget();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenThrow(new RuntimeException("db down"));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RuntimeException.class)
        .hasMessage("db down");

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
  }

  @Test
  void should_propagateAndWriteNothing_when_revokeTenantRoleSetReadThrows() {
    stubRevokeTarget(role("ADMIN_LIKE"));
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(CATALOGUE));
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId))
        .thenThrow(new RuntimeException("db down"));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RuntimeException.class)
        .hasMessage("db down");

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
  }

  @Test
  void should_propagateRecordErrorTimerAndWriteNothing_when_revokeDecisionReadThrows() {
    stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(holder(actorId, roleId)));
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenThrow(new RuntimeException("db down"));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RuntimeException.class)
        .hasMessage("db down");

    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    assertThat(
            meterRegistry
                .find("nexus.rbac.privileged_revoke_lock_hold")
                .tags("operation", "revoke", "outcome", "error")
                .timer())
        .isNotNull();
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
  }

  // ---------------------------------------------------------------------------------------
  // T-016 (row 2, rows 3 and 5): revoke-subset, the administrator requirement, the lockout
  // ---------------------------------------------------------------------------------------

  /** Revoke-subset, union part: the role carries a permission the caller lacks (GRANT_EXCEEDS_CALLER). */
  @Test
  void should_deny403GrantExceedsCallerWithOneDenialRow_when_revokeTargetCarriesPermissionCallerLacks() {
    ActiveAssignmentRef ref = stubBenignRevokeTarget();
    stubCallerHoldsP1Only();
    // Not admin-defining (the catalogue is P1 and P2): the union check alone decides.
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P1, UUID.randomUUID())));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> {
              assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER);
              assertThat(e.getRequiredPermission()).isEqualTo("user:role:assign");
            });

    verify(rbacAuditPort, times(1))
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "MEMBER", actorId, ctx),
            DenialReason.GRANT_EXCEEDS_CALLER, "revoke", 1);
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
    verify(throttlePort, times(1)).recordDenial(tenantId, actorId);
    verify(userRoleAssignmentPort, never()).revoke(eq(ref.id()), any());
    verifyNoInteractions(permissionCachePort);
  }

  @Test
  void should_revoke_when_revokeTargetPermissionsWithinCallerHoldings() {
    ActiveAssignmentRef ref = stubBenignRevokeTarget();
    stubCallerHoldsP1Only();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P1)));
    when(userRoleAssignmentPort.revoke(eq(ref.id()), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort).revoke(eq(ref.id()), any());
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any(), any());
    verify(rbacAuditPort)
        .recordRoleRevoked(new RbacAuditEvent(tenantId, targetUserId, roleId, "MEMBER", actorId, ctx));
  }

  @Test
  void should_revoke_when_revokeTargetRoleHasNoPermissions() {
    ActiveAssignmentRef ref = stubBenignRevokeTarget();
    when(userRoleAssignmentPort.revoke(eq(ref.id()), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort).revoke(eq(ref.id()), any());
  }

  /**
   * Behaviour change (T-016 risk): a caller without {@code user:read} can no longer revoke MEMBER,
   * which carries it. The fixture models MEMBER with {@code P1} and the caller holding only
   * {@code user:role:assign}.
   */
  @Test
  void should_deny403_when_callerWithoutTheMemberPermissionRevokesMember() {
    stubBenignRevokeTarget();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P1)));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    verify(userRoleAssignmentPort, never()).revoke(any(), any());
  }

  /**
   * RC-26.2 (T-E34): a union-holder passes the subset comparison on an admin-defining role but is
   * not an administrator by M11's rows, so they cannot strip an administrator. The reason is
   * NOT_TENANT_ADMIN (A-13), one denial row, one throttle denial; the timer closes as denied.
   */
  @Test
  void should_deny403NotTenantAdmin_when_unionHolderRevokesAnAdminDefiningRole_RC262() {
    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(
        List.of(
            new ActiveAssignmentHolder(ref.id(), targetUserId, roleId, ANY_ASSIGNER),
            holder(UUID.randomUUID(), roleId)));
    lenientCallerIsUnionHolder();

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> {
              assertThat(e.getReason()).isEqualTo(DenialReason.NOT_TENANT_ADMIN);
              assertThat(e.getRequiredPermission()).isEqualTo("user:role:assign");
            });

    verify(rbacAuditPort, times(1))
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "ADMIN_LIKE", actorId, ctx),
            DenialReason.NOT_TENANT_ADMIN, "revoke");
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any(), any());
    verify(throttlePort, times(1)).recordDenial(tenantId, actorId);
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    assertThat(meterRegistry.find("nexus.rbac.last_admin_lockout_blocked").counter()).isNull();
    assertThat(
            meterRegistry
                .find("nexus.rbac.privileged_revoke_lock_hold")
                .tags("operation", "revoke", "outcome", "denied")
                .timer())
        .isNotNull();
  }

  /** The administrator comes from M11's rows even when M13 says otherwise (RC-25.1). */
  @Test
  void should_deny403NotTenantAdmin_when_m13SaysAdministratorButLockedRowsDoNotContainTheCaller() {
    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(
        List.of(
            new ActiveAssignmentHolder(ref.id(), targetUserId, roleId, ANY_ASSIGNER),
            holder(UUID.randomUUID(), roleId)));
    lenientCallerIsAdministrator();

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort, never()).revoke(any(), any());
  }

  /**
   * The administrator requirement comes first and needs no holdings read: a caller who is not an
   * administrator of an admin-defining role gets NOT_TENANT_ADMIN whatever else they lack (A-13),
   * and the live holdings (M13) are never read.
   */
  @Test
  void should_denyNotTenantAdminWithoutReadingHoldings_when_callerIsNotAnAdministratorAndLacksPermissions() {
    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(new ActiveAssignmentHolder(
            ref.id(), targetUserId, roleId, ANY_ASSIGNER)));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort, never()).findHeldRolePermissionIdsForAuthorization(any(), any());
    verify(rbacAuditPort, times(1)).recordRoleAssignmentDenied(any(), any(), any());
  }

  /** An administrator who nevertheless lacks a permission of the role gets GRANT_EXCEEDS_CALLER. */
  @Test
  void should_denyGrantExceedsCaller_when_theAdministratorsLiveHoldingsLackAPermissionOfTheRole() {
    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(
        List.of(
            new ActiveAssignmentHolder(
                    ref.id(), targetUserId, roleId, ANY_ASSIGNER), holder(actorId, roleId)));
    stubCallerHoldsP1Only();

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    verify(rbacAuditPort, times(1))
        .recordRoleAssignmentDenied(any(), eq(DenialReason.GRANT_EXCEEDS_CALLER), eq("revoke"), eq(1));
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
  }

  /**
   * ADR-0017 D4: 403 always precedes 409. A non-administrator revoking the tenant's last
   * administrator gets 403; the lockout never tells them it is the last one.
   */
  @Test
  void should_return403NotLockoutConflict_when_nonAdministratorRevokesTheLastAdministrator() {
    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(new ActiveAssignmentHolder(
            ref.id(), targetUserId, roleId, ANY_ASSIGNER)));
    lenientCallerIsUnionHolder();

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    assertThat(meterRegistry.find("nexus.rbac.last_admin_lockout_blocked").counter()).isNull();
  }

  /** AC5: the actor revokes their OWN last administrator assignment. */
  @Test
  void should_throwLastAdminRoleException_when_administratorRevokesTheirOwnLastAssignment() {
    ActiveAssignmentRef ref = stubRevokeTargetFor(actorId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(new ActiveAssignmentHolder(
            ref.id(), actorId, roleId, ANY_ASSIGNER)));
    stubCallerIsAdministrator();

    assertThatThrownBy(() -> service.revoke(actor, actorId, roleId, ctx))
        .isInstanceOf(LastAdminRoleException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_002");

    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(permissionCachePort, rbacAuditPort);
    Counter counter = meterRegistry.find("nexus.rbac.last_admin_lockout_blocked").counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
  }

  @Test
  void should_revokeSuccessfully_when_anotherDistinctAdministratorRemains() {
    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(
        List.of(
            new ActiveAssignmentHolder(ref.id(), targetUserId, roleId, ANY_ASSIGNER),
            holder(actorId, roleId)));
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.revoke(eq(ref.id()), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort).revoke(eq(ref.id()), any());
    verify(permissionCachePort).evict(tenantId, targetUserId);
    verify(rbacAuditPort)
        .recordRoleRevoked(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "ADMIN_LIKE", actorId, ctx));
  }

  /**
   * MC-D / Edge Case 1: one user holding TWO admin-defining roles is counted ONCE, and excluding
   * the row being revoked (by assignment id, never by user id) still leaves that user counted
   * through their other admin-defining assignment: not a lockout.
   */
  @Test
  void should_notLockOut_when_targetUserHoldsAnotherAdminDefiningRoleViaADifferentAssignment_MCD() {
    UUID otherAdminRoleId = UUID.randomUUID();
    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(
        List.of(
            new ActiveAssignmentHolder(ref.id(), targetUserId, roleId, ANY_ASSIGNER),
            new ActiveAssignmentHolder(
                    UUID.randomUUID(), targetUserId, otherAdminRoleId, ANY_ASSIGNER),
            holder(actorId, otherAdminRoleId)),
        otherAdminRoleId);
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.revoke(eq(ref.id()), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort).revoke(eq(ref.id()), any());
  }

  /** A different user holding another admin-defining role also prevents a lockout. */
  @Test
  void should_notLockOut_when_aDifferentUserHoldsAnotherAdminDefiningRole() {
    UUID otherAdminRoleId = UUID.randomUUID();
    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(
        List.of(
            new ActiveAssignmentHolder(ref.id(), targetUserId, roleId, ANY_ASSIGNER),
            holder(actorId, otherAdminRoleId)),
        otherAdminRoleId);
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.revoke(eq(ref.id()), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort).revoke(eq(ref.id()), any());
  }

  // ---------------------------------------------------------------------------------------
  // US-019 T-021 (RC-57.2, T-E49): under the set lock, revoke classifies the locked roles from
  // the current FOR SHARE read, never from the pre-lock M10' read
  // ---------------------------------------------------------------------------------------

  /**
   * A B8 demotion of the other administrator's role committed while this revoke waited on the set
   * lock: M10' still calls that role admin-defining, the current read does not. The lockout must
   * count from the current read, so the caller's own last administrator assignment stays.
   */
  @Test
  void should_throwLastAdminRoleException_when_m10PrimeCallsTheOtherHoldersRoleAdminDefiningButTheCurrentReadDoesNot() {
    UUID demotedRoleId = UUID.randomUUID();
    ActiveAssignmentRef ref = stubRevokeTargetFor(actorId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(
        List.of(
            new ActiveAssignmentHolder(ref.id(), actorId, roleId, ANY_ASSIGNER),
            holder(UUID.randomUUID(), demotedRoleId)),
        demotedRoleId);
    List<RolePermissionRef> current = new ArrayList<>(wholeCatalogue(roleId));
    current.add(ref(demotedRoleId, P1));
    stubCurrentReadUnderTheSetLock(current);
    stubCallerIsAdministrator();

    assertThatThrownBy(() -> service.revoke(actor, actorId, roleId, ctx))
        .isInstanceOf(LastAdminRoleException.class);

    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(rbacAuditPort);
  }

  /**
   * The caller's only administrator role was demoted while this revoke waited on the set lock: the
   * administrator requirement follows the current read, so 403 NOT_TENANT_ADMIN, whatever M10' and
   * the snapshot holdings say.
   */
  @Test
  void should_deny403NotTenantAdmin_when_theCallersOnlyAdministratorRoleIsNoLongerAdminDefiningInTheCurrentRead() {
    UUID demotedRoleId = UUID.randomUUID();
    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(
        List.of(
            new ActiveAssignmentHolder(ref.id(), targetUserId, roleId, ANY_ASSIGNER),
            holder(actorId, demotedRoleId)),
        demotedRoleId);
    List<RolePermissionRef> current = new ArrayList<>(wholeCatalogue(roleId));
    current.add(ref(demotedRoleId, P1));
    stubCurrentReadUnderTheSetLock(current);
    lenientCallerIsAdministrator();

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort, never()).revoke(any(), any());
  }

  /** The current read covers exactly the lock set and runs after the set lock, before the write. */
  @Test
  void should_readTheLockSetsCurrentPermissionsAfterTheSetLock_when_revokingAnAdminDefiningRole() {
    UUID otherAdminRoleId = UUID.randomUUID();
    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(
        List.of(
            new ActiveAssignmentHolder(ref.id(), targetUserId, roleId, ANY_ASSIGNER),
            holder(actorId, otherAdminRoleId)),
        otherAdminRoleId);
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.revoke(eq(ref.id()), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<UUID>> lockSet = ArgumentCaptor.forClass(List.class);
    InOrder order = Mockito.inOrder(userRoleAssignmentPort);
    order.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), lockSet.capture());
    order.verify(userRoleAssignmentPort).lockRolePermissionsForRoles(tenantId, lockSet.getValue());
    order.verify(userRoleAssignmentPort).revoke(eq(ref.id()), any());
    assertThat(lockSet.getValue()).containsExactlyInAnyOrder(roleId, otherAdminRoleId);
  }

  /**
   * Row 5: the population is the holders of admin-defining roles, nothing narrower or wider. A
   * locked holder of a role that is NOT admin-defining (it is in the lock set only as the target
   * would be) does not prevent the lockout.
   */
  @Test
  void should_throwLastAdminRoleException_when_theOnlyOtherLockedHolderIsNotAnAdministrator() {
    UUID notAdminDefiningRoleId = UUID.randomUUID();
    ActiveAssignmentRef ref = stubRevokeTargetFor(actorId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(
        List.of(
            new ActiveAssignmentHolder(ref.id(), actorId, roleId, ANY_ASSIGNER),
            holder(UUID.randomUUID(), notAdminDefiningRoleId)));
    stubCallerIsAdministrator();

    assertThatThrownBy(() -> service.revoke(actor, actorId, roleId, ctx))
        .isInstanceOf(LastAdminRoleException.class);
  }

  /** Edge Case 3: the lockout predicate is deterministic regardless of the rows' order. */
  @Test
  void should_produceSameResult_regardlessOfLockedHoldersListOrder_EdgeCase3() {
    UUID refId = UUID.randomUUID();
    UUID otherUserId = UUID.randomUUID();
    UUID otherRoleId = UUID.randomUUID();
    Set<UUID> adminDefiningRoleIds = Set.of(otherRoleId);
    ActiveAssignmentHolder revoked = new ActiveAssignmentHolder(
            refId, targetUserId, roleId, ANY_ASSIGNER);
    ActiveAssignmentHolder other =
        new ActiveAssignmentHolder(UUID.randomUUID(), otherUserId, otherRoleId, ANY_ASSIGNER);

    boolean natural =
        RoleAssignmentService.wouldLeaveTenantWithoutAdministrator(
            List.of(revoked, other), refId, adminDefiningRoleIds);
    boolean reversed =
        RoleAssignmentService.wouldLeaveTenantWithoutAdministrator(
            List.of(other, revoked), refId, adminDefiningRoleIds);

    assertThat(natural).isFalse();
    assertThat(reversed).isEqualTo(natural);
  }

  @Test
  void should_excludeNoRow_when_revokedAssignmentIdIsNull_breakGlassUse() {
    ActiveAssignmentHolder holder = new ActiveAssignmentHolder(
            UUID.randomUUID(), targetUserId, roleId, ANY_ASSIGNER);

    assertThat(
            RoleAssignmentService.wouldLeaveTenantWithoutAdministrator(
                List.of(holder), null, Set.of(roleId)))
        .isFalse();
    assertThat(
            RoleAssignmentService.wouldLeaveTenantWithoutAdministrator(
                List.of(), null, Set.of(roleId)))
        .isTrue();
  }

  // ---------------------------------------------------------------------------------------
  // Lock set: ascending unsigned byte-wise order (MC-E), size summary, hold timer (row 10)
  // ---------------------------------------------------------------------------------------

  /**
   * MC-E, {@code revoke()} half: the role-id list passed to M11 is sorted by UNSIGNED byte-wise
   * order of the 16-byte representation, explicitly NOT {@link UUID#compareTo}, which compares
   * {@code mostSigBits} as a SIGNED {@code long}. {@code lowBitRoleId} has {@code mostSigBits = 1L};
   * {@code highBitRoleId} has {@code Long.MIN_VALUE}. Unsigned ascending is {@code [low, high]};
   * signed ascending is the reverse. A test that only asserted "sorted" would pass under either.
   */
  @Test
  void should_sortLockSetByUnsignedBytewiseOrder_notUuidCompareTo_when_revoking_MCE() {
    UUID lowBitRoleId = new UUID(1L, 0L);
    UUID highBitRoleId = new UUID(Long.MIN_VALUE, 0L);
    assertThat(lowBitRoleId.compareTo(highBitRoleId))
        .as("fixture precondition: signed UUID.compareTo must rank lowBitRoleId AFTER highBitRoleId")
        .isGreaterThan(0);
    roleId = lowBitRoleId;

    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(
        List.of(
            new ActiveAssignmentHolder(ref.id(), targetUserId, lowBitRoleId, ANY_ASSIGNER),
            holder(actorId, highBitRoleId)),
        highBitRoleId);
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.revoke(eq(ref.id()), any())).thenReturn(1);

    service.revoke(actor, targetUserId, lowBitRoleId, ctx);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<UUID>> lockSetCaptor = ArgumentCaptor.forClass(List.class);
    verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), lockSetCaptor.capture());
    assertThat(lockSetCaptor.getValue()).containsExactly(lowBitRoleId, highBitRoleId);
    assertThat(lockSetCaptor.getValue())
        .as("must NOT equal UUID.compareTo's (signed) ascending order")
        .isNotEqualTo(List.of(highBitRoleId, lowBitRoleId));
  }

  /** MC-E, {@code assign()} half: the same order for the set lock taken on assign. */
  @Test
  void should_sortLockSetByUnsignedBytewiseOrder_notUuidCompareTo_when_assigning_MCE() {
    UUID lowBitRoleId = new UUID(1L, 0L);
    UUID highBitRoleId = new UUID(Long.MIN_VALUE, 0L);
    roleId = lowBitRoleId;
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(holder(actorId, highBitRoleId)), highBitRoleId);
    stubCallerIsAdministrator();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, lowBitRoleId, ctx);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<UUID>> lockSetCaptor = ArgumentCaptor.forClass(List.class);
    verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), lockSetCaptor.capture());
    assertThat(lockSetCaptor.getValue()).containsExactly(lowBitRoleId, highBitRoleId);
  }

  @Test
  void should_includeTheTargetRoleOnce_when_buildingTheLockSet() {
    UUID other = UUID.randomUUID();

    List<UUID> lockSet = RoleAssignmentService.buildAscendingLockSet(Set.of(other, roleId), roleId);

    assertThat(lockSet).containsExactlyInAnyOrder(other, roleId).doesNotHaveDuplicates();
  }

  @Test
  void should_includeTheTargetRole_when_noRoleIsAdminDefiningYet() {
    assertThat(RoleAssignmentService.buildAscendingLockSet(Set.of(), roleId))
        .containsExactly(roleId);
  }

  @Test
  void should_readM10PrimeOnceAndDecideByCatalogue_when_resolvingAdminDefiningRoleIds() {
    UUID adminRole = UUID.randomUUID();
    UUID shortRole = UUID.randomUUID();
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId))
        .thenReturn(
            List.of(ref(adminRole, P1), ref(adminRole, P2), ref(shortRole, P1)));

    Set<UUID> ids =
        RoleAssignmentService.resolveAdminDefiningRoleIds(
            userRoleAssignmentPort, tenantId, CATALOGUE);

    assertThat(ids).containsExactly(adminRole);
    verify(userRoleAssignmentPort, times(1)).findRolePermissionIdsForTenantRoles(tenantId);
  }

  @Test
  void should_recordLockHoldTimerOutcomeLockout_when_administratorRevokesTheirOwnLastAssignment() {
    ActiveAssignmentRef ref = stubRevokeTargetFor(actorId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(new ActiveAssignmentHolder(
            ref.id(), actorId, roleId, ANY_ASSIGNER)));
    stubCallerIsAdministrator();

    assertThatThrownBy(() -> service.revoke(actor, actorId, roleId, ctx))
        .isInstanceOf(LastAdminRoleException.class);

    var timer =
        meterRegistry.find("nexus.rbac.privileged_revoke_lock_hold").tags("outcome", "lockout").timer();
    assertThat(timer).isNotNull();
    assertThat(timer.count()).isEqualTo(1L);
  }

  @Test
  void should_recordLockHoldTimerOutcomeRevoked_when_adminDefiningRevokeSucceeds() {
    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(
        List.of(new ActiveAssignmentHolder(
                ref.id(), targetUserId, roleId, ANY_ASSIGNER), holder(actorId, roleId)));
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.revoke(eq(ref.id()), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    var timer =
        meterRegistry.find("nexus.rbac.privileged_revoke_lock_hold").tags("outcome", "revoked").timer();
    assertThat(timer).isNotNull();
    assertThat(timer.count()).isEqualTo(1L);
  }

  @Test
  void should_recordLockHoldTimerOutcomeAssigned_when_adminDefiningAssignSucceeds() {
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(holder(actorId, roleId)));
    stubCallerIsAdministrator();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    var timer =
        meterRegistry
            .find("nexus.rbac.privileged_revoke_lock_hold")
            .tags("operation", "assign", "outcome", "assigned")
            .timer();
    assertThat(timer).isNotNull();
    assertThat(timer.count()).isEqualTo(1L);
  }

  @Test
  void should_recordLockHoldTimerOutcomeConflict_when_adminDefiningAssignIsADuplicate() {
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(holder(actorId, roleId)));
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(true);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(DuplicateRoleAssignmentException.class);

    assertThat(
            meterRegistry
                .find("nexus.rbac.privileged_revoke_lock_hold")
                .tags("outcome", "conflict")
                .timer())
        .isNotNull();
  }

  @Test
  void should_recordLockSetSizeDistributionSummary_when_assigningAdminDefiningRole() {
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(
        List.of(holder(actorId, roleId), holder(UUID.randomUUID(), roleId)));
    stubCallerIsAdministrator();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    DistributionSummary summary =
        meterRegistry.find("nexus.rbac.admin_equivalent_lock_set_size").summary();
    assertThat(summary).isNotNull();
    assertThat(summary.count()).isEqualTo(1L);
    assertThat(summary.totalAmount()).isEqualTo(2.0);
  }

  @Test
  void should_recordLockSetSizeDistributionSummary_when_revokingAdminDefiningRole() {
    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(
        List.of(
            new ActiveAssignmentHolder(ref.id(), targetUserId, roleId, ANY_ASSIGNER),
            holder(actorId, roleId),
            holder(UUID.randomUUID(), roleId)));
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.revoke(eq(ref.id()), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    DistributionSummary summary =
        meterRegistry.find("nexus.rbac.admin_equivalent_lock_set_size").summary();
    assertThat(summary).isNotNull();
    assertThat(summary.count()).isEqualTo(1L);
    assertThat(summary.totalAmount()).isEqualTo(3.0);
  }

  /** Revoke acquires M10' then M11 strictly before the decision reads (the order the proof needs). */
  @Test
  void should_takeM10PrimeAndM11BeforeTheDecisionReads_when_revokingAdminDefiningRole() {
    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(
        List.of(new ActiveAssignmentHolder(
                ref.id(), targetUserId, roleId, ANY_ASSIGNER), holder(actorId, roleId)));
    stubCallerIsAdministrator();
    when(userRoleAssignmentPort.revoke(eq(ref.id()), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    InOrder inOrder = Mockito.inOrder(userRoleAssignmentPort);
    inOrder.verify(userRoleAssignmentPort).findActiveAssignmentRef(targetUserId, roleId, tenantId);
    inOrder.verify(userRoleAssignmentPort).findPermissionIdsForRole(roleId, tenantId);
    inOrder.verify(userRoleAssignmentPort).findRolePermissionIdsForTenantRoles(tenantId);
    inOrder.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), any());
    inOrder
        .verify(userRoleAssignmentPort)
        .findHeldRolePermissionIdsForAuthorization(actorId, tenantId);
    inOrder.verify(userRoleAssignmentPort).revoke(eq(ref.id()), any());
  }

  // ---------------------------------------------------------------------------------------
  // L-1 and L-2 on revoke
  // ---------------------------------------------------------------------------------------

  @Test
  void should_deny403PermissionAbsentBeforeRevokeSubset_when_revokeCallerNoLongerHoldsUserRoleAssign() {
    stubBenignRevokeTarget();
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(List.of(ref(UUID.randomUUID(), P1)));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> {
              assertThat(e.getReason()).isEqualTo(DenialReason.PERMISSION_ABSENT);
              assertThat(e.getRequiredPermission()).isEqualTo("user:role:assign");
            });

    verify(rbacAuditPort, times(1))
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "MEMBER", actorId, ctx),
            DenialReason.PERMISSION_ABSENT, "revoke");
    verify(throttlePort, times(1)).recordDenial(tenantId, actorId);
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
  }

  @Test
  void should_throwRoleNotFoundAndNotRevoke_when_m14ReportsRoleNotInTenantOnRevoke() {
    stubBenignRevokeTarget();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");

    verifyNoInteractions(rbacAuditPort);
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
  }

  @Test
  void should_logGrantExceedsCallerWarnWithRevokeOperation_when_revokeSubsetDenies() {
    UUID lacked = UUID.randomUUID();
    stubBenignRevokeTarget();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(lacked)));
    ListAppender<ILoggingEvent> logs = startLogCapture();

    try {
      assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);
    } finally {
      stopLogCapture(logs);
    }

    ILoggingEvent warn =
        logs.list.stream()
            .filter(e -> "RBAC_GRANT_EXCEEDS_CALLER".equals(keyValueMap(e).get("event")))
            .findFirst()
            .orElseThrow();
    assertThat(warn.getLevel()).isEqualTo(Level.WARN);
    assertThat(keyValueMap(warn))
        .containsEntry("operation", "revoke")
        .containsEntry("missingCount", 1);
    assertThat(keyValueMap(warn).values()).doesNotContain(lacked);
  }

  @Test
  void should_logAdministratorRequiredWarnWithIdsOnly_when_revokeOfAdminDefiningRoleDenied() {
    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(new ActiveAssignmentHolder(
            ref.id(), targetUserId, roleId, ANY_ASSIGNER)));
    lenientCallerIsUnionHolder();
    ListAppender<ILoggingEvent> logs = startLogCapture();

    try {
      assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);
    } finally {
      stopLogCapture(logs);
    }

    ILoggingEvent warn =
        logs.list.stream()
            .filter(e -> "RBAC_ADMINISTRATOR_REQUIRED_DENIED".equals(keyValueMap(e).get("event")))
            .findFirst()
            .orElseThrow();
    assertThat(warn.getLevel()).isEqualTo(Level.WARN);
    assertThat(keyValueMap(warn))
        .containsOnlyKeys(
            "event", "tenantId", "targetUserId", "actorUserId", "roleId", "operation");
  }

  // ---------------------------------------------------------------------------------------
  // listActive(): assignedBy redaction by the one definition of "administrator" (row 16)
  // ---------------------------------------------------------------------------------------

  private static PageResult<ActiveRoleAssignment> page(List<ActiveRoleAssignment> items) {
    return new PageResult<>(items, items.size(), 0, 20);
  }

  @Test
  void should_redactAssignedByOnEveryElement_when_callerIsNotAnAdministrator() {
    Instant now = Instant.now();
    UUID otherRoleId = UUID.randomUUID();
    List<ActiveRoleAssignment> stored =
        List.of(
            new ActiveRoleAssignment(targetUserId, roleId, "MEMBER", now, UUID.randomUUID()),
            new ActiveRoleAssignment(targetUserId, otherRoleId, "BILLING", now, UUID.randomUUID()));
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findActiveAssignmentViews(targetUserId, tenantId, 0, 20))
        .thenReturn(page(stored));
    stubCallerHoldsP1Only();

    PageResult<ActiveRoleAssignment> result = service.listActive(actor, targetUserId, 0, 20);

    assertThat(result.items())
        .containsExactly(
            new ActiveRoleAssignment(targetUserId, roleId, "MEMBER", now, null),
            new ActiveRoleAssignment(targetUserId, otherRoleId, "BILLING", now, null));
  }

  /** Row 16: a union-holder is NOT an administrator, so they get the redacted shape. */
  @Test
  void should_redactAssignedBy_when_callerHoldsTheWholeCatalogueOnlyThroughTheUnion() {
    Instant now = Instant.now();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findActiveAssignmentViews(targetUserId, tenantId, 0, 20))
        .thenReturn(
            page(
                List.of(
                    new ActiveRoleAssignment(
                        targetUserId, roleId, "MEMBER", now, UUID.randomUUID()))));
    stubCallerIsUnionHolder();

    assertThat(service.listActive(actor, targetUserId, 0, 20).items())
        .extracting(ActiveRoleAssignment::assignedBy)
        .containsOnlyNulls();
  }

  /** Row 16: an administrator sees assignedBy, whatever their admin role is named. */
  @Test
  void should_preserveAssignedBy_when_callerIsAnAdministrator() {
    Instant now = Instant.now();
    List<ActiveRoleAssignment> stored =
        List.of(new ActiveRoleAssignment(targetUserId, roleId, "MEMBER", now, UUID.randomUUID()));
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findActiveAssignmentViews(targetUserId, tenantId, 0, 20))
        .thenReturn(page(stored));
    stubCallerIsAdministrator();

    assertThat(service.listActive(actor, targetUserId, 0, 20).items())
        .containsExactlyElementsOf(stored);
  }

  @Test
  void should_redactAssignedBy_when_catalogueReadReturnsEmpty() {
    Instant now = Instant.now();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findActiveAssignmentViews(targetUserId, tenantId, 0, 20))
        .thenReturn(
            page(
                List.of(
                    new ActiveRoleAssignment(
                        targetUserId, roleId, "MEMBER", now, UUID.randomUUID()))));
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(Set.of());
    stubCallerIsAdministrator();

    assertThat(service.listActive(actor, targetUserId, 0, 20).items())
        .extracting(ActiveRoleAssignment::assignedBy)
        .containsOnlyNulls();
  }

  @Test
  void should_throwResourceNotFound_when_listActiveTargetUserNotFound() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.listActive(actor, targetUserId, 0, 20))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "USER_NOT_FOUND");

    verify(userRoleAssignmentPort, never()).findActiveAssignmentViews(any(), any(), anyInt(), anyInt());
  }

  @Test
  void should_throwSameNotFoundAndReadNothing_when_listActiveTargetTenantMismatch() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(otherTenantId));

    assertThatThrownBy(() -> service.listActive(actor, targetUserId, 0, 20))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "USER_NOT_FOUND")
        .hasMessage("No such user");

    verify(userRoleAssignmentPort, never()).findActiveAssignmentViews(any(), any(), anyInt(), anyInt());
    verify(userRoleAssignmentPort, never()).findHeldRolePermissionIdsForAuthorization(any(), any());
    verifyNoInteractions(rbacAuditPort);
    assertThat(
            meterRegistry
                .get("nexus.rbac.permission_denied")
                .tag("permission", "user:read")
                .tag("reason", "CROSS_TENANT_TARGET")
                .counter()
                .count())
        .isEqualTo(1.0);
  }

  // ---------------------------------------------------------------------------------------
  // The denial throttle (D14, MC-7; US-018 B8): after the 404s and the classification, before the
  // caller's own authorization reads. Blocks only set-lock and self-target requests.
  // ---------------------------------------------------------------------------------------

  private double deniedThrottledCount(String operation) {
    Counter counter =
        meterRegistry.find("nexus.rbac.denial_throttled").tags("operation", operation).counter();
    return counter == null ? 0.0 : counter.count();
  }

  /** A benign target the caller cannot grant: the role carries P2, the caller holds P1 only. */
  private void stubBenignAssignTargetCallerLacksIt() {
    stubBenignAssignTarget();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P2)));
    stubCallerHoldsP1Only();
  }

  @Test
  void should_assignNormally_when_throttledAndTargetIsBenign() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(THROTTLED);

    ActiveRoleAssignment result = service.assign(actor, targetUserId, roleId, ctx);

    assertThat(result.roleId()).isEqualTo(roleId);
    assertThat(deniedThrottledCount("assign")).isZero();
    verify(rbacAuditPort)
        .recordRoleAssigned(new RbacAuditEvent(tenantId, targetUserId, roleId, "MEMBER", actorId, ctx));
  }

  @Test
  void should_revokeNormally_when_throttledAndTargetIsBenign() {
    stubHappyPathRevoke();
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(THROTTLED);

    service.revoke(actor, targetUserId, roleId, ctx);

    assertThat(deniedThrottledCount("revoke")).isZero();
    verify(rbacAuditPort)
        .recordRoleRevoked(new RbacAuditEvent(tenantId, targetUserId, roleId, "MEMBER", actorId, ctx));
  }

  /** US-019 B7 (design §9.3): a blocked throttled request is a 429 RBAC_011, never a 403. */
  private static void assertThrottled(Throwable e, long expectedRetryAfterSeconds) {
    assertThat(e)
        .isInstanceOfSatisfying(
            RoleChangeThrottledException.class,
            t -> {
              assertThat(t.code()).isEqualTo("RBAC_011");
              assertThat(t.retryAfterSeconds()).isEqualTo(expectedRetryAfterSeconds);
              assertThat(t.selfReported()).isTrue();
            });
  }

  @Test
  void should_throw429Rbac011BeforeTheSetLockWithNoAuditRow_when_throttledAndTargetIsAdminDefining_assign() {
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(CATALOGUE));
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(THROTTLED);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
          .satisfies(e -> assertThrottled(e, RETRY_AFTER_SECONDS));
      assertThat(appender.list.stream().filter(e -> e.getLevel() == Level.WARN))
          .as("the once-per-window WARN is RBAC_DENIAL_THROTTLE_ENGAGED; none per blocked request")
          .isEmpty();
    } finally {
      stopLogCapture(appender);
    }

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(userRoleAssignmentPort, never()).findHeldRolePermissionIdsForAuthorization(any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verify(throttlePort, never()).recordDenial(any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
    assertThat(deniedThrottledCount("assign")).isEqualTo(1.0);
  }

  /**
   * US-019 review R1-6: the window is an unvalidated property. A window under one second must not
   * turn the 429 into a 500 (the clamp's lower bound would exceed its upper bound); Retry-After
   * stays at least one second.
   */
  @ParameterizedTest
  @ValueSource(ints = {0, -5})
  void should_throw429WithOneSecondRetryAfter_when_theThrottleWindowIsBelowOneSecond(int window) {
    RoleAssignmentService shortWindowService =
        new RoleAssignmentService(
            userRoleAssignmentPort, userDirectoryPort, rbacAuditPort, permissionCachePort,
            permissionFreshness, transactionManager, meterRegistry, throttlePort,
            new PiiPermissionGrantRule(true, meterRegistry), MAX_DENIALS, window);
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(CATALOGUE));
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(THROTTLED);

    assertThatThrownBy(() -> shortWindowService.assign(actor, targetUserId, roleId, ctx))
        .satisfies(e -> assertThrottled(e, 1L));
  }

  @Test
  void should_throw429Rbac011BeforeTheSetLockWithNoAuditRow_when_throttledAndTargetIsAdminDefining_revoke() {
    stubRevokeTarget(role("ADMIN_LIKE"));
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(CATALOGUE));
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(THROTTLED);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .satisfies(e -> assertThrottled(e, RETRY_AFTER_SECONDS));

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
    assertThat(deniedThrottledCount("revoke")).isEqualTo(1.0);
    assertThat(meterRegistry.find("nexus.rbac.privileged_revoke_lock_hold").timers()).isEmpty();
  }

  @Test
  void should_throw429Rbac011WithNoAuditAndNoCallerReads_when_throttledAndSelfTargetNonAdmin() {
    stubBenignSelfAssignTarget();
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(THROTTLED);

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .satisfies(e -> assertThrottled(e, RETRY_AFTER_SECONDS));

    verifyNoInteractions(rbacAuditPort);
    verify(throttlePort, never()).recordDenial(any(), any());
    verify(userRoleAssignmentPort, never()).findHeldRolePermissionIdsForAuthorization(any(), any());
    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    assertThat(deniedThrottledCount("assign")).isEqualTo(1.0);
  }

  @Test
  void should_throw429Rbac011_when_throttledAndSelfTargetRevoke() {
    stubRevokeTargetFor(actorId, memberRole());
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(THROTTLED);

    assertThatThrownBy(() -> service.revoke(actor, actorId, roleId, ctx))
        .satisfies(e -> assertThrottled(e, RETRY_AFTER_SECONDS));

    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(rbacAuditPort);
    assertThat(deniedThrottledCount("revoke")).isEqualTo(1.0);
  }

  /** Retry-After is bounded to [1, window] whatever the store reports (design §9.3). */
  @ParameterizedTest
  @CsvSource({"0, 1", "1, 1", "59, 59", "60, 60", "61, 60", "100000, 60"})
  void should_boundRetryAfterToOneSecondAndTheWindow_when_throttledSelfTarget(
      long reported, long expected) {
    stubBenignSelfAssignTarget();
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(new ThrottleStatus(true, reported));

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .satisfies(e -> assertThrottled(e, expected));
  }

  @Test
  void should_assignNormally_when_throttleStatusIsNull() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(null);

    assertThat(service.assign(actor, targetUserId, roleId, ctx).roleId()).isEqualTo(roleId);
  }

  /** Classification (M14, M15) runs before the throttle decision; the caller's own reads after. */
  @Test
  void should_decideThrottleAfterClassificationAndBeforeTheCallersReads_when_assigning() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    InOrder order = Mockito.inOrder(throttlePort, userRoleAssignmentPort);
    order.verify(userRoleAssignmentPort).findPermissionIdsForRole(roleId, tenantId);
    order.verify(throttlePort).throttleStatus(tenantId, actorId);
    order
        .verify(userRoleAssignmentPort)
        .findHeldRolePermissionIdsForAuthorization(actorId, tenantId);
    order.verify(userRoleAssignmentPort).hasActiveAssignment(targetUserId, roleId);
  }

  @Test
  void should_return403WithNoAuditRowCounterAndOneWarn_when_throttledBenignRequestIsDenied() {
    stubBenignAssignTargetCallerLacksIt();
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(THROTTLED);
    when(throttlePort.recordSuppressedDenial(tenantId, actorId)).thenReturn(1, 2);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      for (int i = 0; i < 2; i++) {
        assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
            .isInstanceOf(InsufficientPermissionException.class)
            .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));
      }

      var warns = appender.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
      assertThat(warns).as("one WARN per window, and no per-denial WARN").hasSize(1);
      assertThat(keyValueMap(warns.get(0)))
          .containsOnlyKeys("event", "tenantId", "actorUserId", "operation", "suppressedCount")
          .containsEntry("event", "RBAC_DENIAL_THROTTLED")
          .containsEntry("operation", "assign")
          .containsEntry("suppressedCount", 1);
    } finally {
      stopLogCapture(appender);
    }

    verifyNoInteractions(rbacAuditPort);
    verify(throttlePort, never()).recordDenial(any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    assertThat(deniedThrottledCount("assign")).isEqualTo(2.0);
  }

  @Test
  void should_return403WithNoAuditRow_when_throttledCallerNoLongerHoldsTheEndpointPermission() {
    stubBenignAssignTarget();
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(List.of());
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(THROTTLED);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.PERMISSION_ABSENT));

    verifyNoInteractions(rbacAuditPort);
    assertThat(deniedThrottledCount("assign")).isEqualTo(1.0);
  }

  @Test
  void should_return403WithNoAuditRow_when_throttledRevokeSubsetDenies() {
    stubBenignRevokeTarget();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P2)));
    stubCallerHoldsP1Only();
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(THROTTLED);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    verifyNoInteractions(rbacAuditPort);
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    assertThat(deniedThrottledCount("revoke")).isEqualTo(1.0);
  }

  @Test
  void should_stillReturnTheRealDenial_when_recordSuppressedDenialThrows() {
    stubBenignAssignTargetCallerLacksIt();
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(THROTTLED);
    when(throttlePort.recordSuppressedDenial(tenantId, actorId))
        .thenThrow(new RuntimeException("throttle store down"));

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));
  }

  @Test
  void should_recordFullDenialAndNeverSuppress_when_notThrottled() {
    stubBenignAssignTargetCallerLacksIt();
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(ThrottleStatus.NOT_THROTTLED);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "MEMBER", actorId, ctx),
            DenialReason.GRANT_EXCEEDS_CALLER, "assign", 1);
    verify(throttlePort).recordDenial(tenantId, actorId);
    verify(throttlePort, never()).recordSuppressedDenial(any(), any());
    assertThat(deniedThrottledCount("assign")).isZero();
  }

  @Test
  void should_callRecordDenialOnThrottlePort_when_anAdministratorRequirementDeniesRevoke() {
    ActiveAssignmentRef ref = stubRevokeTarget(role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of(new ActiveAssignmentHolder(
            ref.id(), targetUserId, roleId, ANY_ASSIGNER)));
    lenientCallerIsUnionHolder();

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verify(throttlePort).recordDenial(tenantId, actorId);
  }

  @Test
  void should_emitDenialThrottleEngagedWarnExactlyOnce_when_recordDenialReturnsTrue() {
    stubBenignSelfAssignTarget();
    stubCallerHoldsP1Only();
    when(throttlePort.recordDenial(tenantId, actorId)).thenReturn(true);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);

      var engagedWarnings =
          appender.list.stream()
              .filter(e -> e.getLevel() == Level.WARN)
              .filter(e -> "RBAC_DENIAL_THROTTLE_ENGAGED".equals(keyValueMap(e).get("event")))
              .toList();
      assertThat(engagedWarnings).hasSize(1);
      assertThat(keyValueMap(engagedWarnings.get(0)))
          .containsEntry("tenantId", tenantId)
          .containsEntry("actorUserId", actorId)
          .containsEntry("operation", "assign")
          .containsEntry("maxDenials", MAX_DENIALS)
          .containsEntry("windowSeconds", WINDOW_SECONDS);
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_notEmitDenialThrottleEngagedWarn_when_recordDenialReturnsFalse() {
    stubBenignSelfAssignTarget();
    stubCallerHoldsP1Only();
    when(throttlePort.recordDenial(tenantId, actorId)).thenReturn(false);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);

      assertThat(
              appender.list.stream()
                  .anyMatch(e -> "RBAC_DENIAL_THROTTLE_ENGAGED".equals(keyValueMap(e).get("event"))))
          .isFalse();
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_proceedWithNormalFlow_when_throttleStatusThrows() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();
    when(throttlePort.throttleStatus(tenantId, actorId)).thenThrow(new RuntimeException("store down"));

    ActiveRoleAssignment result = service.assign(actor, targetUserId, roleId, ctx);

    assertThat(result.roleId()).isEqualTo(roleId);
  }

  @Test
  void should_stillThrowRealDenialException_when_recordDenialThrows() {
    stubBenignSelfAssignTarget();
    stubCallerHoldsP1Only();
    when(throttlePort.recordDenial(tenantId, actorId))
        .thenThrow(new RuntimeException("throttle store down"));

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(e -> assertThat(reasonOf(e)).isEqualTo(DenialReason.SELF_ASSIGNMENT));

    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, actorId, roleId, "MEMBER", actorId, ctx),
            DenialReason.SELF_ASSIGNMENT, "assign");
  }

  // ---------------------------------------------------------------------------------------
  // assign() -- US-019 T-007: administrator-only grant of user:directory:read (RC-60, RC-66)
  // ---------------------------------------------------------------------------------------

  private static final UUID PII = RbacSeededPermissionIds.USER_DIRECTORY_READ;

  /** A benign (not admin-defining) target role carrying {@code user:directory:read}. */
  private void stubBenignTargetCarryingDirectoryRead() {
    stubBenignAssignTarget();
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(PII)));
  }

  /** M13: the caller holds {@code user:directory:read} through a partial role (no administrator). */
  private void stubCallerHoldsDirectoryReadOnly() {
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(withUserRoleAssign(List.of(ref(UUID.randomUUID(), PII))));
  }

  @Test
  void should_denyNotTenantAdminWithOneDenialRowAndThrottleDenial_when_nonAdministratorHolderAssignsDirectoryReadRole() {
    stubBenignTargetCarryingDirectoryRead();
    stubCallerHoldsDirectoryReadOnly();

    ListAppender<ILoggingEvent> ruleLogs = startLogCapture(PiiPermissionGrantRule.class);
    try {
      assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
          .isInstanceOfSatisfying(
              InsufficientPermissionException.class,
              e -> {
                assertThat(e.getReason()).isEqualTo(DenialReason.NOT_TENANT_ADMIN);
                assertThat(e.getRequiredPermission()).isEqualTo("user:role:assign");
              });

      assertThat(ruleLogs.list)
          .singleElement()
          .satisfies(
              warn -> {
                assertThat(warn.getLevel()).isEqualTo(Level.WARN);
                assertThat(keyValueMap(warn))
                    .containsOnly(
                        Map.entry("event", "RBAC_PII_PERMISSION_GRANT_DENIED"),
                        Map.entry("tenantId", tenantId),
                        Map.entry("actorUserId", actorId),
                        Map.entry("roleId", roleId),
                        Map.entry("targetUserId", targetUserId),
                        Map.entry("operation", "assign"));
              });
    } finally {
      stopLogCapture(ruleLogs, PiiPermissionGrantRule.class);
    }

    verify(rbacAuditPort, times(1))
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "MEMBER", actorId, ctx),
            DenialReason.NOT_TENANT_ADMIN, "assign");
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any(), any());
    verify(throttlePort, times(1)).recordDenial(tenantId, actorId);
    verify(userRoleAssignmentPort, never()).hasActiveAssignment(any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    assertThat(meterRegistry.get("nexus.rbac.pii_permission_delegated").counter().count())
        .isZero();
  }

  /** RC-66.1: A2 runs first, so a non-holder gets GRANT_EXCEEDS_CALLER and no rule WARN. */
  @Test
  void should_denyGrantExceedsCallerNeverNotTenantAdmin_when_nonHolderAssignsDirectoryReadRole() {
    stubBenignTargetCarryingDirectoryRead();
    stubCallerHoldsP1Only();

    ListAppender<ILoggingEvent> ruleLogs = startLogCapture(PiiPermissionGrantRule.class);
    try {
      assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
          .isInstanceOfSatisfying(
              InsufficientPermissionException.class,
              e -> assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));
      assertThat(ruleLogs.list).isEmpty();
    } finally {
      stopLogCapture(ruleLogs, PiiPermissionGrantRule.class);
    }

    verify(rbacAuditPort, times(1))
        .recordRoleAssignmentDenied(any(), eq(DenialReason.GRANT_EXCEEDS_CALLER), eq("assign"), eq(1));
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
  }

  /** A throttled actor's evaluated denial follows A2's throttled posture: counted, no audit row. */
  @Test
  void should_denyWithoutAuditRow_when_throttledNonAdministratorHolderAssignsDirectoryReadRole() {
    stubBenignTargetCarryingDirectoryRead();
    stubCallerHoldsDirectoryReadOnly();
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(THROTTLED);
    when(throttlePort.recordSuppressedDenial(tenantId, actorId)).thenReturn(2);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> assertThat(e.getReason()).isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any(), any());
    verify(throttlePort, never()).recordDenial(any(), any());
    assertThat(deniedThrottledCount("assign")).isEqualTo(1.0);
  }

  @Test
  void should_assignAndEmitNothing_when_administratorAssignsDirectoryReadRole() {
    stubBenignTargetCarryingDirectoryRead();
    UUID adminDefiningRoleId = UUID.randomUUID();
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(
            withUserRoleAssign(
                List.of(
                    ref(adminDefiningRoleId, P1),
                    ref(adminDefiningRoleId, P2),
                    ref(UUID.randomUUID(), PII))));
    stubSuccessfulInsert();

    ListAppender<ILoggingEvent> ruleLogs = startLogCapture(PiiPermissionGrantRule.class);
    try {
      service.assign(actor, targetUserId, roleId, ctx);
      assertThat(ruleLogs.list).isEmpty();
    } finally {
      stopLogCapture(ruleLogs, PiiPermissionGrantRule.class);
    }

    verify(userRoleAssignmentPort).assign(targetUserId, roleId, tenantId, actorId);
    assertThat(meterRegistry.get("nexus.rbac.pii_permission_delegated").counter().count())
        .isZero();
  }

  /**
   * On the set-lock path the administrator answer comes from the locked rows, never the snapshot:
   * a caller the snapshot calls an administrator but who holds no locked admin-defining row is
   * denied.
   */
  @Test
  void should_denyFromSetLockRows_when_adminDefiningTargetCarriesDirectoryReadAndCallerNotInLock() {
    Set<UUID> catalogueWithPii = Set.of(P1, P2, PII);
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(catalogueWithPii);
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(catalogueWithPii));
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId))
        .thenReturn(List.of(ref(roleId, P1), ref(roleId, P2), ref(roleId, PII)));
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(List.of(holder(UUID.randomUUID(), roleId)));
    UUID snapshotAdminRoleId = UUID.randomUUID();
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(
            withUserRoleAssign(
                List.of(
                    ref(snapshotAdminRoleId, P1),
                    ref(snapshotAdminRoleId, P2),
                    ref(snapshotAdminRoleId, PII))));

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> assertThat(e.getReason()).isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
  }

  @Test
  void should_assignAndEmitDelegatedWarnAndCounterOnce_when_ruleOffAndNonAdministratorAssigns() {
    RoleAssignmentService ruleOffService =
        new RoleAssignmentService(
            userRoleAssignmentPort, userDirectoryPort, rbacAuditPort, permissionCachePort,
            permissionFreshness, transactionManager, meterRegistry, throttlePort,
            new PiiPermissionGrantRule(false, meterRegistry), MAX_DENIALS, WINDOW_SECONDS);
    stubBenignTargetCarryingDirectoryRead();
    stubCallerHoldsDirectoryReadOnly();
    stubSuccessfulInsert();

    ListAppender<ILoggingEvent> ruleLogs = startLogCapture(PiiPermissionGrantRule.class);
    try {
      ruleOffService.assign(actor, targetUserId, roleId, ctx);

      assertThat(ruleLogs.list)
          .singleElement()
          .satisfies(
              warn -> {
                assertThat(warn.getLevel()).isEqualTo(Level.WARN);
                assertThat(keyValueMap(warn))
                    .containsOnly(
                        Map.entry("event", "RBAC_PII_PERMISSION_DELEGATED"),
                        Map.entry("tenantId", tenantId),
                        Map.entry("actorUserId", actorId),
                        Map.entry("roleId", roleId),
                        Map.entry("targetUserId", targetUserId));
              });
    } finally {
      stopLogCapture(ruleLogs, PiiPermissionGrantRule.class);
    }

    verify(userRoleAssignmentPort).assign(targetUserId, roleId, tenantId, actorId);
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
    Counter delegated = meterRegistry.find("nexus.rbac.pii_permission_delegated").counter();
    assertThat(delegated).isNotNull();
    assertThat(delegated.count()).isEqualTo(1.0);
  }

  // ---------------------------------------------------------------------------------------
  // assign() -- US-019 T-020 (design §10.9; RC-56.2, RC-66.3): the non-admin-defining path
  // re-classifies R from a post-insert current read, and rolls back with 409 RBAC_012
  // ---------------------------------------------------------------------------------------

  /** The insert of a benign assign succeeds; nothing after it is stubbed. */
  private void stubInsertOnly() {
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(UUID.randomUUID());
  }

  /** The post-insert current read of R's role_permissions returns {@code permissionIds}. */
  private void stubCurrentRolePermissions(UUID... permissionIds) {
    List<RolePermissionRef> rows = new ArrayList<>();
    for (UUID permissionId : permissionIds) {
      rows.add(ref(roleId, permissionId));
    }
    when(userRoleAssignmentPort.lockRolePermissionsForRoles(tenantId, List.of(roleId)))
        .thenReturn(rows);
  }

  private double classificationChangedCount(String operation) {
    Counter counter =
        meterRegistry
            .find("nexus.rbac.role_classification_changed")
            .tag("operation", operation)
            .counter();
    return counter == null ? 0.0 : counter.count();
  }

  @Test
  void should_insertThenReadTheRolesCurrentPermissionsThenAudit_when_assigningANonAdminDefiningRole() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    InOrder order = Mockito.inOrder(userRoleAssignmentPort, rbacAuditPort);
    order.verify(userRoleAssignmentPort).assign(targetUserId, roleId, tenantId, actorId);
    order.verify(userRoleAssignmentPort).lockRolePermissionsForRoles(tenantId, List.of(roleId));
    order.verify(rbacAuditPort).recordRoleAssigned(any());
    assertThat(classificationChangedCount("assign")).isZero();
  }

  /**
   * RC-56.2: the snapshot classified R as not admin-defining, but a B8 promotion committed while
   * this assign waited on R's row. The current read sees the whole catalogue: 409 RBAC_012, the
   * insert rolls back, and no audit row (success or denial) is written.
   */
  @Test
  void should_throw409Rbac012WithNoAuditCall_when_thePostInsertReadShowsTheRoleBecameAdminDefining() {
    stubBenignAssignTarget();
    stubInsertOnly();
    stubCurrentRolePermissions(P1, P2);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RoleClassificationChangedException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_012");

    verifyNoInteractions(rbacAuditPort, permissionCachePort);
    verify(throttlePort, never()).recordDenial(any(), any());
    assertThat(classificationChangedCount("assign")).isEqualTo(1.0);
  }

  /** RC-66.3: R gained user:directory:read while the assign waited; the caller is no administrator. */
  @Test
  void should_throw409Rbac012WithNoAuditCall_when_theRoleGainedDirectoryReadWhileWaitingAndTheCallerIsNotAnAdministrator() {
    stubBenignAssignTarget();
    stubInsertOnly();
    stubCurrentRolePermissions(PII);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RoleClassificationChangedException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_012");

    verifyNoInteractions(rbacAuditPort, permissionCachePort);
    assertThat(classificationChangedCount("assign")).isEqualTo(1.0);
  }

  @Test
  void should_abortAssignWithRoleClassificationChanged_when_roleGainedPermissionCallerLacksWhileAssigning() {
    stubBenignAssignTarget();
    stubInsertOnly();
    stubCurrentRolePermissions(P1);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RoleClassificationChangedException.class);

    verify(userRoleAssignmentPort, never()).findActiveAssignmentView(any(), any(), any());
    verifyNoInteractions(rbacAuditPort);
  }

  @Test
  void should_assign_when_callerConcurrentlyPromotedToAdministratorWhileAssigningRoleWithPii() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();
    stubCurrentRolePermissions(PII);

    UUID adminDefiningRoleId = UUID.randomUUID();
    List<RolePermissionRef> nonAdminHeld = withUserRoleAssign(List.of());
    List<RolePermissionRef> adminHeld = withUserRoleAssign(wholeCatalogue(adminDefiningRoleId));

    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(nonAdminHeld)
        .thenReturn(adminHeld);

    service.assign(actor, targetUserId, roleId, ctx);

    verify(rbacAuditPort).recordRoleAssigned(any());
    assertThat(classificationChangedCount("assign")).isZero();
  }

  @Test
  void should_assign_when_theRoleGainedDirectoryReadWhileWaitingAndTheCallerIsAnAdministrator() {
    stubBenignAssignTarget();
    stubCallerIsAdministrator();
    stubSuccessfulInsert();
    stubCurrentRolePermissions(PII);

    service.assign(actor, targetUserId, roleId, ctx);

    verify(rbacAuditPort).recordRoleAssigned(any());
    assertThat(classificationChangedCount("assign")).isZero();
  }

  /** With the rule off, a gain seen only by the current read still emits the delegation WARN. */
  @Test
  void should_assignAndEmitDelegated_when_ruleOffAndTheRoleGainedDirectoryReadWhileWaiting() {
    RoleAssignmentService ruleOffService =
        new RoleAssignmentService(
            userRoleAssignmentPort, userDirectoryPort, rbacAuditPort, permissionCachePort,
            permissionFreshness, transactionManager, meterRegistry, throttlePort,
            new PiiPermissionGrantRule(false, meterRegistry), MAX_DENIALS, WINDOW_SECONDS);
    stubBenignAssignTarget();
    stubSuccessfulInsert();
    stubCurrentRolePermissions(PII);

    ruleOffService.assign(actor, targetUserId, roleId, ctx);

    assertThat(meterRegistry.get("nexus.rbac.pii_permission_delegated").counter().count())
        .isEqualTo(1.0);
  }

  /**
   * The set-lock path takes only the RC-57.2 read over the lock set, once, and no post-insert
   * RC-56.2 read: R is in the lock set and assign holds its rows.
   */
  @Test
  void should_readTheLockSetsPermissionsOnlyOnce_when_assigningAnAdminDefiningRole() {
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of());
    stubCallerIsUnionHolder();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort, times(1)).lockRolePermissionsForRoles(any(), any());
  }

  // ---------------------------------------------------------------------------------------
  // assign() -- US-019 T-020 (RC-56.4): the committed-state detector after an admin-defining assign
  // ---------------------------------------------------------------------------------------

  /**
   * An admin-defining assign that commits; after commit R has one holder assigned by {@code
   * assigner}, and the tenant's administrators are {@code administrators}.
   */
  private void stubCommittedAdminDefiningAssign(UUID assigner, Set<UUID> administrators) {
    stubTargetUserAndRole(targetUserId, role("ADMIN_LIKE"));
    stubAdminDefiningTarget(List.of());
    stubCallerIsUnionHolder();
    stubSuccessfulInsert();
    when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId))
        .thenReturn(List.of(new HolderProvenance(targetUserId, assigner)));
    when(userRoleAssignmentPort.findActiveHolderUserIdsForRoles(tenantId, Set.of(roleId)))
        .thenReturn(administrators);
  }

  @Test
  void should_warnAndCountTheUntaggedPagingDetector_when_anAdminDefiningRoleHasANonAdministratorAssignedHolderAfterCommit() {
    stubCommittedAdminDefiningAssign(actorId, Set.of(targetUserId));

    ListAppender<ILoggingEvent> appender =
        startLogCapture(AdminDefiningRoleProvenanceDetector.class);
    try {
      service.assign(actor, targetUserId, roleId, ctx);

      assertThat(appender.list)
          .singleElement()
          .satisfies(
              warn -> {
                assertThat(warn.getLevel()).isEqualTo(Level.WARN);
                assertThat(keyValueMap(warn))
                    .containsOnly(
                        Map.entry("event", "RBAC_ADMIN_DEFINING_ROLE_HAS_NON_ADMIN_ASSIGNED_HOLDER"),
                        Map.entry("tenantId", tenantId),
                        Map.entry("roleId", roleId),
                        Map.entry("holderCount", 1),
                        Map.entry("nonAdminAssignedCount", 1));
              });
    } finally {
      stopLogCapture(appender, AdminDefiningRoleProvenanceDetector.class);
    }
    Counter detector =
        meterRegistry.get("nexus.rbac.admin_defining_role_non_admin_assigned_holder").counter();
    assertThat(detector.count()).isEqualTo(1.0);
    assertThat(detector.getId().getTags()).isEmpty();
  }

  @Test
  void should_staySilent_when_everyHolderOfTheAssignedAdminDefiningRoleWasAssignedByAnAdministrator() {
    stubCommittedAdminDefiningAssign(actorId, Set.of(actorId, targetUserId));

    service.assign(actor, targetUserId, roleId, ctx);

    assertThat(meterRegistry.find("nexus.rbac.admin_defining_role_non_admin_assigned_holder")
            .counter())
        .isNull();
  }

  @Test
  void should_notRunTheDetector_when_theAssignedRoleIsNotAdminDefining() {
    stubBenignAssignTarget();
    stubSuccessfulInsert();

    service.assign(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort, never()).findActiveHoldersForRole(any(), any());
  }

  // ---------------------------------------------------------------------------------------
  // Log-capture helpers
  // ---------------------------------------------------------------------------------------

  private static ListAppender<ILoggingEvent> startLogCapture(Class<?> source) {
    Logger logger = (Logger) LoggerFactory.getLogger(source);
    ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);
    return listAppender;
  }

  private static void stopLogCapture(ListAppender<ILoggingEvent> listAppender, Class<?> source) {
    Logger logger = (Logger) LoggerFactory.getLogger(source);
    logger.detachAppender(listAppender);
    listAppender.stop();
  }

  private ListAppender<ILoggingEvent> startLogCapture() {
    Logger logger = (Logger) LoggerFactory.getLogger(RoleAssignmentService.class);
    ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);
    return listAppender;
  }

  private void stopLogCapture(ListAppender<ILoggingEvent> listAppender) {
    Logger logger = (Logger) LoggerFactory.getLogger(RoleAssignmentService.class);
    logger.detachAppender(listAppender);
    listAppender.stop();
  }

  private static Map<String, Object> keyValueMap(ILoggingEvent event) {
    Map<String, Object> map = new HashMap<>();
    event.getKeyValuePairs().forEach(kv -> map.put(kv.key, kv.value));
    return map;
  }
}
