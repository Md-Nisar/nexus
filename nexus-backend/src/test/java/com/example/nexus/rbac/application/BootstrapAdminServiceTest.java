package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlertPort;
import com.example.nexus.rbac.application.port.out.BreakGlassAuditEvent;
import com.example.nexus.rbac.application.port.out.BreakGlassGrantLookupPort;
import com.example.nexus.rbac.application.port.out.DirectoryUser;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermissionName;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.DeadlockLoserDataAccessException;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * US-018 T-007 and T-008 (03-design.md §7.1, §7.2): the break-glass first-administrator grant,
 * the replay and invalid-argument refusals, and the mapping of a failed grant transaction to an
 * audited, paged refusal. Plain Mockito, no Spring context: the transaction manager is a mock, so
 * the commit and rollback calls are observable.
 */
@Tag("UnitTest")
class BootstrapAdminServiceTest {

  private static final ChangeRef CHANGE_REF = new ChangeRef("OPS-42");

  private final UUID tenantId = UUID.randomUUID();
  private final UUID targetUserId = UUID.randomUUID();
  private final UUID tenantAdminRoleId = UUID.randomUUID();
  private final UUID newAssignmentId = UUID.randomUUID();

  private UserDirectoryPort userDirectoryPort;
  private UserRoleAssignmentPort userRoleAssignmentPort;
  private RbacAuditPort rbacAuditPort;
  private BreakGlassAlertPort breakGlassAlertPort;
  private BreakGlassGrantLookupPort grantLookupPort;
  private PlatformTransactionManager transactionManager;
  private BootstrapAdminService service;

  @BeforeEach
  void setUp() {
    userDirectoryPort = mock(UserDirectoryPort.class);
    userRoleAssignmentPort = mock(UserRoleAssignmentPort.class);
    rbacAuditPort = mock(RbacAuditPort.class);
    breakGlassAlertPort = mock(BreakGlassAlertPort.class);
    grantLookupPort = mock(BreakGlassGrantLookupPort.class);
    transactionManager = mock(PlatformTransactionManager.class);
    service =
        new BootstrapAdminService(
            userDirectoryPort,
            userRoleAssignmentPort,
            rbacAuditPort,
            breakGlassAlertPort,
            grantLookupPort,
            transactionManager);

    when(transactionManager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());

    when(userDirectoryPort.findUser(targetUserId))
        .thenReturn(Optional.of(new DirectoryUser(tenantId, true)));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(tenantAdminRoleId));
    when(userRoleAssignmentPort.findRole(tenantAdminRoleId))
        .thenReturn(Optional.of(role(tenantAdminRoleId, "TENANT_ADMIN", true)));
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(allDangerous(tenantAdminRoleId));
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), anyList()))
        .thenReturn(List.of());
    when(userRoleAssignmentPort.assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId))
        .thenReturn(newAssignmentId);
  }

  @AfterEach
  void clearSynchronization() {
    if (TransactionSynchronizationManager.isSynchronizationActive()) {
      TransactionSynchronizationManager.clearSynchronization();
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Refusals: one FAILURE row with the reason, then an alert, and the exit code.
  // ---------------------------------------------------------------------------------------------

  @Test
  void should_refuseWithExit3_andWriteOneFailureRowWithNullTenant_andAlert_when_targetUserDoesNotExist() {
    when(userDirectoryPort.findUser(targetUserId)).thenReturn(Optional.empty());

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertRefused(outcome, BreakGlassRefusalReason.TARGET_USER_NOT_FOUND, 3, null);
  }

  @Test
  void should_refuseWithExit3_andWriteOneFailureRow_andAlert_when_targetUserIsNotActive() {
    when(userDirectoryPort.findUser(targetUserId))
        .thenReturn(Optional.of(new DirectoryUser(tenantId, false)));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertRefused(outcome, BreakGlassRefusalReason.TARGET_USER_NOT_ACTIVE, 3, tenantId);
  }

  @Test
  void should_refuseWithExit4_andWriteOneFailureRow_andAlert_when_tenantHasNoTenantAdminRole() {
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.empty());

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertRefused(outcome, BreakGlassRefusalReason.NO_SYSTEM_ADMIN_ROLE, 4, tenantId);
  }

  @Test
  void should_refuseWithExit4_when_tenantAdminRoleIsNotASystemRole() {
    when(userRoleAssignmentPort.findRole(tenantAdminRoleId))
        .thenReturn(Optional.of(role(tenantAdminRoleId, "TENANT_ADMIN", false)));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertRefused(outcome, BreakGlassRefusalReason.NO_SYSTEM_ADMIN_ROLE, 4, tenantId);
  }

  @Test
  void should_refuseWithExit5_andWriteOneFailureRow_andAlert_when_lockedRowsHoldNamedTenantAdmin() {
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), anyList()))
        .thenReturn(
            List.of(new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), tenantAdminRoleId)));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertRefused(outcome, BreakGlassRefusalReason.TENANT_HAS_ADMIN, 5, tenantId);
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
  }

  @Test
  void should_refuseWithExit5_when_lockedRowsHoldAFullyAdminEquivalentCustomRole() {
    UUID customRoleId = UUID.randomUUID();
    List<RolePermissionName> permissions = new ArrayList<>(allDangerous(tenantAdminRoleId));
    permissions.addAll(allDangerous(customRoleId));
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId)).thenReturn(permissions);
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), anyList()))
        .thenReturn(
            List.of(new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), customRoleId)));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertRefused(outcome, BreakGlassRefusalReason.TENANT_HAS_ADMIN, 5, tenantId);
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
  }

  static Stream<Arguments> refusalsBeforeTheLock() {
    return Stream.of(
        Arguments.of(
            "target user missing",
            (Consumer<BootstrapAdminServiceTest>)
                t -> when(t.userDirectoryPort.findUser(t.targetUserId)).thenReturn(Optional.empty())),
        Arguments.of(
            "target user not active",
            (Consumer<BootstrapAdminServiceTest>)
                t ->
                    when(t.userDirectoryPort.findUser(t.targetUserId))
                        .thenReturn(Optional.of(new DirectoryUser(t.tenantId, false)))),
        Arguments.of(
            "no TENANT_ADMIN role",
            (Consumer<BootstrapAdminServiceTest>)
                t ->
                    when(t.userRoleAssignmentPort.findRoleIdByName(t.tenantId, "TENANT_ADMIN"))
                        .thenReturn(Optional.empty())),
        Arguments.of(
            "TENANT_ADMIN not a system role",
            (Consumer<BootstrapAdminServiceTest>)
                t ->
                    when(t.userRoleAssignmentPort.findRole(t.tenantAdminRoleId))
                        .thenReturn(Optional.of(t.role(t.tenantAdminRoleId, "TENANT_ADMIN", false)))));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("refusalsBeforeTheLock")
  void should_neverLockNorInsert_when_refusedBeforeTheLock(
      String label, Consumer<BootstrapAdminServiceTest> arrange) {
    arrange.accept(this);

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    verify(userRoleAssignmentPort, never()).findPermissionNamesForTenantRoles(any());
    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verify(rbacAuditPort, never()).recordBreakGlassGrant(any());
    verify(transactionManager, never()).rollback(any());
  }

  /**
   * T-008: the target lookup runs before the grant transaction, so a refusal for a missing or
   * non-ACTIVE target never opens it.
   */
  @Test
  void should_notOpenGrantTransaction_when_targetIsNotActive() {
    when(userDirectoryPort.findUser(targetUserId))
        .thenReturn(Optional.of(new DirectoryUser(tenantId, false)));

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    verifyNoInteractions(transactionManager);
  }

  @Test
  void should_notOpenGrantTransaction_when_targetDoesNotExist() {
    when(userDirectoryPort.findUser(targetUserId)).thenReturn(Optional.empty());

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    verifyNoInteractions(transactionManager);
  }

  // ---------------------------------------------------------------------------------------------
  // T-008 (a): invalid argument. No argument value reaches the row or the page (L-6).
  // ---------------------------------------------------------------------------------------------

  @Test
  void should_refuseWithExit2_writeRowAndAlertWithoutTenantTargetOrChangeRef_when_recordInvalidArgument() {
    BreakGlassOutcome outcome = service.recordInvalidArgument();

    assertThat(outcome).isEqualTo(new BreakGlassOutcome.Refused(BreakGlassRefusalReason.INVALID_ARGUMENT));
    assertThat(outcome.exitCode()).isEqualTo(2);
    InOrder inOrder = inOrder(rbacAuditPort, breakGlassAlertPort);
    inOrder
        .verify(rbacAuditPort)
        .recordBreakGlassRefusal(new BreakGlassAuditEvent(null, null, null), "INVALID_ARGUMENT");
    inOrder
        .verify(breakGlassAlertPort)
        .alert(
            new BreakGlassAlert(null, null, BreakGlassAlert.Outcome.REFUSED, "INVALID_ARGUMENT", null));
    verifyNoMoreInteractions(rbacAuditPort, breakGlassAlertPort);
    verifyNoInteractions(
        grantLookupPort, userDirectoryPort, userRoleAssignmentPort, transactionManager);
  }

  @Test
  void should_takeNoParameters_when_recordingAnInvalidArgument() throws Exception {
    Method method = BootstrapAdminService.class.getMethod("recordInvalidArgument");

    assertThat(method.getParameterCount()).isZero();
    assertThat(Modifier.isPublic(method.getModifiers())).isTrue();
  }

  // ---------------------------------------------------------------------------------------------
  // T-008 (b): replay refusal (RC-37.2, RC-47)
  // ---------------------------------------------------------------------------------------------

  @Test
  void should_refuseWithExit6_auditAndAlert_beforeUserLookup_when_changeRefAlreadyUsed() {
    when(grantLookupPort.existsSuccessfulGrantWithChangeRef(CHANGE_REF.value())).thenReturn(true);

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertRefused(outcome, BreakGlassRefusalReason.CHANGE_REF_REUSED, 6, null);
    InOrder inOrder = inOrder(grantLookupPort, rbacAuditPort, breakGlassAlertPort);
    inOrder.verify(grantLookupPort).existsSuccessfulGrantWithChangeRef(CHANGE_REF.value());
    inOrder.verify(rbacAuditPort).recordBreakGlassRefusal(any(), eq("CHANGE_REF_REUSED"));
    inOrder.verify(breakGlassAlertPort).alert(any());
    verifyNoInteractions(userDirectoryPort, userRoleAssignmentPort, transactionManager);
  }

  @Test
  void should_queryLookupWithExactChangeRef() {
    ChangeRef longest = new ChangeRef("ABCDEFGHIJ-12345678");

    service.grantFirstAdmin(targetUserId, longest);

    verify(grantLookupPort).existsSuccessfulGrantWithChangeRef("ABCDEFGHIJ-12345678");
    verifyNoMoreInteractions(grantLookupPort);
  }

  @Test
  void should_lookUpChangeRefBeforeTheTarget_when_changeRefIsUnused() {
    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    InOrder inOrder = inOrder(grantLookupPort, userDirectoryPort, transactionManager);
    inOrder.verify(grantLookupPort).existsSuccessfulGrantWithChangeRef(CHANGE_REF.value());
    inOrder.verify(userDirectoryPort).findUser(targetUserId);
    inOrder.verify(transactionManager).getTransaction(any());
  }

  /** Fail closed: a lookup that cannot answer never grants and is not mapped to a refusal. */
  @Test
  void should_propagate_andTouchNothingElse_when_lookupThrows() {
    DataAccessResourceFailureException down = new DataAccessResourceFailureException("db down");
    when(grantLookupPort.existsSuccessfulGrantWithChangeRef(CHANGE_REF.value())).thenThrow(down);

    assertThatThrownBy(() -> service.grantFirstAdmin(targetUserId, CHANGE_REF)).isSameAs(down);

    verifyNoInteractions(
        userDirectoryPort, userRoleAssignmentPort, rbacAuditPort, breakGlassAlertPort, transactionManager);
  }

  // ---------------------------------------------------------------------------------------------
  // Grant path
  // ---------------------------------------------------------------------------------------------

  /**
   * A-6: the zero-admin precondition is the ADR-0018 CALLER-QUALIFYING population. A holder of a
   * role carrying only ONE dangerous permission is locked (it is in the ANY lock set) but is not
   * an administrator, so the tenant still has zero administrators.
   */
  @Test
  void should_grant_when_onlyHoldersOfASingleDangerousPermissionRoleExist() {
    UUID partialRoleId = UUID.randomUUID();
    List<RolePermissionName> permissions = new ArrayList<>(allDangerous(tenantAdminRoleId));
    permissions.add(new RolePermissionName(partialRoleId, "tenant:write"));
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId)).thenReturn(permissions);
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), anyList()))
        .thenReturn(
            List.of(new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), partialRoleId)));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(outcome).isInstanceOf(BreakGlassOutcome.Granted.class);
    assertThat(outcome.exitCode()).isZero();
    verify(userRoleAssignmentPort).assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId);
  }

  @Test
  void should_insertTenantAdminWithAssignedByEqualToTarget_andReturnExit0_when_tenantHasZeroAdmins() {
    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(outcome)
        .isEqualTo(new BreakGlassOutcome.Granted(tenantId, targetUserId, tenantAdminRoleId));
    assertThat(outcome.exitCode()).isZero();
    verify(userRoleAssignmentPort).assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId);
  }

  @Test
  void should_writeSuccessAuditWithChangeRefInsideTransaction_beforeReturn() throws Exception {
    TransactionSynchronizationManager.initSynchronization();

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    // Written inside the grant transaction, i.e. before its commit and any commit callback.
    InOrder inOrder = inOrder(transactionManager, userRoleAssignmentPort, rbacAuditPort);
    ArgumentCaptor<TransactionDefinition> definition =
        ArgumentCaptor.forClass(TransactionDefinition.class);
    inOrder.verify(transactionManager).getTransaction(definition.capture());
    inOrder.verify(userRoleAssignmentPort).assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId);
    inOrder
        .verify(rbacAuditPort)
        .recordBreakGlassGrant(new BreakGlassAuditEvent(tenantId, targetUserId, CHANGE_REF.value()));
    inOrder.verify(transactionManager).commit(any());
    verify(transactionManager, never()).rollback(any());
    verifyNoInteractions(breakGlassAlertPort);
    assertThat(definition.getValue().getPropagationBehavior())
        .isEqualTo(TransactionDefinition.PROPAGATION_REQUIRED);
    assertThat(definition.getValue().isReadOnly()).isFalse();
    // The orchestrator itself is not transactional: the refusal after a failed grant must be
    // written after the grant transaction has rolled back.
    Method method =
        BootstrapAdminService.class.getMethod("grantFirstAdmin", UUID.class, ChangeRef.class);
    assertThat(method.getAnnotation(Transactional.class)).isNull();
    assertThat(BootstrapAdminService.class.getAnnotation(Transactional.class)).isNull();
  }

  @Test
  void should_resolveTargetBeforeOpeningTheGrantTransaction() {
    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    InOrder inOrder = inOrder(userDirectoryPort, transactionManager, userRoleAssignmentPort);
    inOrder.verify(userDirectoryPort).findUser(targetUserId);
    inOrder.verify(transactionManager).getTransaction(any());
    inOrder.verify(userRoleAssignmentPort).findRoleIdByName(tenantId, "TENANT_ADMIN");
  }

  @Test
  void should_takeSetLockBeforeZeroAdminCheckBeforeInsert() {
    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    InOrder inOrder = inOrder(userRoleAssignmentPort, rbacAuditPort);
    inOrder.verify(userRoleAssignmentPort).findPermissionNamesForTenantRoles(tenantId);
    inOrder.verify(userRoleAssignmentPort).findRoleIdByName(tenantId, "TENANT_ADMIN");
    inOrder.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), anyList());
    inOrder.verify(userRoleAssignmentPort).assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId);
    inOrder.verify(rbacAuditPort).recordBreakGlassGrant(any());
    verify(userRoleAssignmentPort).lockActiveAssignmentHolders(any(), any());
  }

  /**
   * The lock set is the ANY-admin-equivalent ids plus TENANT_ADMIN, sorted by UNSIGNED byte-wise
   * order (MC-E). The fixture ids have the high bit set on one side, so a signed {@link
   * UUID#compareTo} order would differ.
   */
  @Test
  void should_lockTheAscendingUnsignedBytewiseSetOfAdminEquivalentIdsPlusTenantAdmin_inTheTargetsTenant() {
    UUID highBitAdmin = UUID.fromString("f0000000-0000-7000-8000-000000000001");
    UUID lowPartial = UUID.fromString("10000000-0000-7000-8000-000000000002");
    UUID midFull = UUID.fromString("70000000-0000-7000-8000-000000000003");
    UUID nonDangerous = UUID.fromString("20000000-0000-7000-8000-000000000004");
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(highBitAdmin));
    when(userRoleAssignmentPort.findRole(highBitAdmin))
        .thenReturn(Optional.of(role(highBitAdmin, "TENANT_ADMIN", true)));
    List<RolePermissionName> permissions = new ArrayList<>(allDangerous(highBitAdmin));
    permissions.addAll(allDangerous(midFull));
    permissions.add(new RolePermissionName(lowPartial, "role:write"));
    permissions.add(new RolePermissionName(nonDangerous, "user:read"));
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId)).thenReturn(permissions);
    when(userRoleAssignmentPort.assign(targetUserId, highBitAdmin, tenantId, targetUserId))
        .thenReturn(newAssignmentId);

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<UUID>> lockSet = ArgumentCaptor.forClass(List.class);
    verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), lockSet.capture());
    assertThat(lockSet.getValue()).containsExactly(lowPartial, midFull, highBitAdmin);
  }

  @Test
  void should_alertGrantedOnlyAfterCommit_when_synchronizationActive() {
    TransactionSynchronizationManager.initSynchronization();

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    verifyNoInteractions(breakGlassAlertPort);
    TransactionSynchronizationManager.getSynchronizations()
        .forEach(TransactionSynchronization::afterCommit);
    verify(breakGlassAlertPort)
        .alert(
            new BreakGlassAlert(
                tenantId, targetUserId, BreakGlassAlert.Outcome.GRANTED, null, CHANGE_REF.value()));
  }

  @Test
  void should_notAlertGranted_when_transactionDoesNotCommit() {
    TransactionSynchronizationManager.initSynchronization();

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    TransactionSynchronizationManager.getSynchronizations()
        .forEach(s -> s.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));
    verifyNoInteractions(breakGlassAlertPort);
  }

  // ---------------------------------------------------------------------------------------------
  // T-008: a failed grant transaction becomes an audited, paged refusal written after the rollback
  // (04-tasks.md T-008 risks; T-007 review finding 3).
  // ---------------------------------------------------------------------------------------------

  static Stream<Arguments> lockFailures() {
    return Stream.of(
        Arguments.of(new CannotAcquireLockException("Deadlock found (1213)")),
        Arguments.of(new DeadlockLoserDataAccessException("deadlock loser", null)),
        Arguments.of(new PessimisticLockingFailureException("Lock wait timeout exceeded (1205)")));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("lockFailures")
  void should_refuseWithExit7_writeFailureRowWithTenant_andAlert_when_assignThrowsALockFailure(
      PessimisticLockingFailureException lockFailure) {
    when(userRoleAssignmentPort.assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId))
        .thenThrow(lockFailure);

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertRefused(outcome, BreakGlassRefusalReason.CONCURRENT_INVOCATION, 7, tenantId);
  }

  @Test
  void should_refuseWithExit7_writeFailureRowWithTenant_andAlert_when_assignThrowsCannotAcquireLock() {
    when(userRoleAssignmentPort.assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId))
        .thenThrow(new CannotAcquireLockException("Deadlock found"));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertRefused(outcome, BreakGlassRefusalReason.CONCURRENT_INVOCATION, 7, tenantId);
    verify(rbacAuditPort, never()).recordBreakGlassGrant(any());
  }

  @Test
  void should_writeRefusalOnlyAfterGrantTransactionRolledBack() {
    when(userRoleAssignmentPort.assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId))
        .thenThrow(new CannotAcquireLockException("Deadlock found"));

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    InOrder inOrder = inOrder(transactionManager, rbacAuditPort, breakGlassAlertPort);
    inOrder.verify(transactionManager).getTransaction(any());
    inOrder.verify(transactionManager).rollback(any());
    inOrder.verify(rbacAuditPort).recordBreakGlassRefusal(any(), eq("CONCURRENT_INVOCATION"));
    inOrder.verify(breakGlassAlertPort).alert(any());
    verify(transactionManager, never()).commit(any());
  }

  @Test
  void should_notAlertGranted_when_deadlockRollsBackGrant() {
    when(userRoleAssignmentPort.assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId))
        .thenThrow(new CannotAcquireLockException("Deadlock found"));
    TransactionSynchronizationManager.initSynchronization();

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
    ArgumentCaptor<BreakGlassAlert> alerts = ArgumentCaptor.forClass(BreakGlassAlert.class);
    verify(breakGlassAlertPort).alert(alerts.capture());
    assertThat(alerts.getAllValues())
        .extracting(BreakGlassAlert::outcome)
        .containsExactly(BreakGlassAlert.Outcome.REFUSED);
  }

  @Test
  void should_refuseWithExit1_UNEXPECTED_ERROR_withTenant_andAlert_when_grantFailsWithNonLockingException() {
    doThrow(new RuntimeException("audit insert failed"))
        .when(rbacAuditPort)
        .recordBreakGlassGrant(any());

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertRefused(outcome, BreakGlassRefusalReason.UNEXPECTED_ERROR, 1, tenantId, true);
  }

  /**
   * RC-40.5: once the insert ran, a failed SUCCESS write rolls the grant back; the FAILURE row
   * that follows is written only after that rollback, so a SUCCESS and a FAILURE row never commit
   * for one invocation.
   */
  @Test
  void should_writeFailureRowOnlyAfterRollback_when_successAuditWriteThrowsAfterTheInsert() {
    doThrow(new RuntimeException("audit insert failed"))
        .when(rbacAuditPort)
        .recordBreakGlassGrant(any());

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    InOrder inOrder = inOrder(userRoleAssignmentPort, rbacAuditPort, transactionManager);
    inOrder.verify(userRoleAssignmentPort).assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId);
    inOrder.verify(rbacAuditPort).recordBreakGlassGrant(any());
    inOrder.verify(transactionManager).rollback(any());
    inOrder.verify(rbacAuditPort).recordBreakGlassRefusal(any(), eq("UNEXPECTED_ERROR"));
    verify(transactionManager, never()).commit(any());
  }

  /** A commit failure (after the SUCCESS write) is still a refusal, and the grant is never paged. */
  @Test
  void should_refuseWithExit1_andNeverAlertGranted_when_commitFails() {
    doThrow(new TransactionSystemException("commit failed")).when(transactionManager).commit(any());
    TransactionSynchronizationManager.initSynchronization();

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(outcome)
        .isEqualTo(new BreakGlassOutcome.Refused(BreakGlassRefusalReason.UNEXPECTED_ERROR));
    verify(rbacAuditPort)
        .recordBreakGlassRefusal(
            new BreakGlassAuditEvent(tenantId, targetUserId, CHANGE_REF.value()), "UNEXPECTED_ERROR");
    ArgumentCaptor<BreakGlassAlert> alerts = ArgumentCaptor.forClass(BreakGlassAlert.class);
    verify(breakGlassAlertPort).alert(alerts.capture());
    assertThat(alerts.getValue().outcome()).isEqualTo(BreakGlassAlert.Outcome.REFUSED);
  }

  /** The refusal write never throws (Group B); if it loses the row, the page still goes out. */
  @Test
  void should_stillAlert_when_refusalWriteLosesTheRow() {
    when(userRoleAssignmentPort.assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId))
        .thenThrow(new CannotAcquireLockException("Deadlock found"));
    // The port contract is never-throw: a lost row is logged inside the adapter and swallowed,
    // which a mock models as doing nothing.

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    verify(breakGlassAlertPort)
        .alert(
            new BreakGlassAlert(
                tenantId,
                targetUserId,
                BreakGlassAlert.Outcome.REFUSED,
                "CONCURRENT_INVOCATION",
                CHANGE_REF.value()));
  }

  /** Errors are not refusals: they propagate after the rollback with no row and no page. */
  @Test
  void should_propagate_withNoRefusalRowAndNoAlert_when_grantThrowsAnError() {
    AssertionError error = new AssertionError("not a RuntimeException");
    when(userRoleAssignmentPort.assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId))
        .thenThrow(error);

    assertThatThrownBy(() -> service.grantFirstAdmin(targetUserId, CHANGE_REF)).isSameAs(error);

    verify(transactionManager).rollback(any());
    verify(rbacAuditPort, never()).recordBreakGlassRefusal(any(), anyString());
    verifyNoInteractions(breakGlassAlertPort);
  }

  // ---------------------------------------------------------------------------------------------
  // Arguments (finding 2): a missing target or change reference is a programming error, never a
  // grant without attribution.
  // ---------------------------------------------------------------------------------------------

  @Test
  void should_throwNullPointerWithClearMessage_andTouchNothing_when_targetUserIdIsNull() {
    assertThatThrownBy(() -> service.grantFirstAdmin(null, CHANGE_REF))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("targetUserId must not be null");

    verifyNoInteractions(
        userDirectoryPort,
        userRoleAssignmentPort,
        rbacAuditPort,
        breakGlassAlertPort,
        grantLookupPort,
        transactionManager);
  }

  @Test
  void should_throwNullPointerWithClearMessage_andTouchNothing_when_changeRefIsNull() {
    assertThatThrownBy(() -> service.grantFirstAdmin(targetUserId, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("changeRef must not be null");

    verifyNoInteractions(
        userDirectoryPort,
        userRoleAssignmentPort,
        rbacAuditPort,
        breakGlassAlertPort,
        grantLookupPort,
        transactionManager);
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------------

  private void assertRefused(
      BreakGlassOutcome outcome, BreakGlassRefusalReason reason, int exitCode, UUID expectedTenant) {
    assertRefused(outcome, reason, exitCode, expectedTenant, false);
  }

  private void assertRefused(
      BreakGlassOutcome outcome,
      BreakGlassRefusalReason reason,
      int exitCode,
      UUID expectedTenant,
      boolean successWriteAttempted) {
    assertThat(outcome).isEqualTo(new BreakGlassOutcome.Refused(reason));
    assertThat(outcome.exitCode()).isEqualTo(exitCode);
    InOrder inOrder = inOrder(rbacAuditPort, breakGlassAlertPort);
    inOrder
        .verify(rbacAuditPort)
        .recordBreakGlassRefusal(
            new BreakGlassAuditEvent(expectedTenant, targetUserId, CHANGE_REF.value()), reason.name());
    inOrder
        .verify(breakGlassAlertPort)
        .alert(
            new BreakGlassAlert(
                expectedTenant,
                targetUserId,
                BreakGlassAlert.Outcome.REFUSED,
                reason.name(),
                CHANGE_REF.value()));
    verify(rbacAuditPort).recordBreakGlassRefusal(any(), anyString());
    if (!successWriteAttempted) {
      verify(rbacAuditPort, never()).recordBreakGlassGrant(any());
    }
    verify(breakGlassAlertPort).alert(any());
  }

  private Role role(UUID id, String name, boolean systemRole) {
    return new Role(id, tenantId, name, "test role", systemRole);
  }

  private static List<RolePermissionName> allDangerous(UUID roleId) {
    return List.of(
        new RolePermissionName(roleId, "role:write"),
        new RolePermissionName(roleId, "user:write"),
        new RolePermissionName(roleId, "tenant:write"));
  }
}
