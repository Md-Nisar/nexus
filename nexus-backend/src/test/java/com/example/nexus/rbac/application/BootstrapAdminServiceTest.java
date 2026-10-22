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
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.rbac.application.port.out.DirectoryUser;
import com.example.nexus.rbac.application.port.out.DirectoryUserStatus;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermissionRef;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.EnumSource;
import org.slf4j.LoggerFactory;
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

  // The fixture catalogue: three permission ids. A role carrying all three is admin-defining; a
  // role carrying fewer is not (ADR-0021 D3).
  private static final UUID PERMISSION_A = UUID.fromString("00000000-0000-7000-8000-00000000000a");
  private static final UUID PERMISSION_B = UUID.fromString("00000000-0000-7000-8000-00000000000b");
  private static final UUID PERMISSION_C = UUID.fromString("00000000-0000-7000-8000-00000000000c");
  private static final java.util.Set<UUID> CATALOGUE =
      java.util.Set.of(PERMISSION_A, PERMISSION_B, PERMISSION_C);

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
  private ListAppender<ILoggingEvent> serviceLog;

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
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(CATALOGUE);
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId))
        .thenReturn(wholeCatalogue(tenantAdminRoleId));
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), anyList()))
        .thenReturn(List.of());
    when(userRoleAssignmentPort.assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId))
        .thenReturn(newAssignmentId);
    when(userDirectoryPort.lockUserStatuses(eq(tenantId), any()))
        .thenReturn(Map.of(targetUserId, DirectoryUserStatus.ACTIVE));

    serviceLog = new ListAppender<>();
    serviceLog.start();
    serviceLogger().addAppender(serviceLog);
  }

  @AfterEach
  void clearSynchronization() {
    if (TransactionSynchronizationManager.isSynchronizationActive()) {
      TransactionSynchronizationManager.clearSynchronization();
    }
    serviceLogger().detachAppender(serviceLog);
    serviceLog.stop();
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

  /** T-019: a tenant whose only administrator holds a custom admin-defining role is refused. */
  @Test
  void should_refuseWithExit5_when_lockedRowsHoldACustomAdminDefiningRole() {
    UUID customRoleId = UUID.randomUUID();
    List<RolePermissionRef> permissions = new ArrayList<>(wholeCatalogue(tenantAdminRoleId));
    permissions.addAll(wholeCatalogue(customRoleId));
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId)).thenReturn(permissions);
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

    verify(userRoleAssignmentPort, never()).findRolePermissionIdsForTenantRoles(any());
    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(userDirectoryPort, never()).lockUserStatuses(any(), any());
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
   * A-6 (re-scoped by US-018 T-019): the zero-admin precondition is the one definition of
   * "administrator", a holder of a role carrying every permission of the catalogue. A holder of a
   * role one permission short is not an administrator, so the tenant still has zero administrators
   * and the grant goes ahead.
   */
  @Test
  void should_grant_when_onlyHoldersOfARoleOnePermissionShortOfTheCatalogueExist() {
    UUID partialRoleId = UUID.randomUUID();
    List<RolePermissionRef> permissions = new ArrayList<>(wholeCatalogue(tenantAdminRoleId));
    permissions.add(new RolePermissionRef(partialRoleId, PERMISSION_A));
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId)).thenReturn(permissions);
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
    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    // Written inside the grant transaction, i.e. before its commit; the page only after it.
    InOrder inOrder =
        inOrder(transactionManager, userRoleAssignmentPort, rbacAuditPort, breakGlassAlertPort);
    ArgumentCaptor<TransactionDefinition> definition =
        ArgumentCaptor.forClass(TransactionDefinition.class);
    inOrder.verify(transactionManager).getTransaction(definition.capture());
    inOrder.verify(userRoleAssignmentPort).assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId);
    inOrder
        .verify(rbacAuditPort)
        .recordBreakGlassGrant(new BreakGlassAuditEvent(tenantId, targetUserId, CHANGE_REF.value()));
    inOrder.verify(transactionManager).commit(any());
    inOrder.verify(breakGlassAlertPort).alert(any());
    verify(transactionManager, never()).rollback(any());
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
    inOrder.verify(userRoleAssignmentPort).findRoleIdByName(tenantId, "TENANT_ADMIN");
    inOrder.verify(userRoleAssignmentPort).findRolePermissionIdsForTenantRoles(tenantId);
    inOrder.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), anyList());
    inOrder.verify(userRoleAssignmentPort).assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId);
    inOrder.verify(rbacAuditPort).recordBreakGlassGrant(any());
    verify(userRoleAssignmentPort).lockActiveAssignmentHolders(any(), any());
  }

  /**
   * The lock set is the admin-defining ids plus TENANT_ADMIN, sorted by UNSIGNED byte-wise order
   * (MC-E). The fixture ids have the high bit set on one side, so a signed {@link UUID#compareTo}
   * order would differ. A role that is one permission short, or benign, is not in the set.
   */
  @Test
  void should_lockTheAscendingUnsignedBytewiseSetOfAdminDefiningIdsPlusTenantAdmin_inTheTargetsTenant() {
    UUID highBitAdmin = UUID.fromString("f0000000-0000-7000-8000-000000000001");
    UUID lowPartial = UUID.fromString("10000000-0000-7000-8000-000000000002");
    UUID midFull = UUID.fromString("70000000-0000-7000-8000-000000000003");
    UUID benignRole = UUID.fromString("20000000-0000-7000-8000-000000000004");
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(highBitAdmin));
    when(userRoleAssignmentPort.findRole(highBitAdmin))
        .thenReturn(Optional.of(role(highBitAdmin, "TENANT_ADMIN", true)));
    List<RolePermissionRef> permissions = new ArrayList<>(wholeCatalogue(highBitAdmin));
    permissions.addAll(wholeCatalogue(midFull));
    permissions.add(new RolePermissionRef(lowPartial, PERMISSION_A));
    permissions.add(new RolePermissionRef(benignRole, PERMISSION_B));
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId)).thenReturn(permissions);
    when(userRoleAssignmentPort.assign(targetUserId, highBitAdmin, tenantId, targetUserId))
        .thenReturn(newAssignmentId);

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<UUID>> lockSet = ArgumentCaptor.forClass(List.class);
    verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), lockSet.capture());
    assertThat(lockSet.getValue()).containsExactly(midFull, highBitAdmin);
  }

  /**
   * T-008 review Low 1: the GRANTED page is sent after {@code execute} returned, so after the
   * commit by construction; the callback registers no commit hook.
   */
  @Test
  void should_alertGrantedOnceAfterCommit_andRegisterNoCommitHook_when_granted() {
    TransactionSynchronizationManager.initSynchronization();

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
    InOrder inOrder = inOrder(transactionManager, breakGlassAlertPort);
    inOrder.verify(transactionManager).commit(any());
    inOrder
        .verify(breakGlassAlertPort)
        .alert(
            new BreakGlassAlert(
                tenantId, targetUserId, BreakGlassAlert.Outcome.GRANTED, null, CHANGE_REF.value()));
    verifyNoMoreInteractions(breakGlassAlertPort);
  }

  /**
   * T-008 review Low 1 (a): a failed GRANTED page after the commit is logged, best effort; the
   * committed grant stays a grant (exit 0) and no UNEXPECTED_ERROR FAILURE row or page follows.
   */
  @Test
  void should_returnGrantedExit0_andWriteNoFailureRowNorRefusalPage_when_grantedAlertThrowsAfterCommit() {
    doThrow(new IllegalStateException("appender down"))
        .when(breakGlassAlertPort)
        .alert(
            new BreakGlassAlert(
                tenantId, targetUserId, BreakGlassAlert.Outcome.GRANTED, null, CHANGE_REF.value()));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(outcome)
        .isEqualTo(new BreakGlassOutcome.Granted(tenantId, targetUserId, tenantAdminRoleId));
    assertThat(outcome.exitCode()).isZero();
    verify(rbacAuditPort, never()).recordBreakGlassRefusal(any(), anyString());
    verify(breakGlassAlertPort).alert(any());
    verify(transactionManager).commit(any());
    verify(transactionManager, never()).rollback(any());
  }

  /**
   * T-008 review Low 1 (b): a TENANT_HAS_ADMIN refusal decided under the lock is audited and paged
   * exactly once, after the grant transaction has ended, and exits 5.
   */
  @Test
  void should_writeExactlyOneFailureRowAndPageAfterCommit_andExit5_when_tenantHasAdmin() {
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), anyList()))
        .thenReturn(
            List.of(new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), tenantAdminRoleId)));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(outcome.exitCode()).isEqualTo(5);
    InOrder inOrder = inOrder(transactionManager, rbacAuditPort, breakGlassAlertPort);
    inOrder.verify(transactionManager).commit(any());
    inOrder
        .verify(rbacAuditPort)
        .recordBreakGlassRefusal(
            new BreakGlassAuditEvent(tenantId, targetUserId, CHANGE_REF.value()), "TENANT_HAS_ADMIN");
    inOrder.verify(breakGlassAlertPort).alert(any());
    verifyNoMoreInteractions(rbacAuditPort, breakGlassAlertPort);
  }

  @Test
  void should_writeFailureRowAfterCommit_when_noSystemAdminRole() {
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.empty());

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    InOrder inOrder = inOrder(transactionManager, rbacAuditPort, breakGlassAlertPort);
    inOrder.verify(transactionManager).commit(any());
    inOrder.verify(rbacAuditPort).recordBreakGlassRefusal(any(), eq("NO_SYSTEM_ADMIN_ROLE"));
    inOrder.verify(breakGlassAlertPort).alert(any());
  }

  /**
   * T-008 review Low 1 (b): when the transaction that decided TENANT_HAS_ADMIN then fails to
   * commit, only the UNEXPECTED_ERROR refusal is written and paged, never both.
   */
  @Test
  void should_writeOnlyOneUnexpectedErrorRowAndPage_when_tenantHasAdminAndCommitFails() {
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), anyList()))
        .thenReturn(
            List.of(new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), tenantAdminRoleId)));
    doThrow(new TransactionSystemException("commit failed")).when(transactionManager).commit(any());

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertRefused(outcome, BreakGlassRefusalReason.UNEXPECTED_ERROR, 1, tenantId);
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
  // O-7 (security review M-1, owner decision 2026-10-15): for A7 only, a holder whose user is
  // DISABLED is not an administrator. Statuses are read under the set lock (locking read).
  // ---------------------------------------------------------------------------------------------

  @Test
  void should_grantExit0_andWriteSuccessRow_when_theSoleAdministratorIsDisabled() {
    UUID disabledAdmin = UUID.randomUUID();
    lockedHolders(holder(disabledAdmin, tenantAdminRoleId));
    lockedStatuses(Map.of(targetUserId, DirectoryUserStatus.ACTIVE, disabledAdmin, DirectoryUserStatus.DISABLED));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(outcome)
        .isEqualTo(new BreakGlassOutcome.Granted(tenantId, targetUserId, tenantAdminRoleId));
    assertThat(outcome.exitCode()).isZero();
    verify(userRoleAssignmentPort).assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId);
    verify(rbacAuditPort)
        .recordBreakGlassGrant(new BreakGlassAuditEvent(tenantId, targetUserId, CHANGE_REF.value()));
    verify(rbacAuditPort, never()).recordBreakGlassRefusal(any(), anyString());
  }

  @Test
  void should_grant_when_everyAdministratorIncludingACustomAdminDefiningRoleHolderIsDisabled() {
    UUID customRoleId = UUID.randomUUID();
    List<RolePermissionRef> permissions = new ArrayList<>(wholeCatalogue(tenantAdminRoleId));
    permissions.addAll(wholeCatalogue(customRoleId));
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId)).thenReturn(permissions);
    UUID disabledNamed = UUID.randomUUID();
    UUID disabledCustom = UUID.randomUUID();
    lockedHolders(holder(disabledNamed, tenantAdminRoleId), holder(disabledCustom, customRoleId));
    lockedStatuses(
        Map.of(
            targetUserId, DirectoryUserStatus.ACTIVE,
            disabledNamed, DirectoryUserStatus.DISABLED,
            disabledCustom, DirectoryUserStatus.DISABLED));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(outcome.exitCode()).isZero();
  }

  /** LOCKED (self-recovering lockout), PENDING and ACTIVE holders still count: exit 5. */
  @ParameterizedTest(name = "{0}")
  @EnumSource(value = DirectoryUserStatus.class, names = "DISABLED", mode = EnumSource.Mode.EXCLUDE)
  void should_refuseWithExit5_andInsertNothing_when_theSoleAdministratorIsNotDisabled(
      DirectoryUserStatus status) {
    UUID admin = UUID.randomUUID();
    lockedHolders(holder(admin, tenantAdminRoleId));
    lockedStatuses(Map.of(targetUserId, DirectoryUserStatus.ACTIVE, admin, status));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertRefused(outcome, BreakGlassRefusalReason.TENANT_HAS_ADMIN, 5, tenantId);
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
  }

  @Test
  void should_refuseWithExit5_when_oneAdministratorIsDisabledAndAnotherIsActive() {
    UUID disabledAdmin = UUID.randomUUID();
    UUID activeAdmin = UUID.randomUUID();
    lockedHolders(holder(disabledAdmin, tenantAdminRoleId), holder(activeAdmin, tenantAdminRoleId));
    lockedStatuses(
        Map.of(
            targetUserId, DirectoryUserStatus.ACTIVE,
            disabledAdmin, DirectoryUserStatus.DISABLED,
            activeAdmin, DirectoryUserStatus.ACTIVE));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertRefused(outcome, BreakGlassRefusalReason.TENANT_HAS_ADMIN, 5, tenantId);
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
  }

  /** Fail closed: a holder whose status the locking read did not return still counts. */
  @Test
  void should_refuseWithExit5_when_aHoldersStatusIsNotReturnedByTheLockingRead() {
    lockedHolders(holder(UUID.randomUUID(), tenantAdminRoleId));
    lockedStatuses(Map.of(targetUserId, DirectoryUserStatus.ACTIVE));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertRefused(outcome, BreakGlassRefusalReason.TENANT_HAS_ADMIN, 5, tenantId);
  }

  /**
   * The statuses are read by a locking read of the target and the administrator holders only (a
   * holder of a role one permission short of the catalogue is not an administrator and is not
   * read), in the target's tenant, after the set lock and before the insert.
   */
  @Test
  void should_lockStatusesOfTargetAndAdministratorHolders_afterTheSetLock_beforeTheInsert() {
    UUID partialRoleId = UUID.randomUUID();
    List<RolePermissionRef> permissions = new ArrayList<>(wholeCatalogue(tenantAdminRoleId));
    permissions.add(new RolePermissionRef(partialRoleId, PERMISSION_A));
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId)).thenReturn(permissions);
    UUID disabledAdmin = UUID.randomUUID();
    UUID partialHolder = UUID.randomUUID();
    lockedHolders(holder(disabledAdmin, tenantAdminRoleId), holder(partialHolder, partialRoleId));
    lockedStatuses(Map.of(targetUserId, DirectoryUserStatus.ACTIVE, disabledAdmin, DirectoryUserStatus.DISABLED));

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<Collection<UUID>> userIds = ArgumentCaptor.forClass(Collection.class);
    InOrder inOrder = inOrder(transactionManager, userRoleAssignmentPort, userDirectoryPort);
    inOrder.verify(transactionManager).getTransaction(any());
    inOrder.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), anyList());
    inOrder.verify(userDirectoryPort).lockUserStatuses(eq(tenantId), userIds.capture());
    inOrder.verify(userRoleAssignmentPort).assign(targetUserId, tenantAdminRoleId, tenantId, targetUserId);
    inOrder.verify(transactionManager).commit(any());
    assertThat(userIds.getValue()).containsExactlyInAnyOrder(targetUserId, disabledAdmin);
  }

  // ---------------------------------------------------------------------------------------------
  // L-2: the target's ACTIVE check is repeated inside the grant transaction, after the set lock,
  // on the locking read, so a target disabled concurrently is never granted.
  // ---------------------------------------------------------------------------------------------

  static Stream<Arguments> targetStatusesUnderTheLock() {
    return Stream.of(
        Arguments.of("PENDING", DirectoryUserStatus.PENDING),
        Arguments.of("LOCKED", DirectoryUserStatus.LOCKED),
        Arguments.of("DISABLED", DirectoryUserStatus.DISABLED),
        Arguments.of("not returned", null));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("targetStatusesUnderTheLock")
  void should_refuseWithExit3_afterTheTransaction_andInsertNothing_when_targetIsNotActiveUnderTheLock(
      String label, DirectoryUserStatus lockedStatus) {
    Map<UUID, DirectoryUserStatus> statuses = new HashMap<>();
    if (lockedStatus != null) {
      statuses.put(targetUserId, lockedStatus);
    }
    lockedStatuses(statuses);

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertRefused(outcome, BreakGlassRefusalReason.TARGET_USER_NOT_ACTIVE, 3, tenantId);
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    InOrder inOrder = inOrder(userDirectoryPort, transactionManager, rbacAuditPort);
    inOrder.verify(userDirectoryPort).lockUserStatuses(eq(tenantId), any());
    inOrder.verify(transactionManager).commit(any());
    inOrder.verify(rbacAuditPort).recordBreakGlassRefusal(any(), eq("TARGET_USER_NOT_ACTIVE"));
  }

  // ---------------------------------------------------------------------------------------------
  // L-1: a refusal page is best effort, like the GRANTED page. A throwing alert port never changes
  // the refusal's exit code; it is logged as RBAC_BREAK_GLASS_ALERT_FAILED with no argument value.
  // ---------------------------------------------------------------------------------------------

  static Stream<Arguments> refusalsWithAThrowingPage() {
    return Stream.of(
        Arguments.of(
            BreakGlassRefusalReason.INVALID_ARGUMENT,
            (Function<BootstrapAdminServiceTest, BreakGlassOutcome>)
                t -> t.service.recordInvalidArgument()),
        Arguments.of(
            BreakGlassRefusalReason.CHANGE_REF_REUSED,
            (Function<BootstrapAdminServiceTest, BreakGlassOutcome>)
                t -> {
                  when(t.grantLookupPort.existsSuccessfulGrantWithChangeRef(CHANGE_REF.value()))
                      .thenReturn(true);
                  return t.service.grantFirstAdmin(t.targetUserId, CHANGE_REF);
                }),
        Arguments.of(
            BreakGlassRefusalReason.TARGET_USER_NOT_FOUND,
            (Function<BootstrapAdminServiceTest, BreakGlassOutcome>)
                t -> {
                  when(t.userDirectoryPort.findUser(t.targetUserId)).thenReturn(Optional.empty());
                  return t.service.grantFirstAdmin(t.targetUserId, CHANGE_REF);
                }),
        Arguments.of(
            BreakGlassRefusalReason.NO_SYSTEM_ADMIN_ROLE,
            (Function<BootstrapAdminServiceTest, BreakGlassOutcome>)
                t -> {
                  when(t.userRoleAssignmentPort.findRoleIdByName(t.tenantId, "TENANT_ADMIN"))
                      .thenReturn(Optional.empty());
                  return t.service.grantFirstAdmin(t.targetUserId, CHANGE_REF);
                }),
        Arguments.of(
            BreakGlassRefusalReason.TENANT_HAS_ADMIN,
            (Function<BootstrapAdminServiceTest, BreakGlassOutcome>)
                t -> {
                  t.lockedHolders(t.holder(UUID.randomUUID(), t.tenantAdminRoleId));
                  return t.service.grantFirstAdmin(t.targetUserId, CHANGE_REF);
                }),
        Arguments.of(
            BreakGlassRefusalReason.CONCURRENT_INVOCATION,
            (Function<BootstrapAdminServiceTest, BreakGlassOutcome>)
                t -> {
                  when(t.userRoleAssignmentPort.assign(
                          t.targetUserId, t.tenantAdminRoleId, t.tenantId, t.targetUserId))
                      .thenThrow(new CannotAcquireLockException("Deadlock found"));
                  return t.service.grantFirstAdmin(t.targetUserId, CHANGE_REF);
                }),
        Arguments.of(
            BreakGlassRefusalReason.UNEXPECTED_ERROR,
            (Function<BootstrapAdminServiceTest, BreakGlassOutcome>)
                t -> {
                  when(t.userDirectoryPort.lockUserStatuses(eq(t.tenantId), any()))
                      .thenThrow(new DataAccessResourceFailureException("connection lost"));
                  return t.service.grantFirstAdmin(t.targetUserId, CHANGE_REF);
                }));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("refusalsWithAThrowingPage")
  void should_keepTheRefusalExitCode_writeOneFailureRow_andLogAlertFailed_when_refusalPageThrows(
      BreakGlassRefusalReason reason, Function<BootstrapAdminServiceTest, BreakGlassOutcome> act) {
    doThrow(new IllegalStateException("appender down")).when(breakGlassAlertPort).alert(any());

    BreakGlassOutcome outcome = act.apply(this);

    assertThat(outcome).isEqualTo(new BreakGlassOutcome.Refused(reason));
    assertThat(outcome.exitCode()).isEqualTo(reason.exitCode());
    verify(rbacAuditPort).recordBreakGlassRefusal(any(), eq(reason.name()));
    verify(rbacAuditPort, never()).recordBreakGlassGrant(any());
    verify(breakGlassAlertPort).alert(any());
    List<ILoggingEvent> failures =
        serviceLog.list.stream()
            .filter(e -> "RBAC_BREAK_GLASS_ALERT_FAILED".equals(keyValues(e).get("event")))
            .toList();
    assertThat(failures).hasSize(1);
    ILoggingEvent failure = failures.get(0);
    assertThat(failure.getLevel()).isEqualTo(Level.ERROR);
    assertThat(keyValues(failure)).containsEntry("reason", reason.name());
    assertThat(failure.getThrowableProxy().getMessage()).isEqualTo("appender down");
    for (ILoggingEvent event : serviceLog.list) {
      assertThat(event.getFormattedMessage() + "|" + event.getKeyValuePairs())
          .doesNotContain(targetUserId.toString(), CHANGE_REF.value());
    }
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

  private ActiveAssignmentHolder holder(UUID userId, UUID roleId) {
    return new ActiveAssignmentHolder(UUID.randomUUID(), userId, roleId);
  }

  private void lockedHolders(ActiveAssignmentHolder... holders) {
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), anyList()))
        .thenReturn(List.of(holders));
  }

  private void lockedStatuses(Map<UUID, DirectoryUserStatus> statuses) {
    when(userDirectoryPort.lockUserStatuses(eq(tenantId), any())).thenReturn(statuses);
  }

  private static Map<String, Object> keyValues(ILoggingEvent event) {
    Map<String, Object> map = new HashMap<>();
    if (event.getKeyValuePairs() != null) {
      event.getKeyValuePairs().forEach(kv -> map.put(kv.key, kv.value));
    }
    return map;
  }

  private static Logger serviceLogger() {
    return (Logger) LoggerFactory.getLogger(BootstrapAdminService.class);
  }

  private Role role(UUID id, String name, boolean systemRole) {
    return new Role(id, tenantId, name, "test role", systemRole);
  }

  /** A role carrying every permission of the fixture catalogue: admin-defining (ADR-0021 D3). */
  private static List<RolePermissionRef> wholeCatalogue(UUID roleId) {
    return List.of(
        new RolePermissionRef(roleId, PERMISSION_A),
        new RolePermissionRef(roleId, PERMISSION_B),
        new RolePermissionRef(roleId, PERMISSION_C));
  }
}
