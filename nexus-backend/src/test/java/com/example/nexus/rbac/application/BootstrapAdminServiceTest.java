package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlertPort;
import com.example.nexus.rbac.application.port.out.BreakGlassAuditEvent;
import com.example.nexus.rbac.application.port.out.DirectoryUser;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermissionName;
import java.lang.reflect.Method;
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
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * US-018 T-007 (03-design.md §7.1, §7.2): the break-glass first-administrator grant. Plain
 * Mockito, no Spring context.
 */
@Tag("UnitTest")
class BootstrapAdminServiceTest {

  private static final String CHANGE_REF = "OPS-42";

  private final UUID tenantId = UUID.randomUUID();
  private final UUID targetUserId = UUID.randomUUID();
  private final UUID tenantAdminRoleId = UUID.randomUUID();
  private final UUID newAssignmentId = UUID.randomUUID();

  private UserDirectoryPort userDirectoryPort;
  private UserRoleAssignmentPort userRoleAssignmentPort;
  private RbacAuditPort rbacAuditPort;
  private BreakGlassAlertPort breakGlassAlertPort;
  private BootstrapAdminService service;

  @BeforeEach
  void setUp() {
    userDirectoryPort = mock(UserDirectoryPort.class);
    userRoleAssignmentPort = mock(UserRoleAssignmentPort.class);
    rbacAuditPort = mock(RbacAuditPort.class);
    breakGlassAlertPort = mock(BreakGlassAlertPort.class);
    service =
        new BootstrapAdminService(
            userDirectoryPort, userRoleAssignmentPort, rbacAuditPort, breakGlassAlertPort);

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

    // Written before the method returned, i.e. before any commit callback has run.
    verify(rbacAuditPort)
        .recordBreakGlassGrant(new BreakGlassAuditEvent(tenantId, targetUserId, CHANGE_REF));
    verifyNoInteractions(breakGlassAlertPort);
    Method method =
        BootstrapAdminService.class.getMethod("grantFirstAdmin", UUID.class, String.class);
    Transactional transactional = method.getAnnotation(Transactional.class);
    assertThat(transactional).isNotNull();
    assertThat(transactional.propagation()).isEqualTo(Propagation.REQUIRED);
    assertThat(transactional.readOnly()).isFalse();
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
        .alert(new BreakGlassAlert(tenantId, targetUserId, "GRANTED", null, CHANGE_REF));
  }

  @Test
  void should_notAlertGranted_when_transactionDoesNotCommit() {
    TransactionSynchronizationManager.initSynchronization();

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    TransactionSynchronizationManager.getSynchronizations()
        .forEach(s -> s.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));
    verifyNoInteractions(breakGlassAlertPort);
  }

  @Test
  void should_propagate_andNotAlertGranted_when_successAuditWriteThrows() {
    RuntimeException auditFailure = new RuntimeException("audit insert failed");
    doThrow(auditFailure).when(rbacAuditPort).recordBreakGlassGrant(any());

    assertThatThrownBy(() -> service.grantFirstAdmin(targetUserId, CHANGE_REF))
        .isSameAs(auditFailure);

    verifyNoInteractions(breakGlassAlertPort);
  }

  @Test
  void should_neverWriteAFailureRowAfterASuccessRow() {
    service.grantFirstAdmin(targetUserId, CHANGE_REF);
    doThrow(new RuntimeException("audit insert failed"))
        .when(rbacAuditPort)
        .recordBreakGlassGrant(any());
    assertThatThrownBy(() -> service.grantFirstAdmin(targetUserId, CHANGE_REF))
        .isInstanceOf(RuntimeException.class);

    verify(rbacAuditPort, never()).recordBreakGlassRefusal(any(), anyString());
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------------

  private void assertRefused(
      BreakGlassOutcome outcome, BreakGlassRefusalReason reason, int exitCode, UUID expectedTenant) {
    assertThat(outcome).isEqualTo(new BreakGlassOutcome.Refused(reason));
    assertThat(outcome.exitCode()).isEqualTo(exitCode);
    InOrder inOrder = inOrder(rbacAuditPort, breakGlassAlertPort);
    inOrder
        .verify(rbacAuditPort)
        .recordBreakGlassRefusal(
            new BreakGlassAuditEvent(expectedTenant, targetUserId, CHANGE_REF), reason.name());
    inOrder
        .verify(breakGlassAlertPort)
        .alert(
            new BreakGlassAlert(expectedTenant, targetUserId, "REFUSED", reason.name(), CHANGE_REF));
    verify(rbacAuditPort).recordBreakGlassRefusal(any(), anyString());
    verify(rbacAuditPort, never()).recordBreakGlassGrant(any());
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
