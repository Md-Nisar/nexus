package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlertPort;
import com.example.nexus.rbac.application.port.out.BreakGlassAuditEvent;
import com.example.nexus.rbac.application.port.out.BreakGlassGrantLookupPort;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort.DirectoryUser;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermissionName;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Unit tests for {@link BootstrapAdminService} (US-018 A7, T-007; 03-design.md §7.1). */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class BootstrapAdminServiceTest {

  private static final String CHANGE_REF = "OPS-4711";

  @Mock private UserRoleAssignmentPort userRoleAssignmentPort;
  @Mock private UserDirectoryPort userDirectoryPort;
  @Mock private RbacAuditPort rbacAuditPort;
  @Mock private BreakGlassAlertPort alertPort;
  @Mock private BreakGlassGrantLookupPort grantLookupPort;

  private BootstrapAdminService service;

  private UUID tenantId;
  private UUID targetUserId;
  private UUID adminRoleId;

  @BeforeEach
  void setUp() {
    service =
        new BootstrapAdminService(
            userRoleAssignmentPort, userDirectoryPort, rbacAuditPort, alertPort, grantLookupPort);
    tenantId = UUID.randomUUID();
    targetUserId = UUID.randomUUID();
    adminRoleId = UUID.randomUUID();
  }

  @AfterEach
  void clearSynchronization() {
    if (TransactionSynchronizationManager.isSynchronizationActive()) {
      TransactionSynchronizationManager.clearSynchronization();
    }
  }

  private void givenActiveTargetWithSystemAdminRole() {
    when(userDirectoryPort.findDirectoryUser(targetUserId))
        .thenReturn(Optional.of(new DirectoryUser(tenantId, true)));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, RbacRoleNames.TENANT_ADMIN))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.findRole(adminRoleId))
        .thenReturn(
            Optional.of(new Role(adminRoleId, tenantId, RbacRoleNames.TENANT_ADMIN, null, true)));
  }

  private void givenHolders(ActiveAssignmentHolder... holders) {
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId)).thenReturn(List.of());
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(List.of(holders));
  }

  private BreakGlassAuditEvent capturedRefusal() {
    ArgumentCaptor<BreakGlassAuditEvent> captor =
        ArgumentCaptor.forClass(BreakGlassAuditEvent.class);
    verify(rbacAuditPort).recordBreakGlassRefused(captor.capture());
    return captor.getValue();
  }

  private BreakGlassAlert capturedAlert() {
    ArgumentCaptor<BreakGlassAlert> captor = ArgumentCaptor.forClass(BreakGlassAlert.class);
    verify(alertPort).raise(captor.capture());
    return captor.getValue();
  }

  private void assertRefusedWithoutGrant(String reason, UUID expectedTenant) {
    BreakGlassAuditEvent row = capturedRefusal();
    assertThat(row.reason()).isEqualTo(reason);
    assertThat(row.tenantId()).isEqualTo(expectedTenant);
    assertThat(row.targetUserId()).isEqualTo(targetUserId);
    assertThat(row.changeRef()).isEqualTo(CHANGE_REF);
    BreakGlassAlert alert = capturedAlert();
    assertThat(alert.outcome()).isEqualTo(BreakGlassAlert.OUTCOME_REFUSED);
    assertThat(alert.reason()).isEqualTo(reason);
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verify(rbacAuditPort, never()).recordBreakGlassGranted(any());
  }

  @Test
  void should_refuseWithExit3AndAuditAndAlert_when_targetUserDoesNotExist() {
    when(userDirectoryPort.findDirectoryUser(targetUserId)).thenReturn(Optional.empty());

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(outcome).isEqualTo(BreakGlassOutcome.USER_NOT_FOUND);
    assertThat(outcome.exitCode()).isEqualTo(3);
    assertRefusedWithoutGrant("USER_NOT_FOUND", null);
  }

  @Test
  void should_refuseWithExit3AndAuditAndAlert_when_targetUserIsNotActive() {
    when(userDirectoryPort.findDirectoryUser(targetUserId))
        .thenReturn(Optional.of(new DirectoryUser(tenantId, false)));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(outcome).isEqualTo(BreakGlassOutcome.USER_NOT_ACTIVE);
    assertThat(outcome.exitCode()).isEqualTo(3);
    assertRefusedWithoutGrant("USER_NOT_ACTIVE", tenantId);
  }

  @Test
  void should_refuseWithExit4AndAuditAndAlert_when_tenantHasNoTenantAdminRole() {
    when(userDirectoryPort.findDirectoryUser(targetUserId))
        .thenReturn(Optional.of(new DirectoryUser(tenantId, true)));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, RbacRoleNames.TENANT_ADMIN))
        .thenReturn(Optional.empty());

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(outcome).isEqualTo(BreakGlassOutcome.NO_SYSTEM_ADMIN_ROLE);
    assertThat(outcome.exitCode()).isEqualTo(4);
    assertRefusedWithoutGrant("NO_SYSTEM_ADMIN_ROLE", tenantId);
    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
  }

  @Test
  void should_refuseWithExit4_when_tenantAdminRoleIsNotASystemRole() {
    when(userDirectoryPort.findDirectoryUser(targetUserId))
        .thenReturn(Optional.of(new DirectoryUser(tenantId, true)));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, RbacRoleNames.TENANT_ADMIN))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.findRole(adminRoleId))
        .thenReturn(
            Optional.of(new Role(adminRoleId, tenantId, RbacRoleNames.TENANT_ADMIN, null, false)));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(outcome).isEqualTo(BreakGlassOutcome.NO_SYSTEM_ADMIN_ROLE);
    assertRefusedWithoutGrant("NO_SYSTEM_ADMIN_ROLE", tenantId);
  }

  @Test
  void should_refuseWithExit4_when_roleResolvedByNameBelongsToAnotherTenant() {
    UUID otherTenant = UUID.randomUUID();
    when(userDirectoryPort.findDirectoryUser(targetUserId))
        .thenReturn(Optional.of(new DirectoryUser(tenantId, true)));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, RbacRoleNames.TENANT_ADMIN))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.findRole(adminRoleId))
        .thenReturn(
            Optional.of(
                new Role(adminRoleId, otherTenant, RbacRoleNames.TENANT_ADMIN, null, true)));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(outcome).isEqualTo(BreakGlassOutcome.NO_SYSTEM_ADMIN_ROLE);
  }

  @Test
  void should_refuseWithExit5AndAuditAndAlert_when_tenantAlreadyHasAnAdministrator() {
    givenActiveTargetWithSystemAdminRole();
    givenHolders(new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), adminRoleId));

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(outcome).isEqualTo(BreakGlassOutcome.TENANT_HAS_ADMIN);
    assertThat(outcome.exitCode()).isEqualTo(5);
    assertRefusedWithoutGrant("TENANT_HAS_ADMIN", tenantId);
  }

  @Test
  void should_refuseWithExit5_when_holderOfAllThreeDangerousPermissionsRoleExists() {
    UUID customAdminRole = UUID.randomUUID();
    givenActiveTargetWithSystemAdminRole();
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(
            List.of(
                new RolePermissionName(customAdminRole, "user:write"),
                new RolePermissionName(customAdminRole, "role:write"),
                new RolePermissionName(customAdminRole, "tenant:write")));
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), customAdminRole)));

    assertThat(service.grantFirstAdmin(targetUserId, CHANGE_REF))
        .isEqualTo(BreakGlassOutcome.TENANT_HAS_ADMIN);
  }

  @Test
  void should_grant_when_onlyHolderIsOfARoleThatCannotPassTheCallerGate() {
    // A holder of a role with ONE dangerous permission is in the lock set but is not an
    // administrator (ADR-0018 H-1 caller-qualifying population): it must not block recovery.
    UUID partialRole = UUID.randomUUID();
    givenActiveTargetWithSystemAdminRole();
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(List.of(new RolePermissionName(partialRole, "tenant:write")));
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), partialRole)));

    assertThat(service.grantFirstAdmin(targetUserId, CHANGE_REF))
        .isEqualTo(BreakGlassOutcome.GRANTED);
  }

  @Test
  void should_grantWithAssignedByTarget_when_tenantHasZeroAdministrators() {
    givenActiveTargetWithSystemAdminRole();
    givenHolders();

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(outcome).isEqualTo(BreakGlassOutcome.GRANTED);
    assertThat(outcome.exitCode()).isZero();
    verify(userRoleAssignmentPort).assign(targetUserId, adminRoleId, tenantId, targetUserId);
    verify(rbacAuditPort, never()).recordBreakGlassRefused(any());
  }

  @Test
  void should_writeSuccessAuditWithChangeRefAndNoReason_when_granted() {
    givenActiveTargetWithSystemAdminRole();
    givenHolders();

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    ArgumentCaptor<BreakGlassAuditEvent> captor =
        ArgumentCaptor.forClass(BreakGlassAuditEvent.class);
    verify(rbacAuditPort).recordBreakGlassGranted(captor.capture());
    assertThat(captor.getValue())
        .isEqualTo(new BreakGlassAuditEvent(tenantId, targetUserId, CHANGE_REF, null));
  }

  @Test
  void should_lockSetOverAscendingAdminDefiningIdsPlusTenantAdmin_when_granting() {
    UUID customAdminRole = UUID.randomUUID();
    givenActiveTargetWithSystemAdminRole();
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(List.of(new RolePermissionName(customAdminRole, "user:write")));
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(List.of());

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<UUID>> captor = ArgumentCaptor.forClass(List.class);
    verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), captor.capture());
    List<UUID> lockSet = captor.getValue();
    assertThat(lockSet).containsExactlyInAnyOrder(customAdminRole, adminRoleId);
    List<UUID> ascending = new ArrayList<>(lockSet);
    ascending.sort(
        (a, b) -> {
          int cmp = Long.compareUnsigned(a.getMostSignificantBits(), b.getMostSignificantBits());
          return cmp != 0
              ? cmp
              : Long.compareUnsigned(a.getLeastSignificantBits(), b.getLeastSignificantBits());
        });
    assertThat(lockSet).isEqualTo(ascending);
  }

  @Test
  void should_primeThenLockThenInsertThenAudit_when_granting() {
    givenActiveTargetWithSystemAdminRole();
    givenHolders();

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    InOrder order = inOrder(userRoleAssignmentPort, rbacAuditPort, alertPort);
    order.verify(userRoleAssignmentPort).findPermissionNamesForTenantRoles(tenantId);
    order.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), any());
    order.verify(userRoleAssignmentPort).assign(targetUserId, adminRoleId, tenantId, targetUserId);
    order.verify(rbacAuditPort).recordBreakGlassGranted(any());
    order.verify(alertPort).raise(any());
  }

  @Test
  void should_notInsertBeforeLock_when_refusingForExistingAdministrator() {
    givenActiveTargetWithSystemAdminRole();
    givenHolders(new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), adminRoleId));

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    InOrder order = inOrder(userRoleAssignmentPort, rbacAuditPort);
    order.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), any());
    order.verify(rbacAuditPort).recordBreakGlassRefused(any());
  }

  @Test
  void should_alertGrantedOnlyAfterCommit_when_runInsideATransaction() {
    givenActiveTargetWithSystemAdminRole();
    givenHolders();
    TransactionSynchronizationManager.initSynchronization();

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    verifyNoInteractions(alertPort);
    TransactionSynchronizationManager.getSynchronizations()
        .forEach(TransactionSynchronization::afterCommit);
    BreakGlassAlert alert = capturedAlert();
    assertThat(alert.outcome()).isEqualTo(BreakGlassAlert.OUTCOME_GRANTED);
    assertThat(alert.reason()).isNull();
    assertThat(alert.tenantId()).isEqualTo(tenantId);
    assertThat(alert.targetUserId()).isEqualTo(targetUserId);
    assertThat(alert.changeRef()).isEqualTo(CHANGE_REF);
  }

  @Test
  void should_neverAlertGranted_when_theAtomicAuditWriteFails() {
    givenActiveTargetWithSystemAdminRole();
    givenHolders();
    doThrow(new IllegalStateException("audit down"))
        .when(rbacAuditPort)
        .recordBreakGlassGranted(any());
    TransactionSynchronizationManager.initSynchronization();

    assertThatThrownBy(
            () -> service.grantFirstAdmin(targetUserId, CHANGE_REF))
        .isInstanceOf(IllegalStateException.class);

    // The transaction rolls back, afterCommit never fires: no GRANTED page for a grant that did
    // not happen.
    assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
    verifyNoInteractions(alertPort);
  }

  @Test
  void should_notCallAssignOnRoleAssignmentService_by_construction() {
    // EC2: the service has no RoleAssignmentService dependency at all.
    assertThat(BootstrapAdminService.class.getDeclaredConstructors()[0].getParameterTypes())
        .doesNotContain(RoleAssignmentService.class);
  }

  // ── T-008: replay refusal (RC-37.2, RC-47) and invalid-argument refusal (RC-54(a)) ──

  @Test
  void should_refuseWithExit6BeforeAnyUserLookup_when_changeRefWasUsedOnASuccessfulGrant() {
    when(grantLookupPort.existsSuccessfulGrantWithChangeRef(CHANGE_REF)).thenReturn(true);

    BreakGlassOutcome outcome = service.grantFirstAdmin(targetUserId, CHANGE_REF);

    assertThat(outcome).isEqualTo(BreakGlassOutcome.CHANGE_REF_REUSED);
    assertThat(outcome.exitCode()).isEqualTo(6);
    verifyNoInteractions(userDirectoryPort);
    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    BreakGlassAuditEvent row = capturedRefusal();
    assertThat(row)
        .isEqualTo(new BreakGlassAuditEvent(null, targetUserId, CHANGE_REF, "CHANGE_REF_REUSED"));
    BreakGlassAlert alert = capturedAlert();
    assertThat(alert.outcome()).isEqualTo(BreakGlassAlert.OUTCOME_REFUSED);
    assertThat(alert.reason()).isEqualTo("CHANGE_REF_REUSED");
    assertThat(alert.changeRef()).isEqualTo(CHANGE_REF);
  }

  @Test
  void should_lookUpTheExactChangeRefBeforeResolvingTheUser_when_granting() {
    givenActiveTargetWithSystemAdminRole();
    givenHolders();

    service.grantFirstAdmin(targetUserId, CHANGE_REF);

    InOrder order = inOrder(grantLookupPort, userDirectoryPort);
    order.verify(grantLookupPort).existsSuccessfulGrantWithChangeRef(CHANGE_REF);
    order.verify(userDirectoryPort).findDirectoryUser(targetUserId);
  }

  @Test
  void should_writeInvalidArgumentRowWithNothingElse_when_refusingAnInvalidArgument() {
    BreakGlassOutcome outcome = service.refuseInvalidArgument();

    assertThat(outcome).isEqualTo(BreakGlassOutcome.INVALID_ARGUMENT);
    assertThat(outcome.exitCode()).isEqualTo(2);
    assertThat(capturedRefusal())
        .isEqualTo(new BreakGlassAuditEvent(null, null, null, "INVALID_ARGUMENT"));
    assertThat(capturedAlert())
        .isEqualTo(
            new BreakGlassAlert(
                null, null, BreakGlassAlert.OUTCOME_REFUSED, "INVALID_ARGUMENT", null));
    verifyNoInteractions(userRoleAssignmentPort, userDirectoryPort, grantLookupPort);
  }
}
