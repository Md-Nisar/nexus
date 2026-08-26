package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentRef;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.LastAdminRoleException;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Unit tests for {@link RoleAssignmentService} — the only place AC4 (tenant isolation), AC5
 * (last-admin lockout), and AC8 (self-escalation guard) are enforced (03-design.md §4.2).
 *
 * <p>Test strategy: every branch of {@code assign}/{@code revoke}/{@code listActive} — happy
 * path, every 404/403/409 error branch, the {@code equalsIgnoreCase} case-variant matching for
 * {@code TENANT_ADMIN} (T-E7/R-9), the actor-agnostic AC5 lockout, the T-E8 tenant-check-not-
 * bypassed-by-the-repository assertion, and the inline-vs-deferred side-effect fallback
 * (03-design.md §3.1 step 7).
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class RoleAssignmentServiceTest {

  @Mock private UserRoleAssignmentPort userRoleAssignmentPort;
  @Mock private UserDirectoryPort userDirectoryPort;
  @Mock private RbacAuditPort rbacAuditPort;
  @Mock private PermissionCachePort permissionCachePort;

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
    service =
        new RoleAssignmentService(
            userRoleAssignmentPort, userDirectoryPort, rbacAuditPort, permissionCachePort);

    actorId = UUID.randomUUID();
    tenantId = UUID.randomUUID();
    otherTenantId = UUID.randomUUID();
    targetUserId = UUID.randomUUID();
    roleId = UUID.randomUUID();
    actor = new RoleChangeActor(actorId, tenantId);
    ctx = RequestContext.UNKNOWN;
  }

  private Role memberRole() {
    return new Role(roleId, tenantId, "MEMBER", "desc", false);
  }

  private Role adminRole(String name) {
    return new Role(roleId, tenantId, name, "desc", false);
  }

  // ---------------------------------------------------------------------------------------
  // assign()
  // ---------------------------------------------------------------------------------------

  @Test
  void should_insertReReadAndFireSideEffects_when_happyPath() {
    Role role = memberRole();
    Instant assignedAt = Instant.now();
    UUID userRoleId = UUID.randomUUID();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "MEMBER", assignedAt, actorId);

    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(userRoleId);
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    ActiveRoleAssignment result = service.assign(actor, targetUserId, roleId, ctx);

    assertThat(result).isEqualTo(view);
    verify(userRoleAssignmentPort, never())
        .hasActiveAdminAssignment(any(), any(), any()); // not TENANT_ADMIN, guard skipped

    InOrder inOrder = Mockito.inOrder(permissionCachePort, rbacAuditPort);
    inOrder.verify(permissionCachePort).evict(tenantId, targetUserId);
    inOrder
        .verify(rbacAuditPort)
        .recordRoleAssigned(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "MEMBER", actorId, ctx));
  }

  // Load-bearing (US-014 Decision 2): this and the other 404/409 negative assertions in this
  // file are now proof of the 403-only ROLE_ASSIGNMENT_DENIED scope, not incidental. Do not
  // weaken -- defense-in-depth only, the catch type in RoleAssignmentService is the structural
  // control.
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
  void should_throwCrossTenantTarget_when_assignTargetTenantMismatch() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(otherTenantId));

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.CROSS_TENANT_TARGET));

    verify(userRoleAssignmentPort, never()).findRole(any());
    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, null, actorId, ctx),
            DenialReason.CROSS_TENANT_TARGET);
    verifyNoInteractions(permissionCachePort);
  }

  /**
   * US-014 Phase 8 test-coverage audit: {@code recordDenial}'s own {@code catch (RuntimeException)}
   * (defense-in-depth atop {@link RbacAuditPort}'s "must never throw" contract) is untested by any
   * existing test -- every other test mocks {@code rbacAuditPort} to succeed silently. Proves the
   * real denial ({@code CROSS_TENANT_TARGET}) still wins and is not masked or replaced by the audit
   * port's contract violation.
   */
  @Test
  void should_stillThrowOriginalDenialException_when_rbacAuditPortViolatesNeverThrowContract() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(otherTenantId));
    doThrow(new RuntimeException("audit port broke its never-throw contract"))
        .when(rbacAuditPort)
        .recordRoleAssignmentDenied(any(), any());

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.CROSS_TENANT_TARGET));
  }

  /**
   * Companion to the test above: the defensive catch must also make the contract violation
   * operationally visible via an ERROR log carrying the {@code RBAC_AUDIT_DENIAL_CALL_SITE_FAILED}
   * marker, mirroring {@code RbacAuthEventAdapterTest}'s {@code RBAC_AUDIT_WRITE_LOST} pattern.
   */
  @Test
  void should_logErrorWithCallSiteFailedMarker_when_rbacAuditPortViolatesNeverThrowContract() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(otherTenantId));
    doThrow(new RuntimeException("audit port broke its never-throw contract"))
        .when(rbacAuditPort)
        .recordRoleAssignmentDenied(any(), any());

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);

      var errorEvents = appender.list.stream().filter(e -> e.getLevel() == Level.ERROR).toList();
      assertThat(errorEvents).hasSize(1);
      Map<String, Object> keyValues = keyValueMap(errorEvents.get(0));
      assertThat(keyValues)
          .containsEntry("event", "RBAC_AUDIT_DENIAL_CALL_SITE_FAILED")
          .containsEntry("tenantId", tenantId)
          .containsEntry("targetUserId", targetUserId);
    } finally {
      stopLogCapture(appender);
    }
  }

  // Load-bearing (US-014 Decision 2) -- see the comment on
  // should_throwResourceNotFound_when_targetUserNotFound above.
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
  void should_throwCrossTenantTarget_when_assignRoleTenantMismatch() {
    Role foreignRole = new Role(roleId, otherTenantId, "MEMBER", "desc", false);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(foreignRole));

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.CROSS_TENANT_TARGET));

    verify(userRoleAssignmentPort, never()).hasActiveAssignment(any(), any());
    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, null, actorId, ctx),
            DenialReason.CROSS_TENANT_TARGET);
    verifyNoInteractions(permissionCachePort);
  }

  @Test
  void should_throwNotTenantAdmin_when_grantingTenantAdminAndCallerNotActiveAdmin() {
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort, never()).hasActiveAssignment(any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "TENANT_ADMIN", actorId, ctx),
            DenialReason.NOT_TENANT_ADMIN);
    verifyNoInteractions(permissionCachePort);
  }

  /**
   * Proves the AC8 guard compares role names via {@code equalsIgnoreCase}, not {@code .equals()}
   * — {@code roles.name}'s collation makes {@code uq_roles_tenant_name} case-insensitive, so a
   * case-sensitive Java compare would silently disable this guard for a differently-cased row
   * (R-9). If the implementation used {@code .equals()}, this case-variant name would skip the
   * admin check entirely and the assignment would proceed instead of throwing.
   */
  @Test
  void should_throwNotTenantAdmin_when_roleNameIsDifferentCaseVariantOfTenantAdmin() {
    Role role = adminRole("tenant_admin");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort).hasActiveAdminAssignment(actorId, roleId, tenantId);
    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "tenant_admin", actorId, ctx),
            DenialReason.NOT_TENANT_ADMIN);
    verifyNoInteractions(permissionCachePort);
  }

  /**
   * AC8 positive path: caller DOES hold an active admin assignment. Verifies {@code
   * hasActiveAdminAssignment} is invoked with the resolved role's own id (never a hardcoded or
   * actor-derived value — T-E7) and that the flow proceeds to the duplicate-check/insert path.
   */
  @Test
  void should_proceedToInsert_when_grantingTenantAdminAndCallerIsActiveAdmin() {
    Role role = adminRole("TENANT_ADMIN");
    Instant assignedAt = Instant.now();
    UUID userRoleId = UUID.randomUUID();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "TENANT_ADMIN", assignedAt, actorId);

    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(userRoleId);
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    ActiveRoleAssignment result = service.assign(actor, targetUserId, roleId, ctx);

    assertThat(result).isEqualTo(view);
    verify(userRoleAssignmentPort).hasActiveAdminAssignment(actorId, role.getId(), tenantId);
    verify(userRoleAssignmentPort).assign(targetUserId, roleId, tenantId, actorId);
    verify(permissionCachePort).evict(tenantId, targetUserId);
    verify(rbacAuditPort)
        .recordRoleAssigned(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "TENANT_ADMIN", actorId, ctx));
  }

  // Load-bearing (US-014 Decision 2) -- see the comment on
  // should_throwResourceNotFound_when_targetUserNotFound above.
  @Test
  void should_throwDuplicateRoleAssignment_when_activeAssignmentAlreadyExists() {
    Role role = memberRole();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(true);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(DuplicateRoleAssignmentException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_004");

    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  /**
   * Inline-vs-afterCommit fallback (03-design.md §3.1 step 7): a plain Mockito unit test has no
   * active Spring transaction synchronization, so {@code registerPostCommitSideEffects} must run
   * the cache-evict/audit side effects inline, synchronously, before {@code assign(...)} returns.
   * This is the only kind of test that can observe that fallback directly.
   */
  @Test
  void should_fireSideEffectsInlineSynchronously_when_noActiveTransactionSynchronization() {
    assertThat(TransactionSynchronizationManager.isSynchronizationActive())
        .as("sanity check: a plain unit test has no active transaction synchronization")
        .isFalse();

    Role role = memberRole();
    Instant assignedAt = Instant.now();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "MEMBER", assignedAt, actorId);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    service.assign(actor, targetUserId, roleId, ctx);

    // By the time assign() has returned, the side effects must already have fired -- there is
    // no pending afterCommit callback to wait for.
    verify(permissionCachePort, times(1)).evict(tenantId, targetUserId);
    verify(rbacAuditPort, times(1)).recordRoleAssigned(any());
  }

  /**
   * Complements the test above: when a transaction synchronization IS active (as it would be
   * under a real {@code @Transactional} call), the side effects must be deferred to {@code
   * afterCommit} rather than fired inline.
   */
  @Test
  void should_deferSideEffectsUntilAfterCommit_when_transactionSynchronizationActive() {
    Role role = memberRole();
    Instant assignedAt = Instant.now();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "MEMBER", assignedAt, actorId);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    TransactionSynchronizationManager.initSynchronization();
    try {
      service.assign(actor, targetUserId, roleId, ctx);

      verifyNoInteractions(permissionCachePort, rbacAuditPort);

      for (TransactionSynchronization synchronization :
          TransactionSynchronizationManager.getSynchronizations()) {
        synchronization.afterCommit();
      }

      verify(permissionCachePort).evict(tenantId, targetUserId);
      verify(rbacAuditPort).recordRoleAssigned(any());
    } finally {
      TransactionSynchronizationManager.clearSynchronization();
    }
  }

  // ---------------------------------------------------------------------------------------
  // revoke()
  // ---------------------------------------------------------------------------------------

  @Test
  void should_revokeAndFireSideEffectsWithRecordRoleRevoked_when_happyPathNonAdmin() {
    Role role = memberRole();
    UUID refId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentIds(any(), any());
    InOrder inOrder = Mockito.inOrder(permissionCachePort, rbacAuditPort);
    inOrder.verify(permissionCachePort).evict(tenantId, targetUserId);
    inOrder
        .verify(rbacAuditPort)
        .recordRoleRevoked(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "MEMBER", actorId, ctx));
  }

  // Load-bearing (US-014 Decision 2) -- see the comment on
  // should_throwResourceNotFound_when_targetUserNotFound above.
  @Test
  void should_throwResourceNotFound_when_revokeTargetUserNotFound() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "USER_NOT_FOUND");

    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  @Test
  void should_throwCrossTenantTarget_when_revokeTargetTenantMismatch() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(otherTenantId));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.CROSS_TENANT_TARGET));

    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, null, actorId, ctx),
            DenialReason.CROSS_TENANT_TARGET);
    verifyNoInteractions(permissionCachePort);
  }

  // Load-bearing (US-014 Decision 2) -- see the comment on
  // should_throwResourceNotFound_when_targetUserNotFound above.
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
  void should_throwCrossTenantTarget_when_revokeRoleTenantMismatch() {
    Role foreignRole = new Role(roleId, otherTenantId, "MEMBER", "desc", false);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(foreignRole));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.CROSS_TENANT_TARGET));

    verify(userRoleAssignmentPort, never()).findActiveAssignmentRef(any(), any(), any());
    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, null, actorId, ctx),
            DenialReason.CROSS_TENANT_TARGET);
    verifyNoInteractions(permissionCachePort);
  }

  /**
   * The real ordering in {@link RoleAssignmentService#revoke} resolves the M3 assignment-ref
   * FIRST, ahead of the admin-lockout check — this covers "never assigned"/"already revoked"
   * identically for admin and non-admin roles. So the lockout-guard port method must never be
   * called for a non-admin role...
   */
  // Load-bearing (US-014 Decision 2) -- see the comment on
  // should_throwResourceNotFound_when_targetUserNotFound above.
  @Test
  void should_neverCallLockActiveAssignmentIds_when_nonAdminRoleAssignmentNotFound() {
    Role role = memberRole();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_ASSIGNMENT_NOT_FOUND");

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentIds(any(), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  /**
   * ...and, per the real (read, not assumed) ordering in the source, this is ALSO true for an
   * admin role: {@code findActiveAssignmentRef} (M3) is resolved before {@code
   * lockActiveAssignmentIds} (M1) is ever reached, so a not-found assignment short-circuits
   * before the lockout guard runs, even when the role being revoked is {@code TENANT_ADMIN}.
   */
  // Load-bearing (US-014 Decision 2) -- see the comment on
  // should_throwResourceNotFound_when_targetUserNotFound above.
  @Test
  void should_neverCallLockActiveAssignmentIds_when_adminRoleAssignmentNotFound() {
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_ASSIGNMENT_NOT_FOUND");

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentIds(any(), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  /** AC5, actor-agnostic variant 1: the actor is revoking their OWN last-admin assignment. */
  // Load-bearing (US-014 Decision 2) -- see the comment on
  // should_throwResourceNotFound_when_targetUserNotFound above.
  @Test
  void should_throwLastAdminRoleException_when_lockedSetSizeOneContainsTargetRef_selfRevoke() {
    UUID refId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    // Actor revoking their own assignment: target == actor.
    when(userDirectoryPort.findTenantId(actorId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(actorId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId));

    assertThatThrownBy(() -> service.revoke(actor, actorId, roleId, ctx))
        .isInstanceOf(LastAdminRoleException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_002");

    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  /**
   * AC5, actor-agnostic variant 2: a DIFFERENT admin revokes someone else's last-admin
   * assignment. The guard must fire identically -- it is not conditioned on self-revocation.
   */
  // Load-bearing (US-014 Decision 2) -- see the comment on
  // should_throwResourceNotFound_when_targetUserNotFound above.
  @Test
  void should_throwLastAdminRoleException_when_lockedSetSizeOneContainsTargetRef_differentAdminRevoking() {
    UUID refId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(LastAdminRoleException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_002");

    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  @Test
  void should_revokeSuccessfully_when_lockedSetSizeTwoOrMore() {
    UUID refId = UUID.randomUUID();
    UUID otherAdminRefId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId, otherAdminRefId));
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort).revoke(eq(refId), any());
    verify(permissionCachePort).evict(tenantId, targetUserId);
    verify(rbacAuditPort)
        .recordRoleRevoked(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "TENANT_ADMIN", actorId, ctx));
  }

  /**
   * Different-case {@code TENANT_ADMIN} still enters the lockout-guard code path on revoke
   * (mirrors the assign-side {@code equalsIgnoreCase} proof) -- {@code lockActiveAssignmentIds}
   * must be invoked even though the persisted role name is not the exact-case constant.
   */
  @Test
  void should_invokeLockoutGuard_when_revokeRoleNameIsDifferentCaseVariantOfTenantAdmin() {
    UUID refId = UUID.randomUUID();
    UUID otherAdminRefId = UUID.randomUUID();
    Role role = adminRole("Tenant_Admin");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId, otherAdminRefId));
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort).lockActiveAssignmentIds(tenantId, roleId);
    verify(userRoleAssignmentPort).revoke(eq(refId), any());
  }

  // Load-bearing (US-014 Decision 2) -- see the comment on
  // should_throwResourceNotFound_when_targetUserNotFound above.
  @Test
  void should_throwResourceNotFound_when_revokeLosesRaceAndZeroRowsAffected() {
    Role role = memberRole();
    UUID refId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(0);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_ASSIGNMENT_NOT_FOUND");

    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  // ---------------------------------------------------------------------------------------
  // listActive()
  // ---------------------------------------------------------------------------------------

  @Test
  void should_redactAssignedByOnEveryElement_when_callerNotActiveAdmin() {
    Instant now = Instant.now();
    UUID otherRoleId = UUID.randomUUID();
    UUID grantor1 = UUID.randomUUID();
    UUID grantor2 = UUID.randomUUID();
    List<ActiveRoleAssignment> stored =
        List.of(
            new ActiveRoleAssignment(targetUserId, roleId, "MEMBER", now, grantor1),
            new ActiveRoleAssignment(targetUserId, otherRoleId, "BILLING_ADMIN", now, grantor2));

    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findActiveAssignmentViews(targetUserId, tenantId))
        .thenReturn(stored);
    when(userRoleAssignmentPort.findActiveAssignmentViews(actorId, tenantId))
        .thenReturn(List.of()); // caller holds no active TENANT_ADMIN

    List<ActiveRoleAssignment> result = service.listActive(actor, targetUserId);

    assertThat(result)
        .containsExactly(
            new ActiveRoleAssignment(targetUserId, roleId, "MEMBER", now, null),
            new ActiveRoleAssignment(targetUserId, otherRoleId, "BILLING_ADMIN", now, null));
  }

  @Test
  void should_preserveAssignedBy_when_callerIsActiveAdmin() {
    Instant now = Instant.now();
    UUID otherRoleId = UUID.randomUUID();
    UUID grantor = UUID.randomUUID();
    List<ActiveRoleAssignment> stored =
        List.of(new ActiveRoleAssignment(targetUserId, roleId, "MEMBER", now, grantor));

    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findActiveAssignmentViews(targetUserId, tenantId))
        .thenReturn(stored);
    when(userRoleAssignmentPort.findActiveAssignmentViews(actorId, tenantId))
        .thenReturn(
            List.of(
                new ActiveRoleAssignment(
                    actorId, otherRoleId, "TENANT_ADMIN", now, UUID.randomUUID())));

    List<ActiveRoleAssignment> result = service.listActive(actor, targetUserId);

    assertThat(result).containsExactlyElementsOf(stored);
  }

  @Test
  void should_throwResourceNotFound_when_listActiveTargetUserNotFound() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.listActive(actor, targetUserId))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "USER_NOT_FOUND");

    verify(userRoleAssignmentPort, never()).findActiveAssignmentViews(any(), any());
  }

  /**
   * T-E8 fix verification: the tenant check must happen BEFORE, and must not be replaced by,
   * M4's own tenant predicate -- without this explicit check a cross-tenant probe would silently
   * return {@code 200 {"data":[]}} instead of a 403. Asserts {@code findActiveAssignmentViews} is
   * never invoked once the tenant mismatch is detected.
   */
  @Test
  void should_throwCrossTenantTarget_andNeverCallFindActiveAssignmentViews_when_listActiveTargetTenantMismatch() {
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(otherTenantId));

    assertThatThrownBy(() -> service.listActive(actor, targetUserId))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.CROSS_TENANT_TARGET));

    verify(userRoleAssignmentPort, never()).findActiveAssignmentViews(any(), any());
    // Load-bearing (US-014 T-E14): listActive's 403 is deliberately excluded from AC4 — this
    // is the binding, build-blocking control on that exclusion, not the RequestContext-shaped
    // barrier alone. If this assertion is ever removed, a read-path denial could mislabel a GET
    // and widen the emitting population from TENANT_ADMIN to every user:read holder.
    verifyNoInteractions(rbacAuditPort);
  }

  // ---------------------------------------------------------------------------------------
  // Log-capture helpers (mirrors RbacAuthEventAdapterTest's pattern)
  // ---------------------------------------------------------------------------------------

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
