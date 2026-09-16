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
import com.example.nexus.rbac.application.port.out.RoleChangeThrottlePort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentRef;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.LastAdminRoleException;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
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

  // T-010 (D14): the two throttle @Value fields, used only as WARN fields at the transition
  // (A-4) -- fixed test values, not stubbed, since no test asserts a specific bound being
  // enforced by these numbers themselves (that is RateLimitRoleChangeThrottleAdapterTest's job).
  private static final int MAX_DENIALS = 5;
  private static final int WINDOW_SECONDS = 60;

  @Mock private UserRoleAssignmentPort userRoleAssignmentPort;
  @Mock private UserDirectoryPort userDirectoryPort;
  @Mock private RbacAuditPort rbacAuditPort;
  @Mock private PermissionCachePort permissionCachePort;
  @Mock private RoleChangeThrottlePort throttlePort;

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
            meterRegistry, throttlePort, MAX_DENIALS, WINDOW_SECONDS);

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

  private Role customRole(String name) {
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
            DenialReason.CROSS_TENANT_TARGET, "assign");
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
        .recordRoleAssignmentDenied(any(), any(), any());

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
        .recordRoleAssignmentDenied(any(), any(), any());

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
            DenialReason.CROSS_TENANT_TARGET, "assign");
    verifyNoInteractions(permissionCachePort);
  }

  @Test
  void should_throwNotTenantAdmin_when_grantingTenantAdminAndCallerNotActiveAdmin() {
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    // M8: on the name-match path, the tenant's TENANT_ADMIN role IS the target role (§5.4);
    // without this stub M8 returns Optional.empty() and the test would pass for the wrong
    // reason (fail-closed on empty M8, not the admin check).
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
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
            DenialReason.NOT_TENANT_ADMIN, "assign");
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
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
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
            DenialReason.NOT_TENANT_ADMIN, "assign");
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
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
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

  // ---------------------------------------------------------------------------------------
  // T-008: the unified privilege gate on assign() -- dangerous-permission path (D4, D5, D15,
  // D17, FR-1). The name-match path's regression contract is covered by the three tests above;
  // this block covers the NEW carriesDangerousPermission() half and the shared throw site.
  // ---------------------------------------------------------------------------------------

  @Test
  void should_throwNotTenantAdmin_when_roleCarriesOneDangerousPermissionAndCallerNotActiveAdmin() {
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID(); // MC-3(a): deliberately != roleId
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    // MC-2: the correct (locking, assignment-based) helper is used, never the redaction helper.
    verify(userRoleAssignmentPort).hasActiveAdminAssignment(actorId, adminRoleId, tenantId);
    verify(userRoleAssignmentPort, never()).findActiveAssignmentViews(any(), any());
    // MC-3(a): the caller's admin status is checked against M8's role, never the target role.
    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), eq(roleId), any());
    // MC-3(b): the caller's own id is checked, never the target's.
    verify(userRoleAssignmentPort, never())
        .hasActiveAdminAssignment(eq(targetUserId), any(), any());
    verify(userRoleAssignmentPort, never()).hasActiveAssignment(any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "BILLING_ADMIN", actorId, ctx),
            DenialReason.NOT_TENANT_ADMIN, "assign");
    verifyNoInteractions(permissionCachePort);
  }

  @Test
  void should_throwNotTenantAdmin_when_roleCarriesAllThreeDangerousPermissionsAndCallerNotActiveAdmin() {
    Role role = customRole("SUPER_CUSTOM");
    UUID adminRoleId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("role:write", "user:write", "tenant:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    // Edge Case 3, dangerous-only variant: even with all three dangerous permissions present,
    // exactly one denial/audit row/metric increment -- structural (a single `||`), not ordering.
    verify(rbacAuditPort, times(1))
        .recordRoleAssignmentDenied(any(), eq(DenialReason.NOT_TENANT_ADMIN), eq("assign"));
    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), eq(roleId), any());
    verify(userRoleAssignmentPort, never())
        .hasActiveAdminAssignment(eq(targetUserId), any(), any());
  }

  /**
   * Proves {@code carriesDangerousPermission} delegates to {@code RbacDangerousPermissions
   * .contains}, which is case-insensitive (mirrors the role-name case-variant proof above).
   */
  @Test
  void should_throwNotTenantAdmin_when_roleCarriesCaseVariantDangerousPermissionName() {
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("User:Write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort).hasActiveAdminAssignment(actorId, adminRoleId, tenantId);
    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), eq(roleId), any());
    verify(userRoleAssignmentPort, never())
        .hasActiveAdminAssignment(eq(targetUserId), any(), any());
  }

  @Test
  void should_proceedToInsert_when_roleCarriesOnlyNonDangerousPermission() {
    Role role = customRole("BILLING_VIEWER");
    Instant assignedAt = Instant.now();
    UUID userRoleId = UUID.randomUUID();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "BILLING_VIEWER", assignedAt, actorId);

    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId)).thenReturn(List.of("user:read"));
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(userRoleId);
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    ActiveRoleAssignment result = service.assign(actor, targetUserId, roleId, ctx);

    assertThat(result).isEqualTo(view);
    verify(userRoleAssignmentPort, never()).findRoleIdByName(any(), any());
    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), any(), any());
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
  }

  /** Edge Case 1: an empty permission set means NOT privileged -- the gate must not fire. */
  @Test
  void should_proceedToInsert_when_roleCarriesNoPermissions() {
    Role role = customRole("EMPTY_ROLE");
    Instant assignedAt = Instant.now();
    UUID userRoleId = UUID.randomUUID();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "EMPTY_ROLE", assignedAt, actorId);

    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId)).thenReturn(List.of());
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(userRoleId);
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    ActiveRoleAssignment result = service.assign(actor, targetUserId, roleId, ctx);

    assertThat(result).isEqualTo(view);
    verify(userRoleAssignmentPort, never()).findRoleIdByName(any(), any());
    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), any(), any());
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
  }

  @Test
  void should_proceedToInsert_when_roleCarriesDangerousPermissionAndCallerIsActiveAdmin() {
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    Instant assignedAt = Instant.now();
    UUID userRoleId = UUID.randomUUID();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "BILLING_ADMIN", assignedAt, actorId);

    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(userRoleId);
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    ActiveRoleAssignment result = service.assign(actor, targetUserId, roleId, ctx);

    assertThat(result).isEqualTo(view);
    verify(userRoleAssignmentPort).hasActiveAdminAssignment(actorId, adminRoleId, tenantId);
    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), eq(roleId), any());
    verify(userRoleAssignmentPort, never())
        .hasActiveAdminAssignment(eq(targetUserId), any(), any());
    verify(userRoleAssignmentPort).assign(targetUserId, roleId, tenantId, actorId);
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
  }

  /** R-10/T-E18 precedent, extended: an empty M8 must fail closed WITHOUT ever calling M5. */
  @Test
  void should_denyWithoutCallingHasActiveAdminAssignment_when_tenantHasNoSeededTenantAdminRole() {
    Role role = customRole("BILLING_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), any(), any());
    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "BILLING_ADMIN", actorId, ctx),
            DenialReason.NOT_TENANT_ADMIN, "assign");
  }

  @Test
  void should_propagateAndWriteNothing_when_findPermissionNamesForRoleThrows() {
    Role role = customRole("BILLING_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenThrow(new RuntimeException("db down"));

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RuntimeException.class)
        .hasMessage("db down");

    verify(userRoleAssignmentPort, never()).findRoleIdByName(any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
  }

  @Test
  void should_propagateAndWriteNothing_when_findRoleIdByNameThrows() {
    Role role = customRole("BILLING_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenThrow(new RuntimeException("db down"));

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RuntimeException.class)
        .hasMessage("db down");

    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
  }

  @Test
  void should_propagateAndWriteNothing_when_hasActiveAdminAssignmentThrows() {
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenThrow(new RuntimeException("db down"));

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RuntimeException.class)
        .hasMessage("db down");

    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
  }

  /**
   * Edge Case 3, name-match variant: the seeded TENANT_ADMIN role satisfies BOTH halves of the
   * unified condition (it is literally named TENANT_ADMIN and carries all 7 permissions). The
   * name-first short-circuit means {@code carriesDangerousPermission} (M7) is never evaluated,
   * so exactly one denial/audit row/metric increment is structural, not an ordering rule.
   */
  @Test
  void should_recordExactlyOneDenialAuditAndMetric_when_roleIsNamedTenantAdminAndCallerNotActiveAdmin() {
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verify(userRoleAssignmentPort, never()).findPermissionNamesForRole(any());
    verify(rbacAuditPort, times(1)).recordRoleAssignmentDenied(any(), any(), any());
    Counter counter = meterRegistry.find("nexus.rbac.privileged_role_change_blocked").counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
  }

  /** Gate ordering vs. the 409 branch (§6.2 check 5 precedes check 7), dangerous-permission path. */
  @Test
  void should_notCheckDuplicateAssignment_when_dangerousRoleAndCallerNotActiveAdmin() {
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verify(userRoleAssignmentPort, never()).hasActiveAssignment(any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
  }

  @Test
  void should_logWarnWithOperationAndMatchedOnRoleName_when_grantingTenantAdminAndCallerNotActiveAdmin() {
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);

      var warnEvents =
          appender.list.stream()
              .filter(e -> e.getLevel() == Level.WARN)
              .filter(
                  e -> "RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED".equals(keyValueMap(e).get("event")))
              .toList();
      assertThat(warnEvents).hasSize(1);
      Map<String, Object> keyValues = keyValueMap(warnEvents.get(0));
      assertThat(keyValues)
          .containsEntry("operation", "assign")
          .containsEntry("matchedOn", "ROLE_NAME")
          .containsEntry("tenantId", tenantId)
          .containsEntry("targetUserId", targetUserId)
          .containsEntry("actorUserId", actorId)
          .containsEntry("roleId", roleId)
          .containsEntry("roleName", "TENANT_ADMIN");
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_logWarnWithOperationAndMatchedOnDangerousPermission_when_dangerousRoleAndCallerNotActiveAdmin() {
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(false);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);

      var warnEvents =
          appender.list.stream()
              .filter(e -> e.getLevel() == Level.WARN)
              .filter(
                  e -> "RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED".equals(keyValueMap(e).get("event")))
              .toList();
      assertThat(warnEvents).hasSize(1);
      Map<String, Object> keyValues = keyValueMap(warnEvents.get(0));
      assertThat(keyValues)
          .containsEntry("operation", "assign")
          .containsEntry("matchedOn", "DANGEROUS_PERMISSION")
          .containsEntry("roleName", "BILLING_ADMIN");
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_incrementPrivilegedRoleChangeBlockedCounter_withMatchedOnRoleNameTag_when_grantingTenantAdminAndCallerNotActiveAdmin() {
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    Counter counter =
        meterRegistry
            .find("nexus.rbac.privileged_role_change_blocked")
            .tags("operation", "assign", "matchedOn", "ROLE_NAME")
            .counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
  }

  @Test
  void should_incrementPrivilegedRoleChangeBlockedCounter_withMatchedOnDangerousPermissionTag_when_dangerousRoleAndCallerNotActiveAdmin() {
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    Counter counter =
        meterRegistry
            .find("nexus.rbac.privileged_role_change_blocked")
            .tags("operation", "assign", "matchedOn", "DANGEROUS_PERMISSION")
            .counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
  }

  /** MC-3's deliberate FR-4 exception: self-assignment is the one case where the two axes collapse. */
  @Test
  void should_throwNotTenantAdmin_when_actorSelfAssignsDangerousRoleAndIsNotActiveAdmin() {
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(actorId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.assign(actor, actorId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    assertThat(meterRegistry.find("nexus.rbac.self_role_assignment").counter()).isNull();
  }

  @Test
  void should_tagPrivilegedTrueAndCallerIsAdminTrue_when_actorSelfAssignsDangerousRoleAndIsActiveAdmin() {
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    Instant assignedAt = Instant.now();
    UUID userRoleId = UUID.randomUUID();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(actorId, roleId, "BILLING_ADMIN", assignedAt, actorId);

    when(userDirectoryPort.findTenantId(actorId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(actorId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(actorId, roleId, tenantId, actorId)).thenReturn(userRoleId);
    when(userRoleAssignmentPort.findActiveAssignmentView(actorId, roleId, tenantId))
        .thenReturn(Optional.of(view));
    // M-2 (07-security-review.md): callerIsAdmin is now independently re-derived via
    // callerHoldsActiveTenantAdmin's findActiveAssignmentViews projection, not inferred from
    // `privileged` -- stub it to agree with the M5 locking read above so this success path
    // still tags callerIsAdmin="true".
    when(userRoleAssignmentPort.findActiveAssignmentViews(actorId, tenantId))
        .thenReturn(
            List.of(new ActiveRoleAssignment(actorId, adminRoleId, "TENANT_ADMIN", assignedAt, actorId)));

    ActiveRoleAssignment result = service.assign(actor, actorId, roleId, ctx);

    assertThat(result).isEqualTo(view);
    Counter counter =
        meterRegistry
            .find("nexus.rbac.self_role_assignment")
            .tags("tenantId", tenantId.toString(), "privileged", "true", "callerIsAdmin", "true")
            .counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
  }

  /**
   * M-2 (07-security-review.md, RC-11.2): proves {@code callerIsAdmin="false"} is now reachable
   * on the {@code privileged="true"} series -- the exact value the canary alert
   * ({@code nexus_rbac_gate_bypass_canary}) fires on. Simulates the two independent mechanisms
   * disagreeing: M5's locking read ({@code hasActiveAdminAssignment}) says the caller is an
   * active admin (so the gate passes and {@code assign()} still succeeds), but the M4 projection
   * ({@code callerHoldsActiveTenantAdmin}) shows no active {@code TENANT_ADMIN} assignment for
   * that same actor -- a T-E22-class disagreement, no longer definitionally unemittable.
   */
  @Test
  void should_tagCallerIsAdminFalse_when_hasActiveAdminAssignmentAndCallerHoldsActiveTenantAdminDisagree() {
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    Instant assignedAt = Instant.now();
    UUID userRoleId = UUID.randomUUID();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(actorId, roleId, "BILLING_ADMIN", assignedAt, actorId);

    when(userDirectoryPort.findTenantId(actorId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(actorId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(actorId, roleId, tenantId, actorId)).thenReturn(userRoleId);
    when(userRoleAssignmentPort.findActiveAssignmentView(actorId, roleId, tenantId))
        .thenReturn(Optional.of(view));
    when(userRoleAssignmentPort.findActiveAssignmentViews(actorId, tenantId)).thenReturn(List.of());

    ActiveRoleAssignment result = service.assign(actor, actorId, roleId, ctx);

    assertThat(result).isEqualTo(view);
    Counter counter =
        meterRegistry
            .find("nexus.rbac.self_role_assignment")
            .tags("tenantId", tenantId.toString(), "privileged", "true", "callerIsAdmin", "false")
            .counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
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
  // RC-7 (T-005): nexus.rbac.self_role_assignment — unconditional exploitation-side signal
  // ---------------------------------------------------------------------------------------

  /**
   * 03-design.md §9.2/§10.2 (RC-7): unconditional, no dangerous-permission lookup. Proves the
   * counter fires whenever {@code targetUserId == actor.userId()} AND that {@code assign()}'s
   * outcome is unchanged -- same successful result as the non-self happy path.
   */
  @Test
  void should_incrementSelfRoleAssignmentCounter_andStillSucceed_when_actorAssignsRoleToSelf() {
    Role role = memberRole();
    Instant assignedAt = Instant.now();
    UUID userRoleId = UUID.randomUUID();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(actorId, roleId, "MEMBER", assignedAt, actorId);

    when(userDirectoryPort.findTenantId(actorId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.hasActiveAssignment(actorId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(actorId, roleId, tenantId, actorId))
        .thenReturn(userRoleId);
    when(userRoleAssignmentPort.findActiveAssignmentView(actorId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    ActiveRoleAssignment result = service.assign(actor, actorId, roleId, ctx);

    assertThat(result).isEqualTo(view);
    Counter counter = meterRegistry.find("nexus.rbac.self_role_assignment").counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
    // D7/D15 (§9.2): a non-dangerous role never reaches the gate, so callerIsAdmin is "n_a",
    // never "false" -- that unreachability on the success path is the bypass canary's premise.
    assertThat(counter.getId().getTag("privileged")).isEqualTo("false");
    assertThat(counter.getId().getTag("callerIsAdmin")).isEqualTo("n_a");
  }

  /** Complements the test above: a non-self assignment must never increment the counter. */
  @Test
  void should_notIncrementSelfRoleAssignmentCounter_when_targetIsDifferentUser() {
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

    assertThat(meterRegistry.find("nexus.rbac.self_role_assignment").counter()).isNull();
  }

  /**
   * The counter must be accompanied by a WARN log (design §9.2), mirroring the file's existing
   * {@code RBAC_LAST_ADMIN_REVOCATION_BLOCKED} structured-WARN convention.
   */
  @Test
  void should_logWarnWithSelfRoleAssignmentMarker_when_actorAssignsRoleToSelf() {
    Role role = memberRole();
    Instant assignedAt = Instant.now();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(actorId, roleId, "MEMBER", assignedAt, actorId);

    when(userDirectoryPort.findTenantId(actorId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.hasActiveAssignment(actorId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(actorId, roleId, tenantId, actorId))
        .thenReturn(UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveAssignmentView(actorId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.assign(actor, actorId, roleId, ctx);

      var warnEvents = appender.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
      assertThat(warnEvents).hasSize(1);
      Map<String, Object> keyValues = keyValueMap(warnEvents.get(0));
      assertThat(keyValues)
          .containsEntry("event", "RBAC_SELF_ROLE_ASSIGNMENT")
          .containsEntry("tenantId", tenantId)
          .containsEntry("targetUserId", actorId)
          .containsEntry("roleId", roleId);
    } finally {
      stopLogCapture(appender);
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
            DenialReason.CROSS_TENANT_TARGET, "revoke");
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
            DenialReason.CROSS_TENANT_TARGET, "revoke");
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
    // T-009: the privilege gate now runs ahead of AC5 -- the caller must pass it to reach the
    // lockout guard at all (design §6.4).
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(true);

    assertThatThrownBy(() -> service.revoke(actor, actorId, roleId, ctx))
        .isInstanceOf(LastAdminRoleException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_002");

    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  /**
   * AC5, actor-agnostic variant 2: a DIFFERENT admin revokes someone else's last-admin
   * assignment. The guard must fire identically -- it is not conditioned on self-revocation.
   *
   * <p>T-009 / design §6.4: once the privilege gate is wired in, this exact state (the actor
   * holds an active admin assignment while the LOCKED set contains only the TARGET's ref, never
   * the actor's own) is proven unreachable in production -- M1's predicate is a superset of M5's,
   * so the actor's own row would necessarily also be in {@code lockedActiveAdminIds} whenever M5
   * returns true. Mockito can still construct the state artificially, and this test is
   * deliberately kept: it is the unit-level proof that the AC5 guard itself performs no
   * actor/target comparison (it only checks {@code size() <= 1 && contains(ref.id())}),
   * independent of whether the state is reachable. See design §6.4 for the reachability proof.
   */
  // Load-bearing (US-014 Decision 2) -- see the comment on
  // should_throwResourceNotFound_when_targetUserNotFound above.
  @Test
  void should_throwLastAdminRoleException_when_lockedSetSizeOneContainsTargetRef_differentAdminRevoking_syntheticStateSeeDesign64() {
    UUID refId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(true);

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
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(true);
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
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(true);
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
  // T-009: the unified privilege gate on revoke() -- pinned lock order (D2), the AC5 interaction
  // (D1: 403 before 409), and the D18 lock-hold timer. AC5 itself and the case-variant lockout
  // match are covered by the tests above (updated with the two new gate stubs); this block
  // covers the NEW gate call site on revoke(), the dangerous-permission path, the 403-before-409
  // ordering, the InOrder lock-ordering proof, and the D18 timer's four outcomes.
  // ---------------------------------------------------------------------------------------

  @Test
  void should_throwNotTenantAdmin_when_revokingTenantAdminAndCallerNotActiveAdmin() {
    UUID refId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId, UUID.randomUUID()));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "TENANT_ADMIN", actorId, ctx),
            DenialReason.NOT_TENANT_ADMIN, "revoke");
    verifyNoInteractions(permissionCachePort);

    // D18: the timer started right after M1 (lockActiveAssignmentIds) returns must be stopped
    // with outcome=denied at this throw site.
    var timer =
        meterRegistry
            .find("nexus.rbac.privileged_revoke_lock_hold")
            .tags("outcome", "denied")
            .timer();
    assertThat(timer).isNotNull();
    assertThat(timer.count()).isEqualTo(1L);
  }

  @Test
  void should_throwNotTenantAdmin_when_revokeRoleNameIsDifferentCaseVariantOfTenantAdmin() {
    UUID refId = UUID.randomUUID();
    Role role = adminRole("tenant_admin");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId, UUID.randomUUID()));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort).hasActiveAdminAssignment(actorId, roleId, tenantId);
    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "tenant_admin", actorId, ctx),
            DenialReason.NOT_TENANT_ADMIN, "revoke");
    verifyNoInteractions(permissionCachePort);
  }

  @Test
  void should_throwNotTenantAdmin_when_revokingRoleCarriesOneDangerousPermissionAndCallerNotActiveAdmin() {
    UUID refId = UUID.randomUUID();
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID(); // MC-3(a): deliberately != roleId
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    // MC-2: the correct (locking, assignment-based) helper is used, never the redaction helper.
    verify(userRoleAssignmentPort).hasActiveAdminAssignment(actorId, adminRoleId, tenantId);
    verify(userRoleAssignmentPort, never()).findActiveAssignmentViews(any(), any());
    // MC-3(a): the caller's admin status is checked against M8's role, never the target role.
    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), eq(roleId), any());
    // MC-3(b): the caller's own id is checked, never the target's.
    verify(userRoleAssignmentPort, never())
        .hasActiveAdminAssignment(eq(targetUserId), any(), any());
    // D2/§6.5: M1's X lock is only acquired on the nameMatch path -- never for a dangerous
    // custom role, whatever the gate's outcome.
    verify(userRoleAssignmentPort, never()).lockActiveAssignmentIds(any(), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "BILLING_ADMIN", actorId, ctx),
            DenialReason.NOT_TENANT_ADMIN, "revoke");
    verifyNoInteractions(permissionCachePort);
    // D18: the timer never starts on a non-nameMatch path -- M1 never ran, so nothing to stop.
    assertThat(meterRegistry.find("nexus.rbac.privileged_revoke_lock_hold").timers()).isEmpty();
  }

  @Test
  void should_throwNotTenantAdmin_when_revokingRoleCarriesAllThreeDangerousPermissionsAndCallerNotActiveAdmin() {
    UUID refId = UUID.randomUUID();
    Role role = customRole("SUPER_CUSTOM");
    UUID adminRoleId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("role:write", "user:write", "tenant:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    // Edge Case 3, dangerous-only variant: exactly one denial/audit row/metric increment.
    verify(rbacAuditPort, times(1))
        .recordRoleAssignmentDenied(any(), eq(DenialReason.NOT_TENANT_ADMIN), eq("revoke"));
    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), eq(roleId), any());
    verify(userRoleAssignmentPort, never())
        .hasActiveAdminAssignment(eq(targetUserId), any(), any());
  }

  /**
   * Proves {@code carriesDangerousPermission} delegates to {@code RbacDangerousPermissions
   * .contains}, which is case-insensitive (mirrors the role-name case-variant proof above).
   */
  @Test
  void should_throwNotTenantAdmin_when_revokingRoleCarriesCaseVariantDangerousPermissionName() {
    UUID refId = UUID.randomUUID();
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("User:Write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort).hasActiveAdminAssignment(actorId, adminRoleId, tenantId);
    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), eq(roleId), any());
    verify(userRoleAssignmentPort, never())
        .hasActiveAdminAssignment(eq(targetUserId), any(), any());
  }

  @Test
  void should_revokeSuccessfully_when_revokedRoleCarriesOnlyNonDangerousPermission() {
    UUID refId = UUID.randomUUID();
    Role role = customRole("BILLING_VIEWER");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId)).thenReturn(List.of("user:read"));
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort, never()).findRoleIdByName(any(), any());
    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), any(), any());
    verify(userRoleAssignmentPort, never()).lockActiveAssignmentIds(any(), any());
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
    verify(rbacAuditPort)
        .recordRoleRevoked(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "BILLING_VIEWER", actorId, ctx));
  }

  /** Edge Case 1: an empty permission set means NOT privileged -- the gate must not fire. */
  @Test
  void should_revokeSuccessfully_when_revokedRoleCarriesNoPermissions() {
    UUID refId = UUID.randomUUID();
    Role role = customRole("EMPTY_ROLE");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId)).thenReturn(List.of());
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort, never()).findRoleIdByName(any(), any());
    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), any(), any());
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
  }

  @Test
  void should_revokeSuccessfully_when_revokedRoleCarriesDangerousPermissionAndCallerIsActiveAdmin() {
    UUID refId = UUID.randomUUID();
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort).hasActiveAdminAssignment(actorId, adminRoleId, tenantId);
    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), eq(roleId), any());
    verify(userRoleAssignmentPort, never())
        .hasActiveAdminAssignment(eq(targetUserId), any(), any());
    verify(userRoleAssignmentPort, never()).lockActiveAssignmentIds(any(), any());
    verify(userRoleAssignmentPort).revoke(eq(refId), any());
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
  }

  /** R-10/T-E18 precedent, extended to revoke: an empty M8 must fail closed WITHOUT calling M5. */
  @Test
  void should_denyWithoutCallingHasActiveAdminAssignment_when_tenantHasNoSeededTenantAdminRoleOnRevoke() {
    UUID refId = UUID.randomUUID();
    Role role = customRole("BILLING_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), any(), any());
    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "BILLING_ADMIN", actorId, ctx),
            DenialReason.NOT_TENANT_ADMIN, "revoke");
  }

  @Test
  void should_propagateAndWriteNothing_when_findPermissionNamesForRoleThrowsDuringRevoke() {
    UUID refId = UUID.randomUUID();
    Role role = customRole("BILLING_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenThrow(new RuntimeException("db down"));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RuntimeException.class)
        .hasMessage("db down");

    verify(userRoleAssignmentPort, never()).findRoleIdByName(any(), any());
    verify(userRoleAssignmentPort, never()).lockActiveAssignmentIds(any(), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
  }

  @Test
  void should_propagateAndWriteNothing_when_findRoleIdByNameThrowsDuringRevoke() {
    UUID refId = UUID.randomUUID();
    Role role = customRole("BILLING_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenThrow(new RuntimeException("db down"));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RuntimeException.class)
        .hasMessage("db down");

    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), any(), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
  }

  /** D18: an unexpected propagating failure on the nameMatch path must be tagged outcome=error. */
  @Test
  void should_propagateAndRecordErrorOutcome_when_hasActiveAdminAssignmentThrowsDuringRevoke() {
    UUID refId = UUID.randomUUID();
    UUID otherAdminRefId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId, otherAdminRefId));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenThrow(new RuntimeException("db down"));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RuntimeException.class)
        .hasMessage("db down");

    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);

    var timer =
        meterRegistry
            .find("nexus.rbac.privileged_revoke_lock_hold")
            .tags("outcome", "error")
            .timer();
    assertThat(timer).isNotNull();
    assertThat(timer.count()).isEqualTo(1L);
  }

  /**
   * Edge Case 3, name-match variant for revoke: the seeded TENANT_ADMIN role satisfies BOTH
   * halves of the unified condition. The name-first short-circuit means {@code
   * carriesDangerousPermission} (M7) is never evaluated on this path.
   */
  @Test
  void should_recordExactlyOneDenialAuditAndMetric_when_revokedRoleIsNamedTenantAdminAndCallerNotActiveAdmin() {
    UUID refId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId, UUID.randomUUID()));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verify(userRoleAssignmentPort, never()).findPermissionNamesForRole(any());
    verify(rbacAuditPort, times(1)).recordRoleAssignmentDenied(any(), any(), any());
    Counter counter = meterRegistry.find("nexus.rbac.privileged_role_change_blocked").counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
  }

  @Test
  void should_logWarnWithOperationAndMatchedOnRoleName_when_revokingTenantAdminAndCallerNotActiveAdmin() {
    UUID refId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId, UUID.randomUUID()));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);

      var warnEvents =
          appender.list.stream()
              .filter(e -> e.getLevel() == Level.WARN)
              .filter(
                  e -> "RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED".equals(keyValueMap(e).get("event")))
              .toList();
      assertThat(warnEvents).hasSize(1);
      Map<String, Object> keyValues = keyValueMap(warnEvents.get(0));
      assertThat(keyValues)
          .containsEntry("operation", "revoke")
          .containsEntry("matchedOn", "ROLE_NAME")
          .containsEntry("tenantId", tenantId)
          .containsEntry("targetUserId", targetUserId)
          .containsEntry("actorUserId", actorId)
          .containsEntry("roleId", roleId)
          .containsEntry("roleName", "TENANT_ADMIN");
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_logWarnWithOperationAndMatchedOnDangerousPermission_when_revokingDangerousRoleAndCallerNotActiveAdmin() {
    UUID refId = UUID.randomUUID();
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(false);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);

      var warnEvents =
          appender.list.stream()
              .filter(e -> e.getLevel() == Level.WARN)
              .filter(
                  e -> "RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED".equals(keyValueMap(e).get("event")))
              .toList();
      assertThat(warnEvents).hasSize(1);
      Map<String, Object> keyValues = keyValueMap(warnEvents.get(0));
      assertThat(keyValues)
          .containsEntry("operation", "revoke")
          .containsEntry("matchedOn", "DANGEROUS_PERMISSION")
          .containsEntry("roleName", "BILLING_ADMIN");
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_incrementPrivilegedRoleChangeBlockedCounter_withMatchedOnRoleNameTag_when_revokingTenantAdminAndCallerNotActiveAdmin() {
    UUID refId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId, UUID.randomUUID()));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    Counter counter =
        meterRegistry
            .find("nexus.rbac.privileged_role_change_blocked")
            .tags("operation", "revoke", "matchedOn", "ROLE_NAME")
            .counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
  }

  @Test
  void should_incrementPrivilegedRoleChangeBlockedCounter_withMatchedOnDangerousPermissionTag_when_revokingDangerousRoleAndCallerNotActiveAdmin() {
    UUID refId = UUID.randomUUID();
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    Counter counter =
        meterRegistry
            .find("nexus.rbac.privileged_role_change_blocked")
            .tags("operation", "revoke", "matchedOn", "DANGEROUS_PERMISSION")
            .counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
  }

  /** MC-3's deliberate FR-4 exception: self-revocation is the one case where the two axes collapse. */
  @Test
  void should_throwNotTenantAdmin_when_actorSelfRevokesDangerousRoleAndIsNotActiveAdmin() {
    UUID refId = UUID.randomUUID();
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(actorId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(actorId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.revoke(actor, actorId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort, never()).revoke(any(), any());
  }

  /**
   * D1 / design §6.2 check 5 precedes check 6: a non-admin revoking the tenant's last active
   * admin must see 403 NOT_TENANT_ADMIN, never 409 RBAC_002 -- the 403 must win even though the
   * locked set also satisfies AC5's {@code size() <= 1 && contains(ref.id())} condition.
   */
  @Test
  void should_throwInsufficientPermission_notLastAdminRoleException_when_nonAdminRevokesTenantsLastAdmin() {
    UUID refId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId)); // size 1, contains ref.id() -- AC5 WOULD fire if reached
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false); // caller is NOT an active admin

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class)
          .satisfies(
              e ->
                  assertThat(((InsufficientPermissionException) e).getReason())
                      .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

      assertThat(
              appender.list.stream()
                  .filter(
                      e ->
                          "RBAC_LAST_ADMIN_REVOCATION_BLOCKED".equals(keyValueMap(e).get("event")))
                  .toList())
          .as("the AC5 lockout guard must never run once the gate has already denied")
          .isEmpty();
    } finally {
      stopLogCapture(appender);
    }

    verify(userRoleAssignmentPort, never()).revoke(any(), any());
  }

  /** D2, pinned lock order: M1's X lock must be acquired strictly before M5's S read. */
  @Test
  void should_invokeLockActiveAssignmentIdsBeforeHasActiveAdminAssignment_when_revokingTenantAdminAndCallerIsActiveAdmin() {
    UUID refId = UUID.randomUUID();
    UUID otherAdminRefId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId, otherAdminRefId));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    InOrder inOrder = Mockito.inOrder(userRoleAssignmentPort);
    inOrder.verify(userRoleAssignmentPort).lockActiveAssignmentIds(tenantId, roleId);
    inOrder.verify(userRoleAssignmentPort).hasActiveAdminAssignment(actorId, roleId, tenantId);
  }

  /** D18: the AC5 lockout throw must stop the timer with outcome=lockout. */
  @Test
  void should_recordLockHoldTimerOutcomeLockout_when_differentAdminRevokesTenantsLastAdmin() {
    UUID refId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(true);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(LastAdminRoleException.class);

    var timer =
        meterRegistry
            .find("nexus.rbac.privileged_revoke_lock_hold")
            .tags("outcome", "lockout")
            .timer();
    assertThat(timer).isNotNull();
    assertThat(timer.count()).isEqualTo(1L);
  }

  /** D18: a successful revoke on the nameMatch path must stop the timer with outcome=revoked. */
  @Test
  void should_recordLockHoldTimerOutcomeRevoked_when_revokeSucceedsOnNameMatchPath() {
    UUID refId = UUID.randomUUID();
    UUID otherAdminRefId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId, otherAdminRefId));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    var timer =
        meterRegistry
            .find("nexus.rbac.privileged_revoke_lock_hold")
            .tags("outcome", "revoked")
            .timer();
    assertThat(timer).isNotNull();
    assertThat(timer.count()).isEqualTo(1L);
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
  // T-010: the denial throttle at check 3.5 (D14, MC-7)
  // ---------------------------------------------------------------------------------------

  @Test
  void should_throwWithNoPortOrAuditInteractionsAndIncrementCounter_when_throttled_assign() {
    Role role = memberRole();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(throttlePort.isThrottled(tenantId, actorId)).thenReturn(true);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort, never()).findPermissionNamesForRole(any());
    verify(userRoleAssignmentPort, never()).findRoleIdByName(any(), any());
    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), any(), any());
    verify(userRoleAssignmentPort, never()).hasActiveAssignment(any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verifyNoInteractions(rbacAuditPort);
    verifyNoInteractions(permissionCachePort);

    Counter counter =
        meterRegistry.find("nexus.rbac.denial_throttled").tags("operation", "assign").counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
    assertThat(meterRegistry.find("nexus.rbac.privileged_role_change_blocked").counter()).isNull();
  }

  @Test
  void should_throwWithNoLockOrGateOrAuditInteractionsAndIncrementCounter_when_throttled_revoke() {
    UUID refId = UUID.randomUUID();
    Role role = memberRole();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(throttlePort.isThrottled(tenantId, actorId)).thenReturn(true);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentIds(any(), any());
    verify(userRoleAssignmentPort, never()).findPermissionNamesForRole(any());
    verify(userRoleAssignmentPort, never()).findRoleIdByName(any(), any());
    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), any(), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(rbacAuditPort);
    verifyNoInteractions(permissionCachePort);

    Counter counter =
        meterRegistry.find("nexus.rbac.denial_throttled").tags("operation", "revoke").counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
    assertThat(meterRegistry.find("nexus.rbac.privileged_revoke_lock_hold").timers()).isEmpty();
  }

  @Test
  void should_callRecordDenialOnThrottlePort_when_gateDeniesPrivilegedAssign() {
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verify(throttlePort).recordDenial(tenantId, actorId);
  }

  @Test
  void should_callRecordDenialOnThrottlePort_when_gateDeniesPrivilegedRevoke() {
    UUID refId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentIds(tenantId, roleId))
        .thenReturn(List.of(refId, UUID.randomUUID()));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verify(throttlePort).recordDenial(tenantId, actorId);
  }

  @Test
  void should_emitDenialThrottleEngagedWarnExactlyOnce_when_recordDenialReturnsTrue() {
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false);
    when(throttlePort.recordDenial(tenantId, actorId)).thenReturn(true);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);

      var engagedWarnings =
          appender.list.stream()
              .filter(e -> e.getLevel() == Level.WARN)
              .filter(e -> "RBAC_DENIAL_THROTTLE_ENGAGED".equals(keyValueMap(e).get("event")))
              .toList();
      assertThat(engagedWarnings).hasSize(1);
      Map<String, Object> keyValues = keyValueMap(engagedWarnings.get(0));
      assertThat(keyValues)
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
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false);
    when(throttlePort.recordDenial(tenantId, actorId)).thenReturn(false);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);

      boolean anyEngagedWarn =
          appender.list.stream()
              .anyMatch(e -> "RBAC_DENIAL_THROTTLE_ENGAGED".equals(keyValueMap(e).get("event")));
      assertThat(anyEngagedWarn).isFalse();
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_proceedWithNormalFlow_when_isThrottledThrows() {
    Role role = memberRole();
    Instant assignedAt = Instant.now();
    UUID userRoleId = UUID.randomUUID();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "MEMBER", assignedAt, actorId);

    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(throttlePort.isThrottled(tenantId, actorId)).thenThrow(new RuntimeException("store down"));
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(userRoleId);
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    ActiveRoleAssignment result = service.assign(actor, targetUserId, roleId, ctx);

    assertThat(result).isEqualTo(view);
  }

  @Test
  void should_stillThrowRealDenialException_when_recordDenialThrows() {
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, roleId, tenantId))
        .thenReturn(false);
    when(throttlePort.recordDenial(tenantId, actorId))
        .thenThrow(new RuntimeException("throttle store down"));

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "TENANT_ADMIN", actorId, ctx),
            DenialReason.NOT_TENANT_ADMIN, "assign");
  }

  @Test
  void should_return403_when_actorThrottledAndGateWouldAlsoHaveDenied() {
    UUID refId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(throttlePort.isThrottled(tenantId, actorId)).thenReturn(true);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentIds(any(), any());
    verify(userRoleAssignmentPort, never()).findRoleIdByName(any(), any());
    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), any(), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
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
