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
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.ActiveAssignmentRef;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.LastAdminRoleException;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermissionName;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.lang.reflect.Method;
import java.time.Instant;
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
import org.mockito.ArgumentCaptor;
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
        .hasActiveAssignmentOfAnyRole(any(), any(), any()); // not TENANT_ADMIN, guard skipped

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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort).hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId);
    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "tenant_admin", actorId, ctx),
            DenialReason.NOT_TENANT_ADMIN, "assign");
    verifyNoInteractions(permissionCachePort);
  }

  /**
   * AC8 positive path: caller DOES hold an active admin assignment. Verifies {@code
   * hasActiveAssignmentOfAnyRole} (M5b) is invoked with the resolved role's own id (never a
   * hardcoded or actor-derived value — T-E7) and that the flow proceeds to the
   * duplicate-check/insert path.
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(userRoleId);
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    ActiveRoleAssignment result = service.assign(actor, targetUserId, roleId, ctx);

    assertThat(result).isEqualTo(view);
    verify(userRoleAssignmentPort).hasActiveAssignmentOfAnyRole(actorId, List.of(role.getId()), tenantId);
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    // MC-2: the correct (locking, assignment-based) helper is used, never the redaction helper.
    verify(userRoleAssignmentPort).hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId);
    verify(userRoleAssignmentPort, never()).findActiveAssignmentViews(any(), any());
    // MC-3(a): the caller's admin status is checked against M8's role, never the target role.
    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), eq(List.of(roleId)), any());
    // MC-3(b): the caller's own id is checked, never the target's.
    verify(userRoleAssignmentPort, never())
        .hasActiveAssignmentOfAnyRole(eq(targetUserId), any(), any());
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId))
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
    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), eq(List.of(roleId)), any());
    verify(userRoleAssignmentPort, never())
        .hasActiveAssignmentOfAnyRole(eq(targetUserId), any(), any());
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.assign(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort).hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId);
    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), eq(List.of(roleId)), any());
    verify(userRoleAssignmentPort, never())
        .hasActiveAssignmentOfAnyRole(eq(targetUserId), any(), any());
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
    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), any(), any());
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
    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), any(), any());
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(userRoleId);
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    ActiveRoleAssignment result = service.assign(actor, targetUserId, roleId, ctx);

    assertThat(result).isEqualTo(view);
    verify(userRoleAssignmentPort).hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId);
    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), eq(List.of(roleId)), any());
    verify(userRoleAssignmentPort, never())
        .hasActiveAssignmentOfAnyRole(eq(targetUserId), any(), any());
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

    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), any(), any());
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

    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), any(), any());
    verify(userRoleAssignmentPort, never()).assign(any(), any(), any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
  }

  @Test
  void should_propagateAndWriteNothing_when_hasActiveAssignmentOfAnyRoleThrows() {
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId))
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId))
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId))
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId))
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId))
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(actorId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(actorId, roleId, tenantId, actorId)).thenReturn(userRoleId);
    when(userRoleAssignmentPort.findActiveAssignmentView(actorId, roleId, tenantId))
        .thenReturn(Optional.of(view));
    // M-2 (07-security-review.md), re-derived per US-017 D24/RC-17.1: callerIsAdmin is
    // independently re-derived via callerHoldsActiveAdminEquivalentRole's M12-driven predicate,
    // not inferred from `privileged` -- stub it to agree with the M5b locking read above so this
    // success path still tags callerIsAdmin="true". The view's roleName alone ("TENANT_ADMIN")
    // is sufficient (isFullyAdminEquivalent's name-match half), so findPermissionNamesForActive
    // AssignmentsOfUser (M12) is left unstubbed (default empty list).
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
   * M-2 (07-security-review.md, RC-11.2), re-derived per US-017 D24/RC-17.1: proves {@code
   * callerIsAdmin="false"} is still reachable on the {@code privileged="true"} series -- the
   * exact value the canary alert ({@code nexus_rbac_gate_bypass_canary}) fires on. Simulates the
   * two independent mechanisms disagreeing: M5b's locking read ({@code
   * hasActiveAssignmentOfAnyRole}) says the caller qualifies (so the gate passes and {@code
   * assign()} still succeeds), but the M12-driven canary ({@code
   * callerHoldsActiveAdminEquivalentRole}) shows no active assignment at all for that same actor
   * -- a T-E22-class disagreement, no longer definitionally unemittable.
   */
  @Test
  void should_tagCallerIsAdminFalse_when_gateAndCanaryDisagree() {
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId))
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

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
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

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(permissionCachePort, rbacAuditPort);
  }

  /**
   * ...and, per the real (read, not assumed) ordering in the source, this is ALSO true for an
   * admin role: {@code findActiveAssignmentRef} (M3) is resolved before {@code
   * lockActiveAssignmentHolders} (M11) is ever reached, so a not-found assignment short-circuits
   * before the lockout guard runs, even when the role being revoked is {@code TENANT_ADMIN}.
   *
   * <p>This is also Edge Case 11 (404 before 403): the target role here is the literally-named
   * {@code TENANT_ADMIN}, which would otherwise trigger the privilege gate (and, for a
   * non-qualifying caller, a 403) -- the 404 from M3 fires first regardless, since M3 is resolved
   * ahead of every privilege-gate read.
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

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
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
    // US-017 D5/D6: M11 locks the union set (here just {roleId}, since the tenant has no other
    // admin-equivalent role) and returns the DISTINCT HOLDER rows, not a list of ids.
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(List.of(new ActiveAssignmentHolder(refId, actorId, roleId)));
    // The privilege gate now runs ahead of AC5 -- the caller must pass it (M5b) to reach the
    // lockout guard at all (design §6.4/§7.2).
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(List.of(new ActiveAssignmentHolder(refId, targetUserId, roleId)));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
    UUID otherAdminUserId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(otherAdminRefId, otherAdminUserId, roleId)));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
   * (mirrors the assign-side {@code equalsIgnoreCase} proof) -- {@code lockActiveAssignmentHolders}
   * must be invoked even though the persisted role name is not the exact-case constant.
   */
  @Test
  void should_invokeLockoutGuard_when_revokeRoleNameIsDifferentCaseVariantOfTenantAdmin() {
    UUID refId = UUID.randomUUID();
    UUID otherAdminRefId = UUID.randomUUID();
    UUID otherAdminUserId = UUID.randomUUID();
    Role role = adminRole("Tenant_Admin");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(otherAdminRefId, otherAdminUserId, roleId)));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), any());
    verify(userRoleAssignmentPort).revoke(eq(refId), any());
  }

  /**
   * MC-D (design §11.2) / Edge Case 1: one user holding TWO admin-equivalent roles must be
   * counted ONCE, and excluding the row being revoked (by {@code assignmentId}, NEVER by {@code
   * userId}) must still leave that user counted as a holder via their OTHER admin-equivalent
   * role's row. A naive row-count, or a userId-based exclusion, would wrongly lock this out.
   */
  @Test
  void should_notLockOut_when_targetUserHoldsAnotherAdminEquivalentRoleViaADifferentAssignment_MCD_EdgeCase1() {
    UUID refId = UUID.randomUUID();
    UUID otherAssignmentId = UUID.randomUUID();
    UUID adminRoleId = UUID.randomUUID();
    Role role = customRole("BILLING_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId)).thenReturn(List.of("user:write"));
    // A present M8 id, not empty: this test's subject is the AC5/MC-D lockout math, not the
    // caller gate, so the caller-qualifying set must be non-empty or D9's fail-closed-without-
    // read short-circuit denies before the (broadly stubbed) caller check below is ever reached.
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    // The SAME targetUserId holds two rows: the one being revoked (refId, the BILLING_ADMIN
    // role being revoked -- ANY-qualifying only, not caller-qualifying by itself) and one
    // other, unrelated CALLER-QUALIFYING assignment (otherAssignmentId, the literal admin role
    // adminRoleId) -- counted once, not twice, and excluding refId by ASSIGNMENT id leaves the
    // user's other row intact and caller-qualifying (H-1: must be caller-qualifying, not merely
    // ANY, for MC-D's "counts once via the other row" point to still hold post-fix).
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(otherAssignmentId, targetUserId, adminRoleId)));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(any(), any(), any())).thenReturn(true);
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort).revoke(eq(refId), any());
    verify(rbacAuditPort).recordRoleRevoked(any());
  }

  /** Edge Case 2: two DIFFERENT users, two different admin-equivalent roles -- revoking one
   *  user's assignment must not lock out the tenant; the other user's holder row remains. */
  @Test
  void should_notLockOut_when_aDifferentUserHoldsAnotherAdminEquivalentRole_EdgeCase2() {
    UUID refId = UUID.randomUUID();
    UUID otherAssignmentId = UUID.randomUUID();
    UUID otherHolderUserId = UUID.randomUUID();
    UUID adminRoleId = UUID.randomUUID();
    Role role = customRole("BILLING_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId)).thenReturn(List.of("user:write"));
    // A present M8 id, not empty -- see the identical note on EdgeCase1 above: this test's
    // subject is the AC5/MC-D lockout math, not the caller gate.
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    // H-1: otherHolderUserId's row must be caller-qualifying (the literal admin role
    // adminRoleId), not merely another ANY-qualifying custom role, for "should not lock out" to
    // still hold post-fix.
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(otherAssignmentId, otherHolderUserId, adminRoleId)));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(any(), any(), any())).thenReturn(true);
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort).revoke(eq(refId), any());
  }

  private static boolean invokeWouldLeaveTenantWithoutCallerQualifyingHolder(
      List<ActiveAssignmentHolder> lockedHolders,
      UUID revokedAssignmentId,
      Set<UUID> callerQualifyingRoleIds)
      throws Exception {
    Method method =
        RoleAssignmentService.class.getDeclaredMethod(
            "wouldLeaveTenantWithoutCallerQualifyingHolder", List.class, UUID.class, Set.class);
    method.setAccessible(true);
    return (boolean) method.invoke(null, lockedHolders, revokedAssignmentId, callerQualifyingRoleIds);
  }

  /**
   * Edge Case 3: the D5 predicate must be deterministic -- the same set of locked-holder rows
   * must produce the same lockout decision regardless of the list's iteration/insertion order.
   */
  @Test
  void should_produceSameResult_regardlessOfLockedHoldersListOrder_EdgeCase3() throws Exception {
    UUID refId = UUID.randomUUID();
    UUID otherAssignmentId = UUID.randomUUID();
    UUID otherUserId = UUID.randomUUID();
    UUID otherRoleId = UUID.randomUUID();
    Set<UUID> callerQualifyingRoleIds = Set.of(otherRoleId);
    List<ActiveAssignmentHolder> naturalOrder =
        List.of(
            new ActiveAssignmentHolder(refId, targetUserId, roleId),
            new ActiveAssignmentHolder(otherAssignmentId, otherUserId, otherRoleId));
    List<ActiveAssignmentHolder> reversedOrder =
        List.of(
            new ActiveAssignmentHolder(otherAssignmentId, otherUserId, otherRoleId),
            new ActiveAssignmentHolder(refId, targetUserId, roleId));

    boolean naturalOrderResult =
        invokeWouldLeaveTenantWithoutCallerQualifyingHolder(naturalOrder, refId, callerQualifyingRoleIds);
    boolean reversedOrderResult =
        invokeWouldLeaveTenantWithoutCallerQualifyingHolder(
            reversedOrder, refId, callerQualifyingRoleIds);

    assertThat(naturalOrderResult).isFalse();
    assertThat(reversedOrderResult).isEqualTo(naturalOrderResult);
  }

  /**
   * Edge Case 6: a tenant with NO admin-equivalent role at all means {@code privileged} is false
   * -- the widened lockout gate does not apply (already covered structurally by the
   * "carriesNoPermissions"/"carriesOnlyNonDangerousPermission" tests below, restated here by name
   * for traceability to the requirements' edge-case numbering).
   */

  /**
   * Edge Case 10: a plain, unprivileged revoke (negative baseline) -- already covered
   * structurally by {@code should_revokeSuccessfully_when_revokedRoleCarriesOnlyNonDangerousPermission}
   * below, which asserts no M8/M10/M11/M5b call and a normal success outcome; restated here by
   * name for traceability to the requirements' edge-case numbering.
   */

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
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID())));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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

    // D18: the timer started right after M11 (lockActiveAssignmentHolders) returns must be
    // stopped with outcome=denied at this throw site.
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
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID())));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort).hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId);
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
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID())));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(
            actorId, List.of(adminRoleId), tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    // MC-2: the correct (locking, assignment-based) helper is used, never the redaction helper.
    verify(userRoleAssignmentPort)
        .hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId);
    verify(userRoleAssignmentPort, never()).findActiveAssignmentViews(any(), any());
    // MC-3(a): the caller's admin status is checked against M8's role, never the target role.
    verify(userRoleAssignmentPort, never())
        .hasActiveAssignmentOfAnyRole(any(), eq(List.of(roleId)), any());
    // MC-3(b): the caller's own id is checked, never the target's.
    verify(userRoleAssignmentPort, never())
        .hasActiveAssignmentOfAnyRole(eq(targetUserId), any(), any());
    // D5/D6/§7.2: the widened gate acquires M11 on EVERY privileged path, including a dangerous
    // custom role that does not name-match TENANT_ADMIN -- the pre-US-017 "no lock on this path"
    // behaviour this assertion used to encode no longer holds (FR-1).
    verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verify(rbacAuditPort)
        .recordRoleAssignmentDenied(
            new RbacAuditEvent(tenantId, targetUserId, roleId, "BILLING_ADMIN", actorId, ctx),
            DenialReason.NOT_TENANT_ADMIN, "revoke");
    verifyNoInteractions(permissionCachePort);
    // D18: the widened gate now starts the lock-hold timer on this path too (privileged, not
    // merely nameMatch) -- it must be stopped with outcome=denied at the gate's throw site.
    var timer =
        meterRegistry
            .find("nexus.rbac.privileged_revoke_lock_hold")
            .tags("outcome", "denied")
            .timer();
    assertThat(timer).isNotNull();
    assertThat(timer.count()).isEqualTo(1L);
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(
            actorId, List.of(adminRoleId), tenantId))
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
    verify(userRoleAssignmentPort, never())
        .hasActiveAssignmentOfAnyRole(any(), eq(List.of(roleId)), any());
    verify(userRoleAssignmentPort, never())
        .hasActiveAssignmentOfAnyRole(eq(targetUserId), any(), any());
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(
            actorId, List.of(adminRoleId), tenantId))
        .thenReturn(false);

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort)
        .hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId);
    verify(userRoleAssignmentPort, never())
        .hasActiveAssignmentOfAnyRole(any(), eq(List.of(roleId)), any());
    verify(userRoleAssignmentPort, never())
        .hasActiveAssignmentOfAnyRole(eq(targetUserId), any(), any());
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
    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), any(), any());
    // Benign path (not privileged -- only a non-dangerous permission): +0, M11 never acquired
    // (D5/§7.2's "one condition, one call site" property).
    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
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
    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), any(), any());
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
    // H-1: the remaining holder must hold the caller-qualifying (literal admin) role for this
    // success outcome to still hold post-fix.
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), adminRoleId)));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(
            actorId, List.of(adminRoleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort)
        .hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId);
    verify(userRoleAssignmentPort, never())
        .hasActiveAssignmentOfAnyRole(any(), eq(List.of(roleId)), any());
    verify(userRoleAssignmentPort, never())
        .hasActiveAssignmentOfAnyRole(eq(targetUserId), any(), any());
    // D5/D6/§7.2: the widened gate acquires M11 on every privileged path, including this
    // dangerous-custom-role path -- the pre-US-017 "no lock here" behaviour no longer holds.
    verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), any());
    verify(userRoleAssignmentPort).revoke(eq(refId), any());
    verify(rbacAuditPort, never()).recordRoleAssignmentDenied(any(), any(), any());
  }

  /** R-10/T-E18 precedent, extended to revoke: an empty M8 (with no fully-admin-equivalent
   *  custom role either) must fail closed WITHOUT calling M5b. */
  @Test
  void should_denyWithoutCallingHasActiveAssignmentOfAnyRole_when_tenantHasNoSeededTenantAdminRoleOnRevoke() {
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

    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), any(), any());
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

    // M7 throws before `privileged` is even computed -- neither M10/M8/M11 nor the caller gate
    // is ever reached on this path, so the lock is never acquired (unaffected by D5/D6's
    // widening, which only widens WHEN the lock fires, never makes it fire before `privileged`
    // is known).
    verify(userRoleAssignmentPort, never()).findRoleIdByName(any(), any());
    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
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

    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), any(), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
  }

  /**
   * Edge Case 12: {@code resolveAdminEquivalentRoles}'s M10 read ({@code
   * findPermissionNamesForTenantRoles}) throwing must propagate uncaught out of {@code revoke()}
   * -- fail closed, never swallowed and never silently treated as "allow the revoke." M10 runs
   * before M8 inside {@code resolveAdminEquivalentRoles}, so this exception surfaces before M8,
   * M11, and the caller gate are ever reached.
   */
  @Test
  void should_propagateUncaught_when_findPermissionNamesForTenantRolesThrowsDuringRevoke_EdgeCase12() {
    UUID refId = UUID.randomUUID();
    Role role = customRole("BILLING_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId))
        .thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenThrow(new RuntimeException("db down"));

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, roleId, ctx))
        .isInstanceOf(RuntimeException.class)
        .hasMessage("db down");

    verify(userRoleAssignmentPort, never()).findRoleIdByName(any(), any());
    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), any(), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
    assertThat(meterRegistry.find("nexus.rbac.privileged_revoke_lock_hold").timers()).isEmpty();
  }

  /** D18: an unexpected propagating failure on the nameMatch path must be tagged outcome=error. */
  @Test
  void should_propagateAndRecordErrorOutcome_when_hasActiveAssignmentOfAnyRoleThrowsDuringRevoke() {
    UUID refId = UUID.randomUUID();
    UUID otherAdminRefId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(otherAdminRefId, UUID.randomUUID(), UUID.randomUUID())));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID())));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID())));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(
            actorId, List.of(adminRoleId), tenantId))
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
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID())));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(
            actorId, List.of(adminRoleId), tenantId))
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(
            actorId, List.of(adminRoleId), tenantId))
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
   * D1 / design §6.2 check 5 precedes check 6 / Edge Case 9: a non-admin revoking the tenant's
   * last active admin must see 403 NOT_TENANT_ADMIN, never 409 RBAC_002 -- the 403 must win even
   * though the locked holder set also satisfies AC5's "would leave the tenant without a holder"
   * condition.
   */
  @Test
  void should_throwInsufficientPermission_notLastAdminRoleException_when_nonAdminRevokesTenantsLastAdmin_EdgeCase9() {
    UUID refId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    // Single distinct holder (the row being revoked) -- AC5 WOULD fire if the gate ever let
    // execution reach the wouldLeaveTenantWithoutCallerQualifyingHolder check.
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(List.of(new ActiveAssignmentHolder(refId, targetUserId, roleId)));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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

  /** D2, pinned lock order: M11's X lock must be acquired strictly before M5b's S read. */
  @Test
  void should_invokeLockActiveAssignmentHoldersBeforeHasActiveAssignmentOfAnyRole_when_revokingTenantAdminAndCallerIsActiveAdmin() {
    UUID refId = UUID.randomUUID();
    UUID otherAdminRefId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(otherAdminRefId, UUID.randomUUID(), roleId)));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    InOrder inOrder = Mockito.inOrder(userRoleAssignmentPort);
    inOrder.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), any());
    inOrder.verify(userRoleAssignmentPort).hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId);
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
    // Single distinct holder (the row being revoked): excluding it leaves zero holders.
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(List.of(new ActiveAssignmentHolder(refId, targetUserId, roleId)));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(otherAdminRefId, UUID.randomUUID(), roleId)));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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

  /**
   * MC-E, {@code revoke()} half (D6/RC-20.7): the role-id list passed to M11 must be sorted by
   * UNSIGNED byte-wise order of the 16-byte representation -- explicitly NOT {@link
   * UUID#compareTo}, which compares {@code mostSigBits} as a SIGNED {@code long}. {@code
   * lowBitRoleId} has {@code mostSigBits = 1L} (small, positive under both signed and unsigned
   * interpretation); {@code highBitRoleId} has {@code mostSigBits = Long.MIN_VALUE} (its bit
   * pattern's top bit set -- the largest possible value unsigned, but the smallest, most
   * negative, value signed). Ascending UNSIGNED order is therefore {@code [lowBitRoleId,
   * highBitRoleId]}; ascending SIGNED ({@code UUID.compareTo}) order is the reverse. An MC-E that
   * merely asserted "the list is sorted" would pass under either comparator and give false
   * assurance about the one property D6's deadlock-freedom argument rests on.
   */
  @Test
  void should_sortLockSetByUnsignedBytewiseOrder_notUuidCompareTo_when_revoking_MCE() {
    UUID lowBitRoleId = new UUID(1L, 0L);
    UUID highBitRoleId = new UUID(Long.MIN_VALUE, 0L);
    assertThat(lowBitRoleId.compareTo(highBitRoleId))
        .as("fixture precondition: signed UUID.compareTo must rank lowBitRoleId AFTER highBitRoleId")
        .isGreaterThan(0);

    UUID refId = UUID.randomUUID();
    Role role = new Role(lowBitRoleId, tenantId, "BILLING_ADMIN", "desc", false);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(lowBitRoleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, lowBitRoleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(lowBitRoleId))
        .thenReturn(List.of("user:write"));
    // M10: a second tenant role (highBitRoleId) also carries one dangerous permission, so it
    // joins adminEquivalentIds -- deliberately NOT fully-admin-equivalent, so the caller-
    // qualifying set (M5b) stays empty and the gate fails closed without an extra stub.
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(List.of(new RolePermissionName(highBitRoleId, "user:write")));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.revoke(actor, targetUserId, lowBitRoleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<UUID>> lockSetCaptor = ArgumentCaptor.forClass(List.class);
    verify(userRoleAssignmentPort)
        .lockActiveAssignmentHolders(eq(tenantId), lockSetCaptor.capture());
    List<UUID> lockSet = lockSetCaptor.getValue();

    assertThat(lockSet).containsExactly(lowBitRoleId, highBitRoleId);
    assertThat(lockSet)
        .as("must NOT equal UUID.compareTo's (signed) ascending order")
        .isNotEqualTo(List.of(highBitRoleId, lowBitRoleId));
    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), any(), any());
  }

  // ---------------------------------------------------------------------------------------
  // T-006(d)/(e): MC-F (M5b's argument shape) and MC-G (the redaction/canary helpers never
  // feeding an authorization decision) -- both asserted on both verbs (design §11.2).
  // ---------------------------------------------------------------------------------------

  /**
   * MC-F, {@code revoke()} half (design §11.2): every M5b ({@code hasActiveAssignmentOfAnyRole})
   * call underlying {@code requireCallerHoldsAdminEquivalentRole} must be made with {@code
   * actor.userId()} and a role-id list drawn ONLY from the caller-qualifying set ({@code
   * fullyAdminEquivalentIds ∪ namedAdminRoleId}) -- never {@code targetUserId} and never the
   * target role id alone (T-E22's two fail-open axes, re-exposed by M5b's widened arity). The
   * named-admin branch is stubbed to fail so BOTH sequential M5b calls fire, capturing one
   * invocation per set.
   */
  @Test
  void should_callM5bOnlyWithActorIdAndCallerQualifyingRoleIds_when_revokingPrivilegedRole_MCF() {
    UUID refId = UUID.randomUUID();
    Role role = customRole("BILLING_ADMIN");
    UUID namedAdminRoleId = UUID.randomUUID();
    UUID fullyRoleId = UUID.randomUUID();
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId)).thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(
            List.of(
                new RolePermissionName(fullyRoleId, "role:write"),
                new RolePermissionName(fullyRoleId, "user:write"),
                new RolePermissionName(fullyRoleId, "tenant:write")));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(namedAdminRoleId));
    // Two OTHER distinct holders besides the target, so this revoke never trips AC5's lockout --
    // this test's subject is MC-F, not the lockout math. The other holder must be
    // caller-qualifying (H-1) for the revoke to actually succeed as stubbed below.
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), fullyRoleId)));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(namedAdminRoleId), tenantId))
        .thenReturn(false);
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(fullyRoleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    ArgumentCaptor<UUID> callerIdCaptor = ArgumentCaptor.forClass(UUID.class);
    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<UUID>> roleIdsCaptor = ArgumentCaptor.forClass(List.class);
    verify(userRoleAssignmentPort, times(2))
        .hasActiveAssignmentOfAnyRole(callerIdCaptor.capture(), roleIdsCaptor.capture(), eq(tenantId));

    Set<UUID> callerQualifyingSet = Set.of(namedAdminRoleId, fullyRoleId);
    assertThat(callerIdCaptor.getAllValues())
        .as("M5b's caller argument must always be actor.userId(), never targetUserId")
        .allMatch(actorId::equals);
    assertThat(roleIdsCaptor.getAllValues())
        .as("every M5b call's role-id list must be drawn only from the caller-qualifying set,"
            + " never the target role id alone")
        .allSatisfy(
            roleIds -> {
              assertThat(roleIds).isNotEqualTo(List.of(roleId));
              assertThat(callerQualifyingSet).containsAll(roleIds);
            });
  }

  /**
   * MC-G, {@code revoke()} half (design §11.2): on a privileged revoke targeting a DIFFERENT
   * user, neither the {@code listActive} redaction helper ({@code callerHoldsActiveTenantAdmin})
   * nor the canary's M12 read ({@code findPermissionNamesForActiveAssignmentsOfUser}) may be
   * invoked -- {@code revoke()} has no canary code path at all, so this pins that a future
   * refactor cannot introduce one. The gate's ONLY determination is M5b, a fresh locking read
   * (T-E7). Asserted per-verb, not at class level, since three similarly-named boolean helpers
   * now exist on this class (MC-2 carried forward per D14/D17).
   */
  @Test
  void should_neverInvokeRedactionOrCanaryPortReads_when_revokingPrivilegedRoleFromAnotherUser_MCG() {
    UUID refId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), roleId)));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort, never()).findActiveAssignmentViews(any(), any());
    verify(userRoleAssignmentPort, never()).findPermissionNamesForActiveAssignmentsOfUser(any(), any());
  }

  // ---------------------------------------------------------------------------------------
  // T-003: assign()'s RES-10 fix (D7), the shared caller-gate split query, the re-derived
  // canary (D24/RC-17.1), the D23 promotion signal, and the new instrumentation.
  // ---------------------------------------------------------------------------------------

  /**
   * MC-E, {@code assign()} half (D6/RC-20.7, T-003(e)): sibling of the {@code revoke()} half
   * above -- the SAME ascending unsigned byte-wise order must hold for the lock set built on
   * {@code assign()}'s privileged path, now that D7's RES-10 fix makes {@code assign()} acquire
   * M11 too.
   */
  @Test
  void should_sortLockSetByUnsignedBytewiseOrder_notUuidCompareTo_when_assigning_MCE() {
    UUID lowBitRoleId = new UUID(1L, 0L);
    UUID highBitRoleId = new UUID(Long.MIN_VALUE, 0L);
    assertThat(lowBitRoleId.compareTo(highBitRoleId))
        .as("fixture precondition: signed UUID.compareTo must rank lowBitRoleId AFTER highBitRoleId")
        .isGreaterThan(0);

    Role role = new Role(lowBitRoleId, tenantId, "BILLING_ADMIN", "desc", false);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(lowBitRoleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(lowBitRoleId))
        .thenReturn(List.of("user:write"));
    // Deliberately NOT fully-admin-equivalent (§7.2's caller-qualifying set stays empty), so the
    // gate fails closed without an extra stub -- mirrors the revoke() half's fixture exactly.
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(List.of(new RolePermissionName(highBitRoleId, "user:write")));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.assign(actor, targetUserId, lowBitRoleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<UUID>> lockSetCaptor = ArgumentCaptor.forClass(List.class);
    verify(userRoleAssignmentPort)
        .lockActiveAssignmentHolders(eq(tenantId), lockSetCaptor.capture());
    List<UUID> lockSet = lockSetCaptor.getValue();

    assertThat(lockSet).containsExactly(lowBitRoleId, highBitRoleId);
    assertThat(lockSet)
        .as("must NOT equal UUID.compareTo's (signed) ascending order")
        .isNotEqualTo(List.of(highBitRoleId, lowBitRoleId));
    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), any(), any());
  }

  /**
   * D7/RES-10 fix, §7.2/§7.3: on {@code assign()}'s privileged path, M11 ({@code
   * lockActiveAssignmentHolders}) MUST be acquired strictly before M5b ({@code
   * hasActiveAssignmentOfAnyRole}) -- the whole point of the fix. A caller who ultimately
   * qualifies proves the ORDER, not just that both eventually run. Also proves the gate's own
   * path never touches M12 (A-3/MC-H's gate-only half) -- this is a non-self-assignment, so the
   * canary code path is never reached at all.
   */
  @Test
  void should_acquireM11BeforeM5b_when_assigningPrivilegedRole() {
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    Instant assignedAt = Instant.now();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "BILLING_ADMIN", assignedAt, actorId);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId)).thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    service.assign(actor, targetUserId, roleId, ctx);

    InOrder inOrder = Mockito.inOrder(userRoleAssignmentPort);
    inOrder.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), any());
    inOrder
        .verify(userRoleAssignmentPort)
        .hasActiveAssignmentOfAnyRole(eq(actorId), eq(List.of(adminRoleId)), eq(tenantId));
    verify(userRoleAssignmentPort, never())
        .findPermissionNamesForActiveAssignmentsOfUser(any(), any());
  }

  /**
   * MC-F, {@code assign()} half (design §11.2): every M5b ({@code hasActiveAssignmentOfAnyRole})
   * call underlying {@code requireCallerHoldsAdminEquivalentRole} must be made with {@code
   * actor.userId()} and a role-id list drawn ONLY from the caller-qualifying set ({@code
   * fullyAdminEquivalentIds ∪ namedAdminRoleId}) -- never {@code targetUserId} and never the
   * target role id alone. Sibling of the {@code revoke()} half below.
   */
  @Test
  void should_callM5bOnlyWithActorIdAndCallerQualifyingRoleIds_when_assigningPrivilegedRole_MCF() {
    Role role = customRole("BILLING_ADMIN");
    UUID namedAdminRoleId = UUID.randomUUID();
    UUID fullyRoleId = UUID.randomUUID();
    Instant assignedAt = Instant.now();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "BILLING_ADMIN", assignedAt, actorId);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId)).thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(
            List.of(
                new RolePermissionName(fullyRoleId, "role:write"),
                new RolePermissionName(fullyRoleId, "user:write"),
                new RolePermissionName(fullyRoleId, "tenant:write")));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(namedAdminRoleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(namedAdminRoleId), tenantId))
        .thenReturn(false);
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(fullyRoleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    service.assign(actor, targetUserId, roleId, ctx);

    ArgumentCaptor<UUID> callerIdCaptor = ArgumentCaptor.forClass(UUID.class);
    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<UUID>> roleIdsCaptor = ArgumentCaptor.forClass(List.class);
    verify(userRoleAssignmentPort, times(2))
        .hasActiveAssignmentOfAnyRole(callerIdCaptor.capture(), roleIdsCaptor.capture(), eq(tenantId));

    Set<UUID> callerQualifyingSet = Set.of(namedAdminRoleId, fullyRoleId);
    assertThat(callerIdCaptor.getAllValues())
        .as("M5b's caller argument must always be actor.userId(), never targetUserId")
        .allMatch(actorId::equals);
    assertThat(roleIdsCaptor.getAllValues())
        .as("every M5b call's role-id list must be drawn only from the caller-qualifying set,"
            + " never the target role id alone")
        .allSatisfy(
            roleIds -> {
              assertThat(roleIds).isNotEqualTo(List.of(roleId));
              assertThat(callerQualifyingSet).containsAll(roleIds);
            });
  }

  /**
   * MC-G, {@code assign()} half (design §11.2): on a privileged assignment targeting a DIFFERENT
   * user (so the T-003(b) canary code path is never reached at all), neither the {@code
   * listActive} redaction helper ({@code callerHoldsActiveTenantAdmin}) nor the canary's M12 read
   * ({@code findPermissionNamesForActiveAssignmentsOfUser}) may be invoked. The gate's ONLY
   * determination is M5b, a fresh locking read (T-E7). Asserted per-verb, not at class level,
   * since three similarly-named boolean helpers now exist on this class (MC-2 carried forward
   * per D14/D17).
   */
  @Test
  void should_neverInvokeRedactionOrCanaryPortReads_when_assigningPrivilegedRoleToAnotherUser_MCG() {
    Role role = adminRole("TENANT_ADMIN");
    Instant assignedAt = Instant.now();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "TENANT_ADMIN", assignedAt, actorId);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    service.assign(actor, targetUserId, roleId, ctx);

    verify(userRoleAssignmentPort, never()).findActiveAssignmentViews(any(), any());
    verify(userRoleAssignmentPort, never()).findPermissionNamesForActiveAssignmentsOfUser(any(), any());
  }

  /**
   * US-017 §9.2/D23: {@code privileged_role_change_allowed}'s {@code ROLE_NAME} population. The
   * log companion (RC-16.3) and the D23 promotion signal are both {@code
   * ALL_DANGEROUS_PERMISSIONS}-only, so neither must fire here.
   */
  @Test
  void should_incrementPrivilegedRoleChangeAllowedCounter_withCallerMatchedOnRoleName_when_assigningAndCallerIsNamedAdmin() {
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    Instant assignedAt = Instant.now();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "BILLING_ADMIN", assignedAt, actorId);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId)).thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.assign(actor, targetUserId, roleId, ctx);

      Counter counter =
          meterRegistry
              .find("nexus.rbac.privileged_role_change_allowed")
              .tags("operation", "assign", "callerMatchedOn", "ROLE_NAME")
              .counter();
      assertThat(counter).isNotNull();
      assertThat(counter.count()).isEqualTo(1.0);

      assertThat(
              appender.list.stream()
                  .anyMatch(
                      e ->
                          "RBAC_PRIVILEGED_ROLE_CHANGE_ALLOWED".equals(keyValueMap(e).get("event"))))
          .as("the log companion is ALL_DANGEROUS_PERMISSIONS-only")
          .isFalse();
      assertThat(
              appender.list.stream()
                  .anyMatch(
                      e ->
                          "RBAC_ADMIN_MINTED_BY_NON_NAMED_ADMIN".equals(keyValueMap(e).get("event"))))
          .isFalse();
      assertThat(meterRegistry.find("nexus.rbac.admin_minted_by_non_named_admin").counter()).isNull();
    } finally {
      stopLogCapture(appender);
    }
  }

  /**
   * US-017 §9.2/D23/RC-16.3: {@code privileged_role_change_allowed}'s {@code
   * ALL_DANGEROUS_PERMISSIONS} population -- the new FR-3 population this signal exists to make
   * visible -- plus its log companion (a subject the metric alone cannot provide, T-R11). D23
   * itself must NOT fire: the target role is not the literal {@code TENANT_ADMIN}.
   */
  @Test
  void should_incrementPrivilegedRoleChangeAllowedCounterAndLogCompanion_withCallerMatchedOnAllDangerousPermissions_when_assigningAndCallerHoldsFullyAdminEquivalentCustomRole() {
    Role role = customRole("BILLING_ADMIN");
    UUID fullyRoleId = UUID.randomUUID();
    Instant assignedAt = Instant.now();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "BILLING_ADMIN", assignedAt, actorId);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId)).thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(
            List.of(
                new RolePermissionName(fullyRoleId, "role:write"),
                new RolePermissionName(fullyRoleId, "user:write"),
                new RolePermissionName(fullyRoleId, "tenant:write")));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN")).thenReturn(Optional.empty());
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(fullyRoleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.assign(actor, targetUserId, roleId, ctx);

      Counter counter =
          meterRegistry
              .find("nexus.rbac.privileged_role_change_allowed")
              .tags("operation", "assign", "callerMatchedOn", "ALL_DANGEROUS_PERMISSIONS")
              .counter();
      assertThat(counter).isNotNull();
      assertThat(counter.count()).isEqualTo(1.0);

      var companionEvents =
          appender.list.stream()
              .filter(
                  e -> "RBAC_PRIVILEGED_ROLE_CHANGE_ALLOWED".equals(keyValueMap(e).get("event")))
              .toList();
      assertThat(companionEvents).hasSize(1);
      Map<String, Object> keyValues = keyValueMap(companionEvents.get(0));
      assertThat(keyValues)
          .containsEntry("tenantId", tenantId)
          .containsEntry("actorUserId", actorId)
          .containsEntry("targetUserId", targetUserId)
          .containsEntry("roleId", roleId)
          .containsEntry("roleName", "BILLING_ADMIN")
          .containsEntry("operation", "assign");

      assertThat(
              appender.list.stream()
                  .anyMatch(
                      e ->
                          "RBAC_ADMIN_MINTED_BY_NON_NAMED_ADMIN".equals(keyValueMap(e).get("event"))))
          .as("D23 is TENANT_ADMIN-target-only; this target role is not TENANT_ADMIN")
          .isFalse();
      assertThat(meterRegistry.find("nexus.rbac.admin_minted_by_non_named_admin").counter()).isNull();
    } finally {
      stopLogCapture(appender);
    }
  }

  /**
   * US-017 D23/RC-16.2, the promotion signal's true-positive: a caller who does NOT themselves
   * hold the literal {@code TENANT_ADMIN} role is minting a NEW one via a fully-admin-equivalent
   * custom role -- the single most sensitive operation FR-3 newly permits, and the one for which
   * the re-derived canary would otherwise report {@code callerIsAdmin=true} with no other signal.
   */
  @Test
  void should_emitAdminMintedWarnAndCounter_when_assigningTenantAdminAndCallerHoldsFullyAdminEquivalentCustomRoleButIsNotNamedAdmin() {
    Role role = adminRole("TENANT_ADMIN");
    UUID fullyRoleId = UUID.randomUUID();
    Instant assignedAt = Instant.now();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "TENANT_ADMIN", assignedAt, actorId);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN")).thenReturn(Optional.of(roleId));
    // The caller does NOT hold the literal TENANT_ADMIN role themselves -- they are minting it.
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
        .thenReturn(false);
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(
            List.of(
                new RolePermissionName(fullyRoleId, "role:write"),
                new RolePermissionName(fullyRoleId, "user:write"),
                new RolePermissionName(fullyRoleId, "tenant:write")));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(fullyRoleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.assign(actor, targetUserId, roleId, ctx);

      var warnEvents =
          appender.list.stream()
              .filter(e -> e.getLevel() == Level.WARN)
              .filter(
                  e ->
                      "RBAC_ADMIN_MINTED_BY_NON_NAMED_ADMIN".equals(keyValueMap(e).get("event")))
              .toList();
      assertThat(warnEvents).hasSize(1);
      Map<String, Object> keyValues = keyValueMap(warnEvents.get(0));
      assertThat(keyValues)
          .containsEntry("tenantId", tenantId)
          .containsEntry("actorUserId", actorId)
          .containsEntry("targetUserId", targetUserId)
          .containsEntry("roleId", roleId);

      Counter counter =
          meterRegistry
              .find("nexus.rbac.admin_minted_by_non_named_admin")
              .tags("selfTarget", "false")
              .counter();
      assertThat(counter).isNotNull();
      assertThat(counter.count()).isEqualTo(1.0);
    } finally {
      stopLogCapture(appender);
    }
  }

  /**
   * US-017 D23's negative case (threat-model §9.5 item 3 residual): a caller who IS the literal
   * {@code TENANT_ADMIN} granting {@code TENANT_ADMIN} to someone else is the ordinary, expected
   * path -- not a promotion, and must not page.
   */
  @Test
  void should_notEmitAdminMintedWarn_when_assigningTenantAdminAndCallerIsNamedAdmin() {
    Role role = adminRole("TENANT_ADMIN");
    Instant assignedAt = Instant.now();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "TENANT_ADMIN", assignedAt, actorId);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN")).thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.assign(actor, targetUserId, roleId, ctx);

      assertThat(
              appender.list.stream()
                  .anyMatch(
                      e ->
                          "RBAC_ADMIN_MINTED_BY_NON_NAMED_ADMIN".equals(keyValueMap(e).get("event"))))
          .isFalse();
      assertThat(meterRegistry.find("nexus.rbac.admin_minted_by_non_named_admin").counter()).isNull();
    } finally {
      stopLogCapture(appender);
    }
  }

  /** RES-17/RC-20.4 (A-2): {@code assign()}'s half -- recorded on every privileged assign. */
  @Test
  void should_recordLockSetSizeDistributionSummary_when_assigningPrivilegedRole() {
    Role role = customRole("BILLING_ADMIN");
    UUID adminRoleId = UUID.randomUUID();
    Instant assignedAt = Instant.now();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(targetUserId, roleId, "BILLING_ADMIN", assignedAt, actorId);
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId)).thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(UUID.randomUUID(), actorId, adminRoleId),
                new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), roleId)));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(adminRoleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(targetUserId, roleId, tenantId, actorId))
        .thenReturn(UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveAssignmentView(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(view));

    service.assign(actor, targetUserId, roleId, ctx);

    DistributionSummary summary =
        meterRegistry.find("nexus.rbac.admin_equivalent_lock_set_size").summary();
    assertThat(summary).isNotNull();
    assertThat(summary.count()).isEqualTo(1L);
    assertThat(summary.totalAmount()).isEqualTo(2.0);
  }

  /** RES-17/RC-20.4 (A-2): {@code revoke()}'s half -- recorded on every privileged revoke too. */
  @Test
  void should_recordLockSetSizeDistributionSummary_when_revokingPrivilegedRole() {
    UUID refId = UUID.randomUUID();
    Role role = adminRole("TENANT_ADMIN");
    when(userDirectoryPort.findTenantId(targetUserId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findActiveAssignmentRef(targetUserId, roleId, tenantId))
        .thenReturn(Optional.of(new ActiveAssignmentRef(refId, Instant.now())));
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), roleId),
                new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), roleId)));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.revoke(eq(refId), any())).thenReturn(1);

    service.revoke(actor, targetUserId, roleId, ctx);

    DistributionSummary summary =
        meterRegistry.find("nexus.rbac.admin_equivalent_lock_set_size").summary();
    assertThat(summary).isNotNull();
    assertThat(summary.count()).isEqualTo(1L);
    assertThat(summary.totalAmount()).isEqualTo(3.0);
  }

  /**
   * US-017 D24/RC-17.1, A-3/MC-H: the re-derived canary's self-assignment success path via the
   * {@code ALL_DANGEROUS_PERMISSIONS} route (the gate's success test above already covers the
   * {@code ROLE_NAME} route via name-match). Proves {@code callerHoldsActiveAdminEquivalentRole}
   * answers from M12 (a distinct, user-scoped read, driven by a DIFFERENT role than the target --
   * {@code fullyRoleId} vs. {@code roleId} -- and a DIFFERENT role name, "SUPER_CUSTOM") and that
   * the gate's own M10 read is invoked exactly once, never doubled by the canary.
   */
  @Test
  void should_tagCallerIsAdminTrueViaM12_when_actorSelfAssignsDangerousRoleAndHoldsFullyAdminEquivalentCustomRole() {
    Role role = customRole("BILLING_ADMIN");
    UUID fullyRoleId = UUID.randomUUID();
    Instant assignedAt = Instant.now();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(actorId, roleId, "BILLING_ADMIN", assignedAt, actorId);
    when(userDirectoryPort.findTenantId(actorId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findPermissionNamesForRole(roleId)).thenReturn(List.of("user:write"));
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(
            List.of(
                new RolePermissionName(fullyRoleId, "role:write"),
                new RolePermissionName(fullyRoleId, "user:write"),
                new RolePermissionName(fullyRoleId, "tenant:write")));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN")).thenReturn(Optional.empty());
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(fullyRoleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(actorId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(actorId, roleId, tenantId, actorId)).thenReturn(UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveAssignmentView(actorId, roleId, tenantId))
        .thenReturn(Optional.of(view));
    // M12: the canary's OWN, distinct read -- the caller's own active assignment of the SAME
    // fully-dangerous custom role, under a DIFFERENT role name than the target role.
    when(userRoleAssignmentPort.findActiveAssignmentViews(actorId, tenantId))
        .thenReturn(
            List.of(new ActiveRoleAssignment(actorId, fullyRoleId, "SUPER_CUSTOM", assignedAt, actorId)));
    when(userRoleAssignmentPort.findPermissionNamesForActiveAssignmentsOfUser(actorId, tenantId))
        .thenReturn(
            List.of(
                new RolePermissionName(fullyRoleId, "role:write"),
                new RolePermissionName(fullyRoleId, "user:write"),
                new RolePermissionName(fullyRoleId, "tenant:write")));

    ActiveRoleAssignment result = service.assign(actor, actorId, roleId, ctx);

    assertThat(result).isEqualTo(view);
    Counter counter =
        meterRegistry
            .find("nexus.rbac.self_role_assignment")
            .tags("tenantId", tenantId.toString(), "privileged", "true", "callerIsAdmin", "true")
            .counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);

    // A-3/MC-H: the canary's M12-derived answer must come from a DISTINCT port call from the
    // gate's M10-derived set -- exactly one M10 call (the gate's), and a separate M12 call
    // (the canary's own).
    verify(userRoleAssignmentPort, times(1)).findPermissionNamesForTenantRoles(tenantId);
    verify(userRoleAssignmentPort).findPermissionNamesForActiveAssignmentsOfUser(actorId, tenantId);
  }

  /**
   * M-1 regression (07-security-review.md, 2026-09-24): the canary's M4/M12 reads
   * ({@code callerHoldsActiveAdminEquivalentRole}) MUST happen BEFORE the INSERT, never after.
   * Reading them post-commit meant that, on a self-assignment of a role that is itself fully
   * admin-equivalent, the read would see the row this very request just created, making
   * {@code callerIsAdmin=true} unconditionally reachable and {@code callerIsAdmin=false}
   * structurally UNREACHABLE for exactly the highest-severity target -- the one case the canary
   * most needs to catch a gate bypass for. This is an ordering proof: Mockito's stubbed return
   * values are the same regardless of call order, so only an {@link InOrder} verification can
   * distinguish the fixed code from the pre-fix code.
   */
  @Test
  void should_readCanaryStateBeforeTheInsert_notAfter_when_selfAssigningATenantAdminRole_M1() {
    Role role = adminRole("TENANT_ADMIN");
    Instant assignedAt = Instant.now();
    UUID userRoleId = UUID.randomUUID();
    ActiveRoleAssignment view =
        new ActiveRoleAssignment(actorId, roleId, "TENANT_ADMIN", assignedAt, actorId);

    when(userDirectoryPort.findTenantId(actorId)).thenReturn(Optional.of(tenantId));
    when(userRoleAssignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN")).thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
        .thenReturn(true);
    when(userRoleAssignmentPort.hasActiveAssignment(actorId, roleId)).thenReturn(false);
    when(userRoleAssignmentPort.assign(actorId, roleId, tenantId, actorId)).thenReturn(userRoleId);
    when(userRoleAssignmentPort.findActiveAssignmentView(actorId, roleId, tenantId))
        .thenReturn(Optional.of(view));
    // Caller held NOTHING before this request -- the realistic pre-insert state for an actor
    // whose only qualifying assignment is the one this very call is about to create.
    when(userRoleAssignmentPort.findActiveAssignmentViews(actorId, tenantId)).thenReturn(List.of());

    service.assign(actor, actorId, roleId, ctx);

    InOrder inOrder = Mockito.inOrder(userRoleAssignmentPort);
    inOrder.verify(userRoleAssignmentPort).findActiveAssignmentViews(actorId, tenantId);
    inOrder.verify(userRoleAssignmentPort).assign(actorId, roleId, tenantId, actorId);

    // The pre-insert read correctly found nothing, so the canary must report false even though
    // the row this request itself created (a literal TENANT_ADMIN) would make a POST-insert read
    // report true -- proving the fix, not merely the wiring.
    Counter counter =
        meterRegistry
            .find("nexus.rbac.self_role_assignment")
            .tags("tenantId", tenantId.toString(), "privileged", "true", "callerIsAdmin", "false")
            .counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
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
    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), any(), any());
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

    // Throttled at check 3.5, before nameMatch/privileged is even computed -- neither the lock
    // nor the gate is ever reached.
    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(userRoleAssignmentPort, never()).findPermissionNamesForRole(any());
    verify(userRoleAssignmentPort, never()).findRoleIdByName(any(), any());
    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), any(), any());
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(refId, targetUserId, roleId),
                new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID())));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(roleId));
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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
    when(userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(actorId, List.of(roleId), tenantId))
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

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(userRoleAssignmentPort, never()).findRoleIdByName(any(), any());
    verify(userRoleAssignmentPort, never()).hasActiveAssignmentOfAnyRole(any(), any(), any());
    verify(userRoleAssignmentPort, never()).revoke(any(), any());
    verifyNoInteractions(rbacAuditPort);
  }

  // ---------------------------------------------------------------------------------------
  // resolveAdminEquivalentRoles (T-001(f)) — private, no caller until T-002/T-003; exercised via
  // reflection rather than by widening its visibility (03-design.md §7.2).
  // ---------------------------------------------------------------------------------------

  private RoleAssignmentService.AdminEquivalentRoles invokeResolveAdminEquivalentRoles(
      Role targetRole, boolean nameMatch) throws Exception {
    Method method =
        RoleAssignmentService.class.getDeclaredMethod(
            "resolveAdminEquivalentRoles", UUID.class, Role.class, boolean.class);
    method.setAccessible(true);
    return (RoleAssignmentService.AdminEquivalentRoles)
        method.invoke(service, tenantId, targetRole, nameMatch);
  }

  @Test
  void should_returnEmptySetsAndEmptyNamedAdminRoleId_when_tenantHasNoAdminEquivalentRoles()
      throws Exception {
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(List.of());
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.empty());

    RoleAssignmentService.AdminEquivalentRoles roles =
        invokeResolveAdminEquivalentRoles(customRole("CUSTOM"), false);

    assertThat(roles.adminEquivalentIds()).isEmpty();
    assertThat(roles.fullyAdminEquivalentIds()).isEmpty();
    assertThat(roles.namedAdminRoleId()).isEmpty();
  }

  @Test
  void should_populateAdminEquivalentIdsOnly_when_tenantHasOneRoleCarryingASingleDangerousPermission()
      throws Exception {
    UUID dangerousRoleId = UUID.randomUUID();
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(List.of(new RolePermissionName(dangerousRoleId, "user:write")));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.empty());

    RoleAssignmentService.AdminEquivalentRoles roles =
        invokeResolveAdminEquivalentRoles(customRole("CUSTOM"), false);

    assertThat(roles.adminEquivalentIds()).containsExactly(dangerousRoleId);
    assertThat(roles.fullyAdminEquivalentIds()).isEmpty();
  }

  @Test
  void should_populateBothAdminEquivalentAndFullyAdminEquivalentIds_when_tenantHasOneRoleCarryingAllThreeDangerousPermissions()
      throws Exception {
    UUID fullyDangerousRoleId = UUID.randomUUID();
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(
            List.of(
                new RolePermissionName(fullyDangerousRoleId, "role:write"),
                new RolePermissionName(fullyDangerousRoleId, "user:write"),
                new RolePermissionName(fullyDangerousRoleId, "tenant:write")));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.empty());

    RoleAssignmentService.AdminEquivalentRoles roles =
        invokeResolveAdminEquivalentRoles(customRole("CUSTOM"), false);

    assertThat(roles.adminEquivalentIds()).containsExactly(fullyDangerousRoleId);
    assertThat(roles.fullyAdminEquivalentIds()).containsExactly(fullyDangerousRoleId);
  }

  @Test
  void should_populateNamedAdminRoleId_when_tenantAdminRoleExistsByName() throws Exception {
    UUID namedAdminRoleId = UUID.randomUUID();
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(List.of());
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(namedAdminRoleId));

    RoleAssignmentService.AdminEquivalentRoles roles =
        invokeResolveAdminEquivalentRoles(adminRole("TENANT_ADMIN"), true);

    assertThat(roles.namedAdminRoleId()).contains(namedAdminRoleId);
  }

  @Test
  void should_returnEmptyNamedAdminRoleId_when_tenantAdminRoleDoesNotExist() throws Exception {
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(List.of());
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.empty());

    RoleAssignmentService.AdminEquivalentRoles roles =
        invokeResolveAdminEquivalentRoles(customRole("CUSTOM"), false);

    assertThat(roles.namedAdminRoleId()).isEmpty();
  }

  @Test
  void should_callPortExactlyOnceForM10AndOnceForM8_when_resolvingAdminEquivalentRoles()
      throws Exception {
    when(userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId))
        .thenReturn(List.of(new RolePermissionName(UUID.randomUUID(), "user:write")));
    when(userRoleAssignmentPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.empty());

    invokeResolveAdminEquivalentRoles(customRole("CUSTOM"), false);

    verify(userRoleAssignmentPort, times(1)).findPermissionNamesForTenantRoles(tenantId);
    verify(userRoleAssignmentPort, times(1)).findRoleIdByName(tenantId, "TENANT_ADMIN");
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
