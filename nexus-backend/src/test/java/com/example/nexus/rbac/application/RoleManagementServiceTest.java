package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
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
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.RoleAuditEvent;
import com.example.nexus.rbac.application.port.out.RoleManagementPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.DuplicateRoleNameException;
import com.example.nexus.rbac.domain.DuplicateRolePermissionException;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.ReservedRoleNameException;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleLimitExceededException;
import com.example.nexus.rbac.domain.RoleView;
import com.example.nexus.rbac.domain.SystemRoleImmutableException;
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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

/**
 * Unit tests for {@link RoleManagementService} (03-design.md §4.2, §8.6). Covers AC1-AC9/AC11 and
 * every error branch: RC-1 (reserved names), RC-4 (per-tenant cap), the §8.6-pinned check
 * ordering, AC7's MEMBER coverage (RC-5b), and AC11's F1/T-E14 non-locking-read trap (verified at
 * the collaborator level as defense in depth ahead of T-007's ArchUnit rule).
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class RoleManagementServiceTest {

  private static final long MAX_ROLES_PER_TENANT = 500L;
  private static final String ROLE_WRITE = "role:write";
  private static final String ROLE_READ = "role:read";

  @Mock private RoleManagementPort roleManagementPort;
  @Mock private UserRoleAssignmentPort userRoleAssignmentPort;
  @Mock private RbacAuditPort rbacAuditPort;

  private SimpleMeterRegistry meterRegistry;
  private RoleManagementService service;

  private UUID actorId;
  private UUID tenantId;
  private UUID otherTenantId;
  private UUID roleId;
  private UUID permissionId;
  private RoleChangeActor actor;
  private RequestContext ctx;

  @BeforeEach
  void setUp() {
    meterRegistry = new SimpleMeterRegistry();
    service =
        new RoleManagementService(
            roleManagementPort,
            userRoleAssignmentPort,
            rbacAuditPort,
            meterRegistry,
            MAX_ROLES_PER_TENANT);

    actorId = UUID.randomUUID();
    tenantId = UUID.randomUUID();
    otherTenantId = UUID.randomUUID();
    roleId = UUID.randomUUID();
    permissionId = UUID.randomUUID();
    actor = new RoleChangeActor(actorId, tenantId);
    ctx = RequestContext.UNKNOWN;
  }

  private RoleView customRole(UUID tenant) {
    return new RoleView(roleId, tenant, "Custom Role", "desc", false, Instant.now());
  }

  private RoleView systemRole(String name) {
    return new RoleView(roleId, tenantId, name, "desc", true, Instant.now());
  }

  private PermissionView dangerousPermission() {
    return new PermissionView(permissionId, "role:write", "Manage roles");
  }

  private PermissionView benignPermission() {
    return new PermissionView(permissionId, "user:read", "Read users");
  }

  // ---------------------------------------------------------------------------------------
  // createRole() -- AC1, AC9, AC12, RC-1, RC-4
  // ---------------------------------------------------------------------------------------

  @Test
  void should_createRoleAndReturnView_when_happyPath() {
    UUID newRoleId = UUID.randomUUID();
    RoleView created = new RoleView(newRoleId, tenantId, "Support", "desc", false, Instant.now());
    when(roleManagementPort.countRolesInTenant(tenantId)).thenReturn(1L);
    when(roleManagementPort.createRole(tenantId, "Support", "desc")).thenReturn(newRoleId);
    when(roleManagementPort.findRole(newRoleId)).thenReturn(Optional.of(created));

    RoleView result = service.createRole(actor, "Support", "desc", ctx);

    assertThat(result).isEqualTo(created);
  }

  @Test
  void should_throwReservedRoleNameException_when_nameMatchesTenantAdminCaseInsensitive() {
    assertThatThrownBy(() -> service.createRole(actor, "tenant_admin", "desc", ctx))
        .isInstanceOf(ReservedRoleNameException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_007");

    verifyNoInteractions(roleManagementPort, rbacAuditPort);
  }

  @Test
  void should_throwReservedRoleNameException_when_nameMatchesMemberCaseInsensitive() {
    assertThatThrownBy(() -> service.createRole(actor, "Member", "desc", ctx))
        .isInstanceOf(ReservedRoleNameException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_007");

    verifyNoInteractions(roleManagementPort, rbacAuditPort);
  }

  @Test
  void should_notQueryRoleCount_when_nameIsReserved() {
    assertThatThrownBy(() -> service.createRole(actor, "TENANT_ADMIN", "desc", ctx))
        .isInstanceOf(ReservedRoleNameException.class);

    verify(roleManagementPort, never()).countRolesInTenant(any());
  }

  @Test
  void should_throwRoleLimitExceededException_when_countAtConfiguredMax() {
    when(roleManagementPort.countRolesInTenant(tenantId)).thenReturn(MAX_ROLES_PER_TENANT);

    assertThatThrownBy(() -> service.createRole(actor, "Support", "desc", ctx))
        .isInstanceOf(RoleLimitExceededException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_008");

    verify(roleManagementPort, never()).createRole(any(), any(), any());
  }

  @Test
  void should_allowCreation_when_countBelowConfiguredMax() {
    UUID newRoleId = UUID.randomUUID();
    RoleView created = new RoleView(newRoleId, tenantId, "Support", "desc", false, Instant.now());
    when(roleManagementPort.countRolesInTenant(tenantId)).thenReturn(MAX_ROLES_PER_TENANT - 1);
    when(roleManagementPort.createRole(tenantId, "Support", "desc")).thenReturn(newRoleId);
    when(roleManagementPort.findRole(newRoleId)).thenReturn(Optional.of(created));

    RoleView result = service.createRole(actor, "Support", "desc", ctx);

    assertThat(result).isEqualTo(created);
  }

  @Test
  void should_propagateDuplicateRoleNameException_when_portThrowsOnInsert() {
    when(roleManagementPort.countRolesInTenant(tenantId)).thenReturn(1L);
    when(roleManagementPort.createRole(tenantId, "Support", "desc"))
        .thenThrow(new DuplicateRoleNameException());

    assertThatThrownBy(() -> service.createRole(actor, "Support", "desc", ctx))
        .isInstanceOf(DuplicateRoleNameException.class);
  }

  @Test
  void should_reReadCreatedRoleForDbGeneratedCreatedAt_when_insertSucceeds() {
    UUID newRoleId = UUID.randomUUID();
    RoleView created = new RoleView(newRoleId, tenantId, "Support", "desc", false, Instant.now());
    when(roleManagementPort.countRolesInTenant(tenantId)).thenReturn(1L);
    when(roleManagementPort.createRole(tenantId, "Support", "desc")).thenReturn(newRoleId);
    when(roleManagementPort.findRole(newRoleId)).thenReturn(Optional.of(created));

    service.createRole(actor, "Support", "desc", ctx);

    verify(roleManagementPort).findRole(newRoleId);
  }

  @Test
  void should_recordAuditAndLogWithoutCounter_when_created() {
    UUID newRoleId = UUID.randomUUID();
    RoleView created = new RoleView(newRoleId, tenantId, "Support", "desc", false, Instant.now());
    when(roleManagementPort.countRolesInTenant(tenantId)).thenReturn(1L);
    when(roleManagementPort.createRole(tenantId, "Support", "desc")).thenReturn(newRoleId);
    when(roleManagementPort.findRole(newRoleId)).thenReturn(Optional.of(created));

    service.createRole(actor, "Support", "desc", ctx);

    verify(rbacAuditPort)
        .recordRoleCreated(
            new RoleAuditEvent(tenantId, newRoleId, "Support", null, null, actorId, ctx));
    assertThat(meterRegistry.find("nexus.rbac.dangerous_permission_granted").counter()).isNull();
  }

  // ---------------------------------------------------------------------------------------
  // listRoles() -- AC2
  // ---------------------------------------------------------------------------------------

  @Test
  void should_returnEmptyList_when_noRolesInTenant() {
    when(roleManagementPort.findRolesInTenant(tenantId)).thenReturn(List.of());

    assertThat(service.listRoles(actor)).isEmpty();
  }

  @Test
  void should_returnRolesFromPort_when_rolesExist() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRolesInTenant(tenantId)).thenReturn(List.of(role));

    assertThat(service.listRoles(actor)).containsExactly(role);
  }

  // ---------------------------------------------------------------------------------------
  // listRolePermissions() -- AC3, AC8
  // ---------------------------------------------------------------------------------------

  @Test
  void should_returnPermissions_when_roleExistsInTenant() {
    RoleView role = customRole(tenantId);
    PermissionView permission = benignPermission();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermissionsForRole(roleId)).thenReturn(List.of(permission));

    assertThat(service.listRolePermissions(actor, roleId)).containsExactly(permission);
  }

  @Test
  void should_returnEmptyList_when_roleHasNoPermissionsAttached() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermissionsForRole(roleId)).thenReturn(List.of());

    assertThat(service.listRolePermissions(actor, roleId)).isEmpty();
  }

  @Test
  void should_throwResourceNotFound_when_listPermissionsRoleDoesNotExist() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.listRolePermissions(actor, roleId))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");
  }

  @Test
  void should_throwInsufficientPermission_when_listPermissionsRoleInAnotherTenant() {
    RoleView role = customRole(otherTenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));

    assertThatThrownBy(() -> service.listRolePermissions(actor, roleId))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.CROSS_TENANT_TARGET));

    verify(roleManagementPort, never()).findPermissionsForRole(any());
  }

  // ---------------------------------------------------------------------------------------
  // attachPermission() -- AC4, AC7, AC8, AC11, AC12
  // ---------------------------------------------------------------------------------------

  @Test
  void should_attachPermissionAndReturnView_when_happyPathNonDangerous() {
    RoleView role = customRole(tenantId);
    PermissionView permission = benignPermission();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId)).thenReturn(Optional.of(permission));
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(false);

    PermissionView result = service.attachPermission(actor, roleId, permissionId, ctx);

    assertThat(result).isEqualTo(permission);
    verify(roleManagementPort).attachPermission(roleId, permissionId);
    verifyNoInteractions(userRoleAssignmentPort);
  }

  @Test
  void should_attachDangerousPermissionAndIncrementCounter_when_callerIsActiveAdmin() {
    RoleView role = customRole(tenantId);
    PermissionView permission = dangerousPermission();
    UUID adminRoleId = UUID.randomUUID();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId)).thenReturn(Optional.of(permission));
    when(roleManagementPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(true);
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(false);

    PermissionView result = service.attachPermission(actor, roleId, permissionId, ctx);

    assertThat(result).isEqualTo(permission);
    verify(roleManagementPort).attachPermission(roleId, permissionId);
    Counter counter = meterRegistry.find("nexus.rbac.dangerous_permission_granted").counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
  }

  @Test
  void should_throwResourceNotFound_when_attachRoleDoesNotExist() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");

    verifyNoInteractions(rbacAuditPort);
  }

  @Test
  void should_throwInsufficientPermission_when_attachRoleInAnotherTenant() {
    RoleView role = customRole(otherTenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.CROSS_TENANT_TARGET));

    verify(roleManagementPort, never()).findPermission(any());
  }

  /** Pins §8.6 rule 1: tenant resolution always before AC7, even when the role is also a system role. */
  @Test
  void should_orderTenantCheckBeforeAc7_when_roleIsCrossTenantSystemRole() {
    RoleView foreignSystemRole =
        new RoleView(roleId, otherTenantId, "TENANT_ADMIN", "desc", true, Instant.now());
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(foreignSystemRole));

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.CROSS_TENANT_TARGET));
  }

  @Test
  void should_throwSystemRoleImmutableException_when_attachRoleIsTenantAdmin() {
    RoleView role = systemRole("TENANT_ADMIN");
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(SystemRoleImmutableException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_003");
  }

  @Test
  void should_logWarnWithSystemRoleMutationBlocked_when_attachRoleIsTenantAdmin() {
    RoleView role = systemRole("TENANT_ADMIN");
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
          .isInstanceOf(SystemRoleImmutableException.class);

      var warnEvents = appender.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
      assertThat(warnEvents).hasSize(1);
      assertThat(keyValueMap(warnEvents.get(0)))
          .containsEntry("event", "RBAC_SYSTEM_ROLE_MUTATION_BLOCKED")
          .containsEntry("roleId", roleId);
    } finally {
      stopLogCapture(appender);
    }
  }

  /** RC-5b named case: MEMBER is AC7's sole gate against a dangerous-permission attach. */
  @Test
  void should_throwSystemRoleImmutableException_when_attachRoleIsMember() {
    RoleView role = systemRole("MEMBER");
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(SystemRoleImmutableException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_003");

    verify(roleManagementPort, never()).findPermission(any());
    verifyNoInteractions(userRoleAssignmentPort);
  }

  @Test
  void should_notCallFindPermission_when_ac7Blocks() {
    RoleView role = systemRole("TENANT_ADMIN");
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(SystemRoleImmutableException.class);

    verify(roleManagementPort, never()).findPermission(any());
  }

  @Test
  void should_throwResourceNotFound_when_attachPermissionDoesNotExist() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "PERMISSION_NOT_FOUND");

    verifyNoInteractions(userRoleAssignmentPort);
  }

  @Test
  void should_notInvokeAc11Gate_when_permissionIsNotDangerous() {
    RoleView role = customRole(tenantId);
    PermissionView permission = benignPermission();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId)).thenReturn(Optional.of(permission));
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(false);

    service.attachPermission(actor, roleId, permissionId, ctx);

    verify(roleManagementPort, never()).findRoleIdByName(any(), any());
    verifyNoInteractions(userRoleAssignmentPort);
  }

  @Test
  void should_throwNotTenantAdmin_when_noAdminRoleSeededInTenant() {
    RoleView role = customRole(tenantId);
    PermissionView permission = dangerousPermission();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId)).thenReturn(Optional.of(permission));
    when(roleManagementPort.findRoleIdByName(tenantId, "TENANT_ADMIN")).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

    verify(userRoleAssignmentPort, never()).hasActiveAdminAssignment(any(), any(), any());
    verify(roleManagementPort, never()).attachPermission(any(), any());
  }

  @Test
  void should_throwNotTenantAdmin_when_callerNotActiveAdmin() {
    RoleView role = customRole(tenantId);
    PermissionView permission = dangerousPermission();
    UUID adminRoleId = UUID.randomUUID();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId)).thenReturn(Optional.of(permission));
    when(roleManagementPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(false);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
          .isInstanceOf(InsufficientPermissionException.class)
          .satisfies(
              e ->
                  assertThat(((InsufficientPermissionException) e).getReason())
                      .isEqualTo(DenialReason.NOT_TENANT_ADMIN));

      var warnEvents = appender.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
      assertThat(warnEvents).hasSize(1);
      assertThat(keyValueMap(warnEvents.get(0)))
          .containsEntry("event", "RBAC_DANGEROUS_PERMISSION_ATTACH_BLOCKED");
    } finally {
      stopLogCapture(appender);
    }

    // F1/T-E14 defense in depth: the forbidden non-locking shortcut is never reached.
    verify(userRoleAssignmentPort, never()).findActiveAssignmentViews(any(), any());
    verify(roleManagementPort, never()).attachPermission(any(), any());
  }

  @Test
  void should_throwDuplicateRolePermissionException_when_alreadyAttached() {
    RoleView role = customRole(tenantId);
    PermissionView permission = benignPermission();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId)).thenReturn(Optional.of(permission));
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(true);

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(DuplicateRolePermissionException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_005");

    verify(roleManagementPort, never()).attachPermission(any(), any());
  }

  @Test
  void should_propagateDuplicateRolePermissionException_when_portThrowsOnConcurrentAttach() {
    RoleView role = customRole(tenantId);
    PermissionView permission = benignPermission();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId)).thenReturn(Optional.of(permission));
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(false);
    doThrow(new DuplicateRolePermissionException())
        .when(roleManagementPort)
        .attachPermission(roleId, permissionId);

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(DuplicateRolePermissionException.class);
  }

  @Test
  void should_recordAuditWithDangerousFlagTrue_when_dangerousPermissionGranted() {
    RoleView role = customRole(tenantId);
    PermissionView permission = dangerousPermission();
    UUID adminRoleId = UUID.randomUUID();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId)).thenReturn(Optional.of(permission));
    when(roleManagementPort.findRoleIdByName(tenantId, "TENANT_ADMIN"))
        .thenReturn(Optional.of(adminRoleId));
    when(userRoleAssignmentPort.hasActiveAdminAssignment(actorId, adminRoleId, tenantId))
        .thenReturn(true);
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(false);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.attachPermission(actor, roleId, permissionId, ctx);

      verify(rbacAuditPort)
          .recordRolePermissionGranted(
              new RoleAuditEvent(
                  tenantId, roleId, role.name(), permissionId, "role:write", actorId, ctx));

      var infoEvents = appender.list.stream().filter(e -> e.getLevel() == Level.INFO).toList();
      assertThat(infoEvents).hasSize(1);
      assertThat(keyValueMap(infoEvents.get(0)))
          .containsEntry("event", "ROLE_PERMISSION_GRANTED")
          .containsEntry("dangerous", true);
    } finally {
      stopLogCapture(appender);
    }
  }

  @Test
  void should_recordAuditWithoutIncrementingCounter_when_nonDangerousPermissionGranted() {
    RoleView role = customRole(tenantId);
    PermissionView permission = benignPermission();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId)).thenReturn(Optional.of(permission));
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(false);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.attachPermission(actor, roleId, permissionId, ctx);

      var infoEvents = appender.list.stream().filter(e -> e.getLevel() == Level.INFO).toList();
      assertThat(keyValueMap(infoEvents.get(0))).containsEntry("dangerous", false);
    } finally {
      stopLogCapture(appender);
    }

    assertThat(meterRegistry.find("nexus.rbac.dangerous_permission_granted").counter()).isNull();
  }

  // ---------------------------------------------------------------------------------------
  // detachPermission() -- AC5, AC7, AC8, AC12
  // ---------------------------------------------------------------------------------------

  @Test
  void should_detachPermissionAndCompleteSuccessfully_when_happyPath() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.detachPermission(roleId, permissionId)).thenReturn(1);
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));

    service.detachPermission(actor, roleId, permissionId, ctx);

    verify(roleManagementPort).detachPermission(roleId, permissionId);
  }

  @Test
  void should_throwResourceNotFound_when_detachRoleDoesNotExist() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");
  }

  @Test
  void should_throwInsufficientPermission_when_detachRoleInAnotherTenant() {
    RoleView role = customRole(otherTenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.CROSS_TENANT_TARGET));
  }

  @Test
  void should_throwSystemRoleImmutableException_when_detachRoleIsTenantAdmin() {
    RoleView role = systemRole("TENANT_ADMIN");
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(SystemRoleImmutableException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_003");
  }

  /** RC-5b named case: detaching user:read from MEMBER would strip read access tenant-wide. */
  @Test
  void should_throwSystemRoleImmutableException_when_detachRoleIsMember() {
    RoleView role = systemRole("MEMBER");
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(SystemRoleImmutableException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_003");

    verify(roleManagementPort, never()).detachPermission(any(), any());
  }

  @Test
  void should_notCallDetachOnPort_when_ac7Blocks() {
    RoleView role = systemRole("TENANT_ADMIN");
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(SystemRoleImmutableException.class);

    verify(roleManagementPort, never()).detachPermission(any(), any());
    verifyNoInteractions(rbacAuditPort);
  }

  @Test
  void should_throwResourceNotFound_when_pairingWasNeverAttachedOrAlreadyDetached() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.detachPermission(roleId, permissionId)).thenReturn(0);

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_PERMISSION_NOT_FOUND");

    verify(roleManagementPort, never()).findPermission(any());
    verifyNoInteractions(rbacAuditPort);
  }

  /** Deliberate asymmetry (§3.3): detaching a dangerous permission has NO AC11 gate. */
  @Test
  void should_notGateOnAc11_when_detachingDangerousPermission() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.detachPermission(roleId, permissionId)).thenReturn(1);
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(dangerousPermission()));

    service.detachPermission(actor, roleId, permissionId, ctx);

    verify(roleManagementPort, never()).findRoleIdByName(any(), any());
    verifyNoInteractions(userRoleAssignmentPort);
  }

  @Test
  void should_recordAuditWithPermissionName_when_detached() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.detachPermission(roleId, permissionId)).thenReturn(1);
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));

    service.detachPermission(actor, roleId, permissionId, ctx);

    verify(rbacAuditPort)
        .recordRolePermissionRevoked(
            new RoleAuditEvent(
                tenantId, roleId, role.name(), permissionId, "user:read", actorId, ctx));
  }

  @Test
  void should_logWithoutDangerousKey_when_revoked() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.detachPermission(roleId, permissionId)).thenReturn(1);
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.detachPermission(actor, roleId, permissionId, ctx);

      var infoEvents = appender.list.stream().filter(e -> e.getLevel() == Level.INFO).toList();
      assertThat(infoEvents).hasSize(1);
      Map<String, Object> keyValues = keyValueMap(infoEvents.get(0));
      assertThat(keyValues).containsEntry("event", "ROLE_PERMISSION_REVOKED");
      assertThat(keyValues).doesNotContainKey("dangerous");
    } finally {
      stopLogCapture(appender);
    }
  }

  // ---------------------------------------------------------------------------------------
  // listAllPermissions() -- AC6
  // ---------------------------------------------------------------------------------------

  @Test
  void should_returnAllPermissionsFromPort_when_called() {
    PermissionView permission = benignPermission();
    when(roleManagementPort.findAllPermissions()).thenReturn(List.of(permission));

    assertThat(service.listAllPermissions()).containsExactly(permission);
  }

  // ---------------------------------------------------------------------------------------
  // Test infrastructure
  // ---------------------------------------------------------------------------------------

  private ListAppender<ILoggingEvent> startLogCapture() {
    Logger logger = (Logger) LoggerFactory.getLogger(RoleManagementService.class);
    ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);
    return listAppender;
  }

  private void stopLogCapture(ListAppender<ILoggingEvent> listAppender) {
    Logger logger = (Logger) LoggerFactory.getLogger(RoleManagementService.class);
    logger.detachAppender(listAppender);
    listAppender.stop();
  }

  private static Map<String, Object> keyValueMap(ILoggingEvent event) {
    Map<String, Object> map = new HashMap<>();
    event.getKeyValuePairs().forEach(kv -> map.put(kv.key, kv.value));
    return map;
  }
}
