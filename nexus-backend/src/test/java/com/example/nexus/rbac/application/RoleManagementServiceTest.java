package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
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
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.RoleAuditEvent;
import com.example.nexus.rbac.application.port.out.RoleManagementPort;
import com.example.nexus.rbac.application.port.out.RoleUpdateAuditEvent;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.AttachProvenanceConflictException;
import com.example.nexus.rbac.domain.DuplicateRoleNameException;
import com.example.nexus.rbac.domain.DuplicateRolePermissionException;
import com.example.nexus.rbac.domain.HolderProvenance;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.ReservedRoleNameException;
import com.example.nexus.rbac.domain.RoleHasHoldersException;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermissionRef;
import com.example.nexus.rbac.domain.RoleLimitExceededException;
import com.example.nexus.rbac.domain.RoleView;
import com.example.nexus.rbac.domain.SystemRoleImmutableException;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

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
  private static final UUID ROLE_WRITE_ID = RbacSeededPermissionIds.ROLE_WRITE;
  private static final UUID USER_ROLE_ASSIGN_ID = RbacSeededPermissionIds.USER_ROLE_ASSIGN;

  // Fixture catalogue: two permissions. A role carrying both is admin-defining (ADR-0021 D3).
  private static final UUID P1 = UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final UUID P2 = UUID.fromString("00000000-0000-7000-8000-000000000002");
  private static final Set<UUID> CATALOGUE = Set.of(P1, P2);

  @Mock private RoleManagementPort roleManagementPort;
  @Mock private UserRoleAssignmentPort userRoleAssignmentPort;
  @Mock private RbacAuditPort rbacAuditPort;
  @Mock private PermissionFreshnessService permissionFreshness;
  @Mock private PermissionCachePort permissionCachePort;
  @Mock private PlatformTransactionManager transactionManager;

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
            permissionFreshness,
            permissionCachePort,
            transactionManager,
            meterRegistry,
            MAX_ROLES_PER_TENANT);

    actorId = UUID.randomUUID();
    tenantId = UUID.randomUUID();
    otherTenantId = UUID.randomUUID();
    roleId = UUID.randomUUID();
    permissionId = UUID.randomUUID();
    actor = new RoleChangeActor(actorId, tenantId);
    ctx = RequestContext.UNKNOWN;

    // Baseline (lenient; any test may override): the role is in the tenant and carries no
    // permissions, and the catalogue is the two-permission fixture.
    lenient()
        .when(userRoleAssignmentPort.findPermissionIdsForRole(any(), any()))
        .thenReturn(Optional.of(Set.of()));
    lenient().when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(CATALOGUE);
  }

  private RoleView customRole(UUID tenant) {
    return new RoleView(roleId, tenant, "Custom Role", "desc", false, Instant.now());
  }

  private RoleView systemRole(String name) {
    return new RoleView(roleId, tenantId, name, "desc", true, Instant.now());
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
            new RoleAuditEvent(tenantId, newRoleId, "Support", null, null, actorId, ctx, null));
    assertThat(meterRegistry.find("nexus.rbac.dangerous_permission_granted").counter()).isNull();
  }

  // ---------------------------------------------------------------------------------------
  // listRoles() -- AC2
  // ---------------------------------------------------------------------------------------

  @Test
  void should_returnAnEmptyPage_when_noRolesInTenant() {
    when(roleManagementPort.findRolesInTenant(tenantId, 0, 20))
        .thenReturn(new PageResult<>(List.of(), 0, 0, 20));

    PageResult<RoleView> result = service.listRoles(actor, 0, 20);

    assertThat(result.items()).isEmpty();
    assertThat(result.totalPages()).isZero();
  }

  @Test
  void should_returnTheRequestedPageFromPort_when_rolesExist() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRolesInTenant(tenantId, 2, 5))
        .thenReturn(new PageResult<>(List.of(role), 11, 2, 5));

    PageResult<RoleView> result = service.listRoles(actor, 2, 5);

    assertThat(result.items()).containsExactly(role);
    assertThat(result.totalElements()).isEqualTo(11);
    assertThat(result.totalPages()).isEqualTo(3);
  }

  /** The tenant comes from the actor (the JWT), never from the call's other arguments. */
  @Test
  void should_scopeTheRolePageToTheActorsTenant_when_listing() {
    when(roleManagementPort.findRolesInTenant(any(), eq(0), eq(20)))
        .thenReturn(new PageResult<>(List.of(), 0, 0, 20));

    service.listRoles(actor, 0, 20);

    verify(roleManagementPort).findRolesInTenant(tenantId, 0, 20);
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
  void should_throwSameRoleNotFound_when_listPermissionsRoleInAnotherTenant() {
    RoleView role = customRole(otherTenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));

    assertThatThrownBy(() -> service.listRolePermissions(actor, roleId))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND")
        .hasMessage("No such role");

    verify(roleManagementPort, never()).findPermissionsForRole(any());
    verifyNoInteractions(rbacAuditPort);
    assertThat(
            meterRegistry
                .get("nexus.rbac.permission_denied")
                .tag("permission", "role:read")
                .tag("reason", "CROSS_TENANT_TARGET")
                .counter()
                .count())
        .isEqualTo(1.0);
  }

  // ---------------------------------------------------------------------------------------
  // attachPermission() -- AC4, AC7, AC8, A3, the narrow provenance rule
  // ---------------------------------------------------------------------------------------

  @Test
  void should_attachPermissionAndReturnView_when_happyPath() {
    RoleView role = customRole(tenantId);
    PermissionView permission = benignPermission();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId)).thenReturn(Optional.of(permission));
    stubCallerHolds(permissionId);
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(false);

    // Inside a synchronization that never commits, so only the in-transaction calls are seen; the
    // post-commit holder read has its own tests below.
    PermissionView result =
        inUncommittedSynchronization(
            () -> service.attachPermission(actor, roleId, permissionId, ctx));

    assertThat(result).isEqualTo(permission);
    verify(roleManagementPort).attachPermission(roleId, permissionId);
    // In the transaction: A3's M13, and M14 and M15 to decide whether the attach completes the
    // catalogue. No holder read and no administrator read: that is after commit, or only on the
    // rare provenance branch.
    verify(userRoleAssignmentPort).findHeldRolePermissionIdsForAuthorization(actorId, tenantId);
    verify(userRoleAssignmentPort).findPermissionIdsForRole(roleId, tenantId);
    verify(userRoleAssignmentPort).findCatalogueIds();
    verifyNoMoreInteractions(userRoleAssignmentPort);
  }

  /** The audit row carries no holder count any more: the holder read is after commit (row 13). */
  @Test
  void should_recordAuditWithoutHolderCount_when_attached() {
    RoleView role = customRole(tenantId);
    PermissionView permission = benignPermission();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId)).thenReturn(Optional.of(permission));
    stubCallerHolds(permissionId);
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(false);

    inUncommittedSynchronization(() -> service.attachPermission(actor, roleId, permissionId, ctx));

    verify(rbacAuditPort)
        .recordRolePermissionGranted(
            new RoleAuditEvent(
                tenantId, roleId, role.name(), permissionId, "user:read", actorId, ctx, null));
  }

  /** Row 11: the name-based gate is gone. A caller who holds {@code role:write} may attach it. */
  @Test
  void should_attachAFormerlyDangerousPermission_when_callerHoldsItWithoutBeingNamedTenantAdmin() {
    RoleView role = customRole(tenantId);
    permissionId = ROLE_WRITE_ID;
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(new PermissionView(permissionId, "role:write", "Manage roles")));
    stubCallerHolds();
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(false);

    PermissionView result =
        inUncommittedSynchronization(
            () -> service.attachPermission(actor, roleId, permissionId, ctx));

    assertThat(result.name()).isEqualTo("role:write");
    verify(roleManagementPort).attachPermission(roleId, permissionId);
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
  void should_throwSameRoleNotFound_when_attachRoleInAnotherTenant() {
    RoleView role = customRole(otherTenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND")
        .hasMessage("No such role");

    verify(roleManagementPort, never()).findPermission(any());
    verifyNoInteractions(rbacAuditPort);
    assertThat(
            meterRegistry
                .get("nexus.rbac.permission_denied")
                .tag("permission", "role:write")
                .tag("reason", "CROSS_TENANT_TARGET")
                .counter()
                .count())
        .isEqualTo(1.0);
  }

  /** Pins §8.6 rule 1: tenant resolution always before AC7, even when the role is also a system role. */
  @Test
  void should_orderTenantCheckBeforeAc7_when_roleIsCrossTenantSystemRole() {
    RoleView foreignSystemRole =
        new RoleView(roleId, otherTenantId, "TENANT_ADMIN", "desc", true, Instant.now());
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(foreignSystemRole));

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND")
        .hasMessage("No such role");
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

  /** RC-5b named case: MEMBER is AC7's sole gate against an attach to a system role. */
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
  void should_throwDuplicateRolePermissionException_when_alreadyAttached() {
    RoleView role = customRole(tenantId);
    PermissionView permission = benignPermission();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId)).thenReturn(Optional.of(permission));
    stubCallerHolds(permissionId);
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
    stubCallerHolds(permissionId);
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(false);
    doThrow(new DuplicateRolePermissionException())
        .when(roleManagementPort)
        .attachPermission(roleId, permissionId);

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(DuplicateRolePermissionException.class);
  }

  // ---------------------------------------------------------------------------------------
  // A3 -- attaching a permission requires the caller to hold it (FR-A3.a), whatever it is
  // ---------------------------------------------------------------------------------------

  @Test
  void should_throwGrantExceedsCallerWithRoleWrite_when_callerDoesNotHoldThePermission() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));
    stubCallerHolds(UUID.randomUUID());

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> {
              assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER);
              assertThat(e.getRequiredPermission()).isEqualTo(ROLE_WRITE);
            });

    verify(roleManagementPort, never()).attachPermission(any(), any());
  }

  @Test
  void should_throwGrantExceedsCaller_when_callerHoldsNoPermissions() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));
    stubCallerHolds();

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    verify(roleManagementPort, never()).attachPermission(any(), any());
  }

  /** The held id sits in the second of several refs: A3 checks the union, not the first role. */
  @Test
  void should_attachPermission_when_callerHoldsPermissionThroughAnyActiveRole() {
    RoleView role = customRole(tenantId);
    PermissionView permission = benignPermission();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId)).thenReturn(Optional.of(permission));
    stubCallerHolds(UUID.randomUUID(), permissionId, UUID.randomUUID());
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(false);

    PermissionView result =
        inUncommittedSynchronization(
            () -> service.attachPermission(actor, roleId, permissionId, ctx));

    assertThat(result).isEqualTo(permission);
    verify(roleManagementPort).attachPermission(roleId, permissionId);
  }

  /** A3 runs before the duplicate check: a denied caller learns nothing about attachment state. */
  @Test
  void should_denyGrantExceedsCallerAndNeverCheckDuplicate_when_permissionAlreadyAttachedButNotHeld() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));
    stubCallerHolds(UUID.randomUUID());

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    verify(roleManagementPort, never()).hasPermission(any(), any());
    verify(roleManagementPort, never()).attachPermission(any(), any());
  }

  /** M13 failure must never be read as "allow". */
  @Test
  void should_propagateAndNotAttach_when_heldPermissionReadThrows() {
    RoleView role = customRole(tenantId);
    RuntimeException readFailure = new IllegalStateException("M13 read failed");
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenThrow(readFailure);

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isSameAs(readFailure);

    verify(roleManagementPort, never()).attachPermission(any(), any());
    verifyNoInteractions(rbacAuditPort);
  }

  /** Decision 7: one WARN carrying exactly the four ids -- no role or permission names. */
  @Test
  void should_logAttachExceedsCallerWarnWithIdsOnly_when_a3Denies() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));
    stubCallerHolds(UUID.randomUUID());

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);

      var warnEvents = appender.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
      assertThat(warnEvents).hasSize(1);
      assertThat(keyValueMap(warnEvents.get(0)))
          .containsOnly(
              Map.entry("event", "RBAC_ATTACH_EXCEEDS_CALLER"),
              Map.entry("tenantId", tenantId),
              Map.entry("actorUserId", actorId),
              Map.entry("roleId", roleId),
              Map.entry("permissionId", permissionId));
    } finally {
      stopLogCapture(appender);
    }
  }

  /** Matches the shipped attach-gate posture: no auth_events row on an A3 denial. */
  @Test
  void should_neverRecordAudit_when_a3Denies() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));
    stubCallerHolds();

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verifyNoInteractions(rbacAuditPort);
  }

  // -- 07-security-review.md L-1: role:write must still be in the fresh M13 read ------------

  @Test
  void should_throwPermissionAbsentWithRoleWrite_when_callerHoldsPermissionButNoLongerRoleWrite() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));
    // A3 alone would pass: the caller holds the permission being attached.
    stubCallerHoldsOnly(permissionId);

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> {
              assertThat(e.getReason()).isEqualTo(DenialReason.PERMISSION_ABSENT);
              assertThat(e.getRequiredPermission()).isEqualTo(ROLE_WRITE);
            });

    verify(roleManagementPort, never()).hasPermission(any(), any());
    verify(roleManagementPort, never()).attachPermission(any(), any());
    verifyNoInteractions(rbacAuditPort);
  }

  @Test
  void should_logEndpointPermissionNotHeldWarnWithIdsOnly_when_l1DeniesAttach() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));
    stubCallerHoldsOnly(permissionId);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
          .isInstanceOf(InsufficientPermissionException.class);

      var warnEvents = appender.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
      assertThat(warnEvents).hasSize(1);
      assertThat(keyValueMap(warnEvents.get(0)))
          .containsOnly(
              Map.entry("event", "RBAC_ENDPOINT_PERMISSION_NOT_HELD"),
              Map.entry("tenantId", tenantId),
              Map.entry("actorUserId", actorId),
              Map.entry("roleId", roleId),
              Map.entry("permissionId", permissionId));
    } finally {
      stopLogCapture(appender);
    }
  }

  // ---------------------------------------------------------------------------------------
  // Row 14, R1-1, RC-50(a): the narrow provenance rule (409 RBAC_010)
  // ---------------------------------------------------------------------------------------

  /** The role holds {@code P1}; attaching {@code P2} completes the two-permission catalogue. */
  private void stubCompletingAttach() {
    permissionId = P2;
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(roleManagementPort.findPermission(P2))
        .thenReturn(Optional.of(new PermissionView(P2, "user:read", "Read users")));
    stubCallerHolds(P2);
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(Set.of(P1)));
  }

  /**
   * The tenant has one admin-defining role, and {@code administratorUserIds} are its active holders:
   * M10' lists the role, and the administrator user set read returns them.
   */
  private UUID stubTenantAdministrators(Set<UUID> administratorUserIds) {
    UUID adminDefiningRoleId = UUID.randomUUID();
    // Lenient: a post-commit read that fails before it gets here must not fail the test.
    lenient()
        .when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId))
        .thenReturn(
            List.of(
                new RolePermissionRef(adminDefiningRoleId, P1),
                new RolePermissionRef(adminDefiningRoleId, P2)));
    lenient()
        .when(
            userRoleAssignmentPort.findActiveHolderUserIdsForRoles(
                eq(tenantId), eq(Set.of(adminDefiningRoleId))))
        .thenReturn(administratorUserIds);
    return adminDefiningRoleId;
  }

  /** R1-1: completing the catalogue while one holder was assigned by a non-administrator. */
  @Test
  void should_refuseWith409Rbac010AndWriteNothing_when_completingCatalogueWithANonAdministratorAssignedHolder() {
    stubCompletingAttach();
    UUID holder = UUID.randomUUID();
    UUID nonAdministratorAssigner = UUID.randomUUID();
    when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId))
        .thenReturn(List.of(new HolderProvenance(holder, nonAdministratorAssigner)));
    stubTenantAdministrators(Set.of(UUID.randomUUID()));

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
          .isInstanceOf(AttachProvenanceConflictException.class)
          .hasFieldOrPropertyWithValue("code", "RBAC_010")
          .satisfies(
              e ->
                  assertThat(e.getMessage())
                      .doesNotContain(holder.toString())
                      .doesNotContain(nonAdministratorAssigner.toString()));

      var warnEvents = appender.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
      assertThat(warnEvents).hasSize(1);
      assertThat(keyValueMap(warnEvents.get(0)))
          .containsOnly(
              Map.entry("event", "RBAC_ATTACH_PROVENANCE_REFUSED"),
              Map.entry("tenantId", tenantId),
              Map.entry("actorUserId", actorId),
              Map.entry("roleId", roleId),
              Map.entry("permissionId", P2),
              Map.entry("nonAdminAssignedCount", 1));
    } finally {
      stopLogCapture(appender);
    }

    verify(roleManagementPort, never()).hasPermission(any(), any());
    verify(roleManagementPort, never()).attachPermission(any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort, permissionFreshness);
    Counter denied =
        meterRegistry
            .find("nexus.rbac.permission_denied")
            .tags("permission", "role:write", "reason", "ATTACH_PROVENANCE")
            .counter();
    assertThat(denied).isNotNull();
    assertThat(denied.count()).isEqualTo(1.0);
  }

  /** The same attach with only administrator-assigned holders succeeds and pages row 14. */
  @Test
  void should_attachAndSignalRow14_when_completingCatalogueWithOnlyAdministratorAssignedHolders() {
    stubCompletingAttach();
    UUID administrator = UUID.randomUUID();
    when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId))
        .thenReturn(List.of(new HolderProvenance(UUID.randomUUID(), administrator)));
    stubTenantAdministrators(Set.of(administrator));
    when(roleManagementPort.hasPermission(roleId, P2)).thenReturn(false);

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.attachPermission(actor, roleId, permissionId, ctx);

      var became =
          appender.list.stream()
              .filter(e -> "RBAC_ROLE_BECAME_ADMIN_DEFINING".equals(keyValueMap(e).get("event")))
              .toList();
      assertThat(became).hasSize(1);
      assertThat(became.get(0).getLevel()).isEqualTo(Level.WARN);
      assertThat(keyValueMap(became.get(0)))
          .containsOnly(
              Map.entry("event", "RBAC_ROLE_BECAME_ADMIN_DEFINING"),
              Map.entry("tenantId", tenantId),
              Map.entry("roleId", roleId),
              Map.entry("grantedBy", actorId),
              Map.entry("holderCount", 1));
    } finally {
      stopLogCapture(appender);
    }

    verify(roleManagementPort).attachPermission(roleId, P2);
    Counter counter =
        meterRegistry.find("nexus.rbac.role_became_admin_defining").tag("holders", "1").counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
    assertThat(meterRegistry.find("nexus.rbac.attach_escalates_non_admin_assigned").counter())
        .isNull();
  }

  /** A break-glass holder (assigned_by equals the holder, who is an administrator) never trips it. */
  @Test
  void should_attach_when_theOnlyHolderWasAssignedByThemselvesAndIsAnAdministrator() {
    stubCompletingAttach();
    UUID breakGlassAdmin = UUID.randomUUID();
    when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId))
        .thenReturn(List.of(new HolderProvenance(breakGlassAdmin, breakGlassAdmin)));
    stubTenantAdministrators(Set.of(breakGlassAdmin));
    when(roleManagementPort.hasPermission(roleId, P2)).thenReturn(false);

    service.attachPermission(actor, roleId, permissionId, ctx);

    verify(roleManagementPort).attachPermission(roleId, P2);
  }

  /** The role has no holders: nothing to refuse, and the administrator set is never read. */
  @Test
  void should_attachWithoutReadingAdministrators_when_completingCatalogueOnARoleWithNoHolders() {
    stubCompletingAttach();
    when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId)).thenReturn(List.of());
    when(roleManagementPort.hasPermission(roleId, P2)).thenReturn(false);

    service.attachPermission(actor, roleId, permissionId, ctx);

    verify(roleManagementPort).attachPermission(roleId, P2);
    verify(userRoleAssignmentPort, never()).findActiveHolderUserIdsForRoles(any(), any());
    Counter counter =
        meterRegistry.find("nexus.rbac.role_became_admin_defining").tag("holders", "0").counter();
    assertThat(counter).isNotNull();
  }

  /** RC-50(a): a duplicate attach to an already admin-defining role is still 409 RBAC_005. */
  @Test
  void should_throw409Rbac005NotRbac010_when_attachingToARoleThatIsAlreadyAdminDefining() {
    permissionId = P2;
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(roleManagementPort.findPermission(P2))
        .thenReturn(Optional.of(new PermissionView(P2, "user:read", "Read users")));
    stubCallerHolds(P2);
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(CATALOGUE));
    when(roleManagementPort.hasPermission(roleId, P2)).thenReturn(true);

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(DuplicateRolePermissionException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_005");

    verify(userRoleAssignmentPort, never()).findActiveHoldersForRole(any(), any());
  }

  /** The rule is narrow: an attach that does not complete the catalogue never reads holders. */
  @Test
  void should_notEvaluateProvenance_when_theAttachDoesNotCompleteTheCatalogue() {
    permissionId = P1;
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(roleManagementPort.findPermission(P1))
        .thenReturn(Optional.of(new PermissionView(P1, "user:read", "Read users")));
    stubCallerHolds(P1);
    when(roleManagementPort.hasPermission(roleId, P1)).thenReturn(false);

    inUncommittedSynchronization(() -> service.attachPermission(actor, roleId, P1, ctx));

    verify(userRoleAssignmentPort, never()).findActiveHoldersForRole(any(), any());
    verify(roleManagementPort).attachPermission(roleId, P1);
  }

  /** A3 precedes the provenance rule: a caller who may not attach learns nothing about holders. */
  @Test
  void should_denyGrantExceedsCallerBeforeProvenance_when_callerDoesNotHoldTheCompletingPermission() {
    permissionId = P2;
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(roleManagementPort.findPermission(P2))
        .thenReturn(Optional.of(new PermissionView(P2, "user:read", "Read users")));
    stubCallerHolds(); // the caller does not hold P2

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    verify(userRoleAssignmentPort, never()).findActiveHoldersForRole(any(), any());
  }

  @Test
  void should_propagateAndNotAttach_when_provenanceHolderReadThrows() {
    stubCompletingAttach();
    when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId))
        .thenThrow(new IllegalStateException("db down"));

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(IllegalStateException.class);

    verify(roleManagementPort, never()).attachPermission(any(), any());
  }

  @Test
  void should_failClosed_when_m14ReportsTheRoleNotInTheTenantOnAttach() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));
    stubCallerHolds(permissionId);
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND")
        .hasMessage("No such role");

    verify(roleManagementPort, never()).attachPermission(any(), any());
  }

  // ---------------------------------------------------------------------------------------
  // Row 13 (RC-23.2): the escalation signal, after commit, from one holder read
  // ---------------------------------------------------------------------------------------

  private List<HolderProvenance> stubBenignAttachWithHolders(
      List<HolderProvenance> holders, Set<UUID> administratorUserIds) {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));
    stubCallerHolds(permissionId);
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(false);
    when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId)).thenReturn(holders);
    if (!holders.isEmpty()) {
      stubTenantAdministrators(administratorUserIds);
    }
    return holders;
  }

  private static List<HolderProvenance> holdersAssignedBy(UUID assigner, int count) {
    List<HolderProvenance> holders = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      holders.add(new HolderProvenance(UUID.randomUUID(), assigner));
    }
    return holders;
  }

  @Test
  void should_warnAndCountTicket_when_aHolderWasAssignedByANonAdministrator() {
    UUID nonAdministrator = UUID.randomUUID();
    stubBenignAttachWithHolders(
        holdersAssignedBy(nonAdministrator, 1), Set.of(UUID.randomUUID()));

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.attachPermission(actor, roleId, permissionId, ctx);

      var warn =
          appender.list.stream()
              .filter(
                  e ->
                      "RBAC_ATTACH_ESCALATES_NON_ADMIN_ASSIGNED_HOLDERS"
                          .equals(keyValueMap(e).get("event")))
              .toList();
      assertThat(warn).hasSize(1);
      assertThat(warn.get(0).getLevel()).isEqualTo(Level.WARN);
      assertThat(keyValueMap(warn.get(0)))
          .containsOnly(
              Map.entry("event", "RBAC_ATTACH_ESCALATES_NON_ADMIN_ASSIGNED_HOLDERS"),
              Map.entry("tenantId", tenantId),
              Map.entry("roleId", roleId),
              Map.entry("permissionId", permissionId),
              Map.entry("holderCount", 1),
              Map.entry("nonAdminAssignedCount", 1));
      assertThat(warn.get(0).getFormattedMessage()).doesNotContain(nonAdministrator.toString());
    } finally {
      stopLogCapture(appender);
    }

    Counter counter =
        meterRegistry
            .find("nexus.rbac.attach_escalates_non_admin_assigned")
            .tags("holders", "1", "page", "false")
            .counter();
    assertThat(counter).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
    assertThat(counter.getId().getTags()).extracting("key").doesNotContain("tenantId");
  }

  @Test
  void should_pageTheSignal_when_thePermissionIsUserRoleAssign() {
    permissionId = USER_ROLE_ASSIGN_ID;
    stubBenignAttachWithHolders(holdersAssignedBy(UUID.randomUUID(), 2), Set.of(UUID.randomUUID()));

    service.attachPermission(actor, roleId, permissionId, ctx);

    assertThat(
            meterRegistry
                .find("nexus.rbac.attach_escalates_non_admin_assigned")
                .tags("holders", "2-10", "page", "true")
                .counter())
        .isNotNull();
  }

  @Test
  void should_pageTheSignal_when_thePermissionIsRoleWrite() {
    permissionId = ROLE_WRITE_ID;
    stubBenignAttachWithHolders(holdersAssignedBy(UUID.randomUUID(), 1), Set.of(UUID.randomUUID()));

    service.attachPermission(actor, roleId, permissionId, ctx);

    assertThat(
            meterRegistry
                .find("nexus.rbac.attach_escalates_non_admin_assigned")
                .tags("holders", "1", "page", "true")
                .counter())
        .isNotNull();
  }

  @Test
  void should_bucketOverTenHolders_when_manyHoldersWereAssignedByANonAdministrator() {
    stubBenignAttachWithHolders(holdersAssignedBy(UUID.randomUUID(), 11), Set.of(UUID.randomUUID()));

    service.attachPermission(actor, roleId, permissionId, ctx);

    assertThat(
            meterRegistry
                .find("nexus.rbac.attach_escalates_non_admin_assigned")
                .tags("holders", ">10")
                .counter())
        .isNotNull();
  }

  /** Page when the attach made the role admin-defining even though the pre-commit check passed. */
  @Test
  void should_pageTheSignal_when_theAttachMadeTheRoleAdminDefiningAndAHolderIsNowNonAdminAssigned() {
    stubCompletingAttach();
    when(roleManagementPort.hasPermission(roleId, P2)).thenReturn(false);
    UUID assigner = UUID.randomUUID();
    HolderProvenance holder = new HolderProvenance(UUID.randomUUID(), assigner);
    when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId))
        .thenReturn(List.of(holder));
    UUID adminRoleId = UUID.randomUUID();
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId))
        .thenReturn(
            List.of(new RolePermissionRef(adminRoleId, P1), new RolePermissionRef(adminRoleId, P2)));
    // Before commit the assigner is an administrator; by the time of the read after commit, not.
    when(userRoleAssignmentPort.findActiveHolderUserIdsForRoles(
            eq(tenantId), eq(Set.of(adminRoleId))))
        .thenReturn(Set.of(assigner))
        .thenReturn(Set.of());

    service.attachPermission(actor, roleId, permissionId, ctx);

    assertThat(
            meterRegistry
                .find("nexus.rbac.attach_escalates_non_admin_assigned")
                .tags("holders", "1", "page", "true")
                .counter())
        .isNotNull();
  }

  @Test
  void should_emitNoEscalationSignal_when_everyHolderWasAssignedByAnAdministrator() {
    UUID administrator = UUID.randomUUID();
    stubBenignAttachWithHolders(holdersAssignedBy(administrator, 3), Set.of(administrator));

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.attachPermission(actor, roleId, permissionId, ctx);

      assertThat(
              appender.list.stream()
                  .map(e -> keyValueMap(e).get("event"))
                  .filter(
                      "RBAC_ATTACH_ESCALATES_NON_ADMIN_ASSIGNED_HOLDERS"::equals))
          .isEmpty();
    } finally {
      stopLogCapture(appender);
    }
    assertThat(meterRegistry.find("nexus.rbac.attach_escalates_non_admin_assigned").counter())
        .isNull();
    assertThat(meterRegistry.find("nexus.rbac.role_became_admin_defining").counter()).isNull();
  }

  @Test
  void should_emitNoSignalAndNotReadAdministrators_when_theRoleHasNoHolders() {
    stubBenignAttachWithHolders(List.of(), Set.of());

    service.attachPermission(actor, roleId, permissionId, ctx);

    verify(userRoleAssignmentPort, never()).findActiveHolderUserIdsForRoles(any(), any());
    assertThat(meterRegistry.find("nexus.rbac.attach_escalates_non_admin_assigned").counter())
        .isNull();
  }

  /** The formerly dangerous-permission counter and WARN are retired with the gate (row 13). */
  @Test
  void should_notEmitTheRetiredDangerousPermissionSignals_when_attaching() {
    permissionId = ROLE_WRITE_ID;
    stubBenignAttachWithHolders(holdersAssignedBy(UUID.randomUUID(), 1), Set.of(UUID.randomUUID()));

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      service.attachPermission(actor, roleId, permissionId, ctx);

      assertThat(
              appender.list.stream()
                  .map(e -> keyValueMap(e).get("event"))
                  .filter("RBAC_DANGEROUS_PERMISSION_GRANTED_TO_EXISTING_HOLDERS"::equals))
          .isEmpty();
    } finally {
      stopLogCapture(appender);
    }
    assertThat(meterRegistry.find("nexus.rbac.dangerous_permission_granted").counter()).isNull();
  }

  @Test
  void should_signalRow14WithUnknownHolders_when_theHolderReadFailsAfterACompletingAttach() {
    stubCompletingAttach();
    when(roleManagementPort.hasPermission(roleId, P2)).thenReturn(false);
    when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId))
        .thenReturn(List.of())
        .thenThrow(new org.springframework.dao.QueryTimeoutException("db down"));

    org.assertj.core.api.Assertions.assertThatCode(
            () -> service.attachPermission(actor, roleId, permissionId, ctx))
        .doesNotThrowAnyException();

    // A missing read must alert, never stay silent: unknown holders pages like holders > 0.
    assertThat(
            meterRegistry
                .find("nexus.rbac.role_became_admin_defining")
                .tag("holders", "unknown")
                .counter())
        .isNotNull();
    verifyNoInteractions(permissionCachePort, permissionFreshness);
  }

  // ---------------------------------------------------------------------------------------
  // detachPermission() -- AC5, AC7, AC8, AC12, role-subset (row 12)
  // ---------------------------------------------------------------------------------------

  /** R is in the tenant and carries {@code rolePermissionIds}. */
  private void stubRolePermissions(Set<UUID> rolePermissionIds) {
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.of(rolePermissionIds));
  }

  /** M13: the caller holds each of {@code refs}, each ref through the role it names. */
  private void stubCallerHoldsRefs(RolePermissionRef... refs) {
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(List.of(refs));
  }

  @Test
  void should_detachPermissionAndCompleteSuccessfully_when_callerHoldsEveryPermissionOfTheRole() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    stubRolePermissions(Set.of(P1));
    stubCallerHoldsRefs(new RolePermissionRef(UUID.randomUUID(), P1));
    when(roleManagementPort.detachPermission(roleId, P1)).thenReturn(1);
    when(roleManagementPort.findPermission(P1)).thenReturn(Optional.of(benignPermission()));

    service.detachPermission(actor, roleId, P1, ctx);

    verify(roleManagementPort).detachPermission(roleId, P1);
  }

  @Test
  void should_throwResourceNotFound_when_detachRoleDoesNotExist() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");
  }

  @Test
  void should_throwSameRoleNotFound_when_detachRoleInAnotherTenant() {
    RoleView role = customRole(otherTenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND")
        .hasMessage("No such role");

    verifyNoInteractions(rbacAuditPort);
    assertThat(
            meterRegistry
                .get("nexus.rbac.permission_denied")
                .tag("permission", "role:write")
                .tag("reason", "CROSS_TENANT_TARGET")
                .counter()
                .count())
        .isEqualTo(1.0);
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
    verifyNoInteractions(userRoleAssignmentPort);
  }

  @Test
  void should_throwResourceNotFound_when_pairingWasNeverAttachedOrAlreadyDetached() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    stubRolePermissions(Set.of());
    when(roleManagementPort.detachPermission(roleId, permissionId)).thenReturn(0);

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_PERMISSION_NOT_FOUND");

    verifyNoInteractions(rbacAuditPort);
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
                tenantId, roleId, role.name(), permissionId, "user:read", actorId, ctx, null));
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

  // -- Row 12, RC-26.2: role-subset ---------------------------------------------------------

  /** The caller lacks one of the role's permissions: 403 GRANT_EXCEEDS_CALLER, nothing written. */
  @Test
  void should_deny403_when_callerDoesNotHoldEveryPermissionOfTheRole() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    stubRolePermissions(Set.of(P1, P2));
    stubCallerHoldsRefs(new RolePermissionRef(UUID.randomUUID(), P1));

    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatThrownBy(() -> service.detachPermission(actor, roleId, P1, ctx))
          .isInstanceOfSatisfying(
              InsufficientPermissionException.class,
              e -> {
                assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER);
                assertThat(e.getRequiredPermission()).isEqualTo(ROLE_WRITE);
              });

      var warnEvents = appender.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
      assertThat(warnEvents).hasSize(1);
      assertThat(keyValueMap(warnEvents.get(0)))
          .containsOnly(
              Map.entry("event", "RBAC_ROLE_SUBSET_DENIED"),
              Map.entry("tenantId", tenantId),
              Map.entry("actorUserId", actorId),
              Map.entry("roleId", roleId),
              Map.entry("operation", "detach"));
    } finally {
      stopLogCapture(appender);
    }

    verify(roleManagementPort, never()).detachPermission(any(), any());
    verifyNoInteractions(rbacAuditPort, permissionFreshness, permissionCachePort, transactionManager);
  }

  /** 403 comes before 404: no attachment-existence oracle for a caller outside the subset. */
  @Test
  void should_deny403NotFound404_when_callerLacksThePermissionsAndThePairingDoesNotExist() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    stubRolePermissions(Set.of(P1));
    stubCallerHoldsRefs();
    lenient().when(roleManagementPort.detachPermission(roleId, P2)).thenReturn(0);

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, P2, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verify(roleManagementPort, never()).detachPermission(any(), any());
  }

  /** RC-26.2: a union-holder cannot demote an admin-defining custom role. */
  @Test
  void should_deny403_when_unionHolderDetachesFromAnAdminDefiningRole() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    stubRolePermissions(CATALOGUE);
    stubCallerHoldsRefs(
        new RolePermissionRef(UUID.randomUUID(), P1), new RolePermissionRef(UUID.randomUUID(), P2));

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, P1, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    verify(roleManagementPort, never()).detachPermission(any(), any());
  }

  /** RC-26.2: an administrator whose only admin-defining role is R may not detach from R. */
  @Test
  void should_deny403_when_theCallersOnlyAdminDefiningRoleIsTheRoleBeingDetachedFrom() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    stubRolePermissions(CATALOGUE);
    stubCallerHoldsRefs(new RolePermissionRef(roleId, P1), new RolePermissionRef(roleId, P2));

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, P1, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    verify(roleManagementPort, never()).detachPermission(any(), any());
  }

  /** An administrator through ANOTHER role may detach from R: no single detach removes their status. */
  @Test
  void should_detach_when_callerIsAnAdministratorThroughAnotherRole() {
    UUID otherAdminRoleId = UUID.randomUUID();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    stubRolePermissions(CATALOGUE);
    stubCallerHoldsRefs(
        new RolePermissionRef(roleId, P1),
        new RolePermissionRef(roleId, P2),
        new RolePermissionRef(otherAdminRoleId, P1),
        new RolePermissionRef(otherAdminRoleId, P2));
    when(roleManagementPort.detachPermission(roleId, P1)).thenReturn(1);
    when(roleManagementPort.findPermission(P1)).thenReturn(Optional.of(benignPermission()));

    service.detachPermission(actor, roleId, P1, ctx);

    verify(roleManagementPort).detachPermission(roleId, P1);
  }

  /** The administrator requirement applies only to admin-defining roles: a plain subset suffices. */
  @Test
  void should_detachFromANonAdminDefiningRole_when_callerHoldsItsPermissionsButIsNoAdministrator() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    stubRolePermissions(Set.of(P1));
    stubCallerHoldsRefs(new RolePermissionRef(UUID.randomUUID(), P1));
    when(roleManagementPort.detachPermission(roleId, P1)).thenReturn(1);
    when(roleManagementPort.findPermission(P1)).thenReturn(Optional.of(benignPermission()));

    service.detachPermission(actor, roleId, P1, ctx);

    verify(roleManagementPort).detachPermission(roleId, P1);
  }

  @Test
  void should_deny403_when_callerHoldsNothingAtAll() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    stubRolePermissions(Set.of(P1));
    stubCallerHoldsRefs();

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, P1, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verify(roleManagementPort, never()).detachPermission(any(), any());
  }

  @Test
  void should_failClosed_when_m14ReportsTheRoleNotInTheTenantOnDetach() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(userRoleAssignmentPort.findPermissionIdsForRole(roleId, tenantId))
        .thenReturn(Optional.empty());
    stubCallerHoldsRefs(new RolePermissionRef(UUID.randomUUID(), P1));

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, P1, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verify(roleManagementPort, never()).detachPermission(any(), any());
  }

  @Test
  void should_propagateAndNotDetach_when_roleSubsetReadThrows() {
    RuntimeException readFailure = new IllegalStateException("M13 read failed");
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenThrow(readFailure);

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, permissionId, ctx))
        .isSameAs(readFailure);

    verify(roleManagementPort, never()).detachPermission(any(), any());
    verifyNoInteractions(rbacAuditPort);
  }

  // ---------------------------------------------------------------------------------------
  // US-018 T-010: detach fans the epoch bump out to every holder after commit; attach evicts
  // every holder's cache entry after commit and never bumps (Decisions 15, 17)
  // ---------------------------------------------------------------------------------------

  @Test
  void should_readHoldersOnlyAfterCommit_when_detachInsideSynchronization() {
    List<UUID> holders = stubHappyPathDetach();

    TransactionSynchronizationManager.initSynchronization();
    try {
      service.detachPermission(actor, roleId, permissionId, ctx);

      verify(userRoleAssignmentPort, never()).findActiveUserIdsForRole(any());
      fireAfterCommit();
    } finally {
      TransactionSynchronizationManager.clearSynchronization();
    }

    verify(userRoleAssignmentPort).findActiveUserIdsForRole(roleId);
    verify(permissionFreshness).invalidateHolders(tenantId, holders, "detach");
  }

  @Test
  void should_invalidateHoldersOnlyInsideAfterCommit_when_detachInsideSynchronization() {
    stubHappyPathDetach();
    boolean[] insideAfterCommit = {false};
    doAnswer(invocation -> {
      assertThat(insideAfterCommit[0])
          .as("invalidateHolders called with an active synchronization outside afterCommit (MC-7b)")
          .isTrue();
      return null;
    }).when(permissionFreshness).invalidateHolders(any(), any(), any());

    TransactionSynchronizationManager.initSynchronization();
    try {
      service.detachPermission(actor, roleId, permissionId, ctx);

      verifyNoInteractions(permissionFreshness);
      insideAfterCommit[0] = true;
      fireAfterCommit();
    } finally {
      TransactionSynchronizationManager.clearSynchronization();
    }

    verify(permissionFreshness).invalidateHolders(any(), any(), any());
  }

  @Test
  void should_notThrow_when_holderReadFailsAfterDetachCommit() {
    stubHappyPathDetach();
    when(userRoleAssignmentPort.findActiveUserIdsForRole(roleId))
        .thenThrow(new org.springframework.dao.QueryTimeoutException("db down"));

    // The detach already committed: the administrator must see success, not a 500.
    org.assertj.core.api.Assertions.assertThatCode(
            () -> service.detachPermission(actor, roleId, permissionId, ctx))
        .doesNotThrowAnyException();

    verify(permissionFreshness, never()).invalidateHolders(any(), any(), any());
  }

  @Test
  void should_countPagingSignalAndReadTwice_when_detachHolderReadFailsTwice() {
    stubHappyPathDetach();
    when(userRoleAssignmentPort.findActiveUserIdsForRole(roleId))
        .thenThrow(new org.springframework.dao.QueryTimeoutException("db down"));

    service.detachPermission(actor, roleId, permissionId, ctx);

    verify(userRoleAssignmentPort, times(2)).findActiveUserIdsForRole(roleId);
    verify(permissionFreshness).holderReadFailed(tenantId, roleId, "detach");
    verify(permissionFreshness, never()).invalidateHolders(any(), any(), any());
  }

  @Test
  void should_invalidateHolders_when_detachHolderReadFailsOnceThenSucceeds() {
    stubHappyPathDetach();
    List<UUID> holders = List.of(UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveUserIdsForRole(roleId))
        .thenThrow(new org.springframework.dao.QueryTimeoutException("pool timeout"))
        .thenReturn(holders);

    service.detachPermission(actor, roleId, permissionId, ctx);

    verify(permissionFreshness).invalidateHolders(tenantId, holders, "detach");
    verify(permissionFreshness, never()).holderReadFailed(any(), any(), any());
  }

  @Test
  void should_notRaisePagingSignalOrRetry_when_attachHolderReadFails() {
    stubHappyPathBenignAttach();
    when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId))
        .thenThrow(new org.springframework.dao.QueryTimeoutException("db down"));

    service.attachPermission(actor, roleId, permissionId, ctx);

    verify(userRoleAssignmentPort, times(1)).findActiveHoldersForRole(roleId, tenantId);
    verifyNoInteractions(permissionFreshness);
  }

  @Test
  void should_invalidateEveryHolder_when_detachSucceeds() {
    List<UUID> holders = stubHappyPathDetach();

    service.detachPermission(actor, roleId, permissionId, ctx);

    verify(permissionFreshness).invalidateHolders(tenantId, holders, "detach");
    verifyNoMoreInteractions(permissionFreshness);
  }

  @Test
  void should_neverInvalidate_when_detachReturns404() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    stubRolePermissions(Set.of());
    when(roleManagementPort.detachPermission(roleId, permissionId)).thenReturn(0);

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(ResourceNotFoundException.class);

    verifyNoInteractions(permissionFreshness, permissionCachePort, transactionManager);
    verify(userRoleAssignmentPort, never()).findActiveUserIdsForRole(any());
  }

  @Test
  void should_neverInvalidate_when_detachDenied() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    stubRolePermissions(Set.of(P1));
    stubCallerHoldsRefs();

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, P1, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verifyNoInteractions(permissionFreshness, permissionCachePort, transactionManager);
    verify(userRoleAssignmentPort, never()).findActiveUserIdsForRole(any());
  }

  @Test
  void should_neverInvalidate_when_detachRoleIsSystemRole() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(systemRole("MEMBER")));

    assertThatThrownBy(() -> service.detachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(SystemRoleImmutableException.class);

    verifyNoInteractions(permissionFreshness, permissionCachePort, transactionManager);
  }

  @Test
  void should_neverInvalidate_when_transactionRollsBack() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));
    when(roleManagementPort.detachPermission(roleId, permissionId)).thenReturn(1);

    TransactionSynchronizationManager.initSynchronization();
    try {
      service.detachPermission(actor, roleId, permissionId, ctx);
      for (TransactionSynchronization synchronization :
          TransactionSynchronizationManager.getSynchronizations()) {
        synchronization.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK);
      }
    } finally {
      TransactionSynchronizationManager.clearSynchronization();
    }

    verifyNoInteractions(permissionFreshness, transactionManager);
    verify(userRoleAssignmentPort, never()).findActiveUserIdsForRole(any());
  }

  /**
   * The holder read runs in its own read-only transaction: in afterCommit the outer transaction's
   * resources are still bound, and only REQUIRES_NEW guarantees a fresh read of committed rows.
   * The Redis fan-out starts only after that transaction has ended.
   */
  @Test
  void should_readHoldersInNewReadOnlyTransaction_when_detachCommits() {
    List<UUID> holders = stubHappyPathDetach();
    ArgumentCaptor<TransactionDefinition> definition =
        ArgumentCaptor.forClass(TransactionDefinition.class);

    service.detachPermission(actor, roleId, permissionId, ctx);

    InOrder order = inOrder(transactionManager, userRoleAssignmentPort, permissionFreshness);
    order.verify(transactionManager).getTransaction(definition.capture());
    order.verify(userRoleAssignmentPort).findActiveUserIdsForRole(roleId);
    order.verify(transactionManager).commit(any());
    order.verify(permissionFreshness).invalidateHolders(tenantId, holders, "detach");
    assertThat(definition.getValue().getPropagationBehavior())
        .isEqualTo(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    assertThat(definition.getValue().isReadOnly()).isTrue();
  }

  @Test
  void should_evictEveryHolderAfterCommit_when_attachSucceeds() {
    List<UUID> holders = stubHappyPathBenignAttach();

    TransactionSynchronizationManager.initSynchronization();
    try {
      service.attachPermission(actor, roleId, permissionId, ctx);

      verifyNoInteractions(permissionCachePort);
      verify(userRoleAssignmentPort, never()).findActiveHoldersForRole(any(), any());
      fireAfterCommit();
    } finally {
      TransactionSynchronizationManager.clearSynchronization();
    }

    verify(permissionCachePort).evict(tenantId, holders);
    verifyNoMoreInteractions(permissionCachePort);
  }

  @Test
  void should_notThrow_when_holderReadFailsAfterAttachCommit() {
    stubHappyPathBenignAttach();
    when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId))
        .thenThrow(new org.springframework.dao.QueryTimeoutException("db down"));

    org.assertj.core.api.Assertions.assertThatCode(
            () -> service.attachPermission(actor, roleId, permissionId, ctx))
        .doesNotThrowAnyException();

    verifyNoInteractions(permissionCachePort);
  }

  @Test
  void should_neverBump_when_attachSucceeds() {
    stubHappyPathBenignAttach();

    service.attachPermission(actor, roleId, permissionId, ctx);

    verifyNoInteractions(permissionFreshness);
  }

  @Test
  void should_readAttachHoldersInNewReadOnlyTransaction_when_attachCommits() {
    List<UUID> holders = stubHappyPathBenignAttach();
    ArgumentCaptor<TransactionDefinition> definition =
        ArgumentCaptor.forClass(TransactionDefinition.class);

    service.attachPermission(actor, roleId, permissionId, ctx);

    InOrder order = inOrder(transactionManager, userRoleAssignmentPort, permissionCachePort);
    order.verify(transactionManager).getTransaction(definition.capture());
    order.verify(userRoleAssignmentPort).findActiveHoldersForRole(roleId, tenantId);
    order.verify(transactionManager).commit(any());
    order.verify(permissionCachePort).evict(tenantId, holders);
    assertThat(definition.getValue().getPropagationBehavior())
        .isEqualTo(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    assertThat(definition.getValue().isReadOnly()).isTrue();
  }

  @Test
  void should_neverEvict_when_attachDenied() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));
    stubCallerHolds();

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verifyNoInteractions(permissionCachePort, permissionFreshness, transactionManager);
  }

  // ---------------------------------------------------------------------------------------
  // listAllPermissions() -- AC6
  // ---------------------------------------------------------------------------------------

  @Test
  void should_returnAllPermissionsFromPort_when_called() {
    PermissionView permission = benignPermission();
    when(roleManagementPort.findAllPermissions(1, 8))
        .thenReturn(new PageResult<>(List.of(permission), 9, 1, 8));

    PageResult<PermissionView> result = service.listAllPermissions(1, 8);

    assertThat(result.items()).containsExactly(permission);
    assertThat(result.totalPages()).isEqualTo(2);
  }

  // ---------------------------------------------------------------------------------------
  // Test infrastructure
  // ---------------------------------------------------------------------------------------

  /**
   * Stubs M13 for the actor so the caller holds the endpoint permission {@code role:write}
   * (07-security-review.md L-1) plus exactly {@code heldPermissionIds}, each through its own
   * (random) role. A3 requires every successful attach to find the attached id here.
   */
  private void stubCallerHolds(UUID... heldPermissionIds) {
    UUID[] withRoleWrite = Arrays.copyOf(heldPermissionIds, heldPermissionIds.length + 1);
    withRoleWrite[heldPermissionIds.length] = ROLE_WRITE_ID;
    stubCallerHoldsOnly(withRoleWrite);
  }

  /**
   * Stubs M13 for the actor so the caller holds exactly {@code heldPermissionIds} and nothing else
   * — not even {@code role:write} unless it is passed in.
   */
  private void stubCallerHoldsOnly(UUID... heldPermissionIds) {
    List<RolePermissionRef> refs = new ArrayList<>();
    for (UUID heldPermissionId : heldPermissionIds) {
      refs.add(new RolePermissionRef(UUID.randomUUID(), heldPermissionId));
    }
    when(userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(refs);
  }

  /** A successful detach by a caller who holds the role's permission; three holders after commit. */
  private List<UUID> stubHappyPathDetach() {
    List<UUID> holders = List.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID());
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(Optional.of(benignPermission()));
    stubRolePermissions(Set.of(permissionId));
    stubCallerHoldsRefs(new RolePermissionRef(UUID.randomUUID(), permissionId));
    when(roleManagementPort.detachPermission(roleId, permissionId)).thenReturn(1);
    when(userRoleAssignmentPort.findActiveUserIdsForRole(roleId)).thenReturn(holders);
    return holders;
  }

  /**
   * A successful ordinary attach whose role has three active holders after commit, all assigned by
   * administrators (so no escalation signal). Returns the holder user ids.
   */
  private List<UUID> stubHappyPathBenignAttach() {
    UUID administrator = UUID.randomUUID();
    List<HolderProvenance> holders = holdersAssignedBy(administrator, 3);
    stubBenignAttachWithHolders(holders, Set.of(administrator));
    return holders.stream().map(HolderProvenance::userId).toList();
  }

  private static void fireAfterCommit() {
    for (TransactionSynchronization synchronization :
        TransactionSynchronizationManager.getSynchronizations()) {
      synchronization.afterCommit();
    }
  }

  /** Runs {@code call} inside an active synchronization that never reaches afterCommit. */
  private static <T> T inUncommittedSynchronization(Supplier<T> call) {
    TransactionSynchronizationManager.initSynchronization();
    try {
      return call.get();
    } finally {
      TransactionSynchronizationManager.clearSynchronization();
    }
  }

  // ---------------------------------------------------------------------------------------
  // softDeleteRole() -- US-018 C1 (T-025): 404 -> 403 (role-subset) -> 409 RBAC_003 -> [set lock]
  // -> UPDATE -> 409 RBAC_009 -> audit
  // ---------------------------------------------------------------------------------------

  private ActiveAssignmentHolder holder(UUID holderRoleId) {
    return new ActiveAssignmentHolder(UUID.randomUUID(), UUID.randomUUID(), holderRoleId);
  }

  /** A custom, non-admin-defining role the caller may delete: it carries P1 and the caller holds P1. */
  private void stubDeletableBenignRole() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    stubRolePermissions(Set.of(P1));
    stubCallerHoldsRefs(new RolePermissionRef(UUID.randomUUID(), P1));
  }

  @Test
  void should_softDeleteAndAudit_when_customRoleHasNoActiveHolders() {
    stubDeletableBenignRole();
    when(roleManagementPort.softDeleteRole(eq(roleId), eq(tenantId), any(Instant.class)))
        .thenReturn(1);
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(tenantId, List.of(roleId)))
        .thenReturn(List.of());

    service.softDeleteRole(actor, roleId, ctx);

    verify(rbacAuditPort)
        .recordRoleDeleted(
            new RoleAuditEvent(tenantId, roleId, "Custom Role", null, null, actorId, ctx, null));
  }

  @Test
  void should_notTakeTheSetLock_when_deletedRoleIsNotAdminDefining() {
    stubDeletableBenignRole();
    when(roleManagementPort.softDeleteRole(eq(roleId), eq(tenantId), any(Instant.class)))
        .thenReturn(1);
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(tenantId, List.of(roleId)))
        .thenReturn(List.of());

    service.softDeleteRole(actor, roleId, ctx);

    verify(userRoleAssignmentPort, never()).findRolePermissionIdsForTenantRoles(any());
    verify(userRoleAssignmentPort, times(1)).lockActiveAssignmentHolders(any(), any());
  }

  @Test
  void should_throwRoleNotFound_when_deleteRoleDoesNotExistOrIsAlreadyDeleted() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.softDeleteRole(actor, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");

    verifyNoInteractions(rbacAuditPort);
    verify(roleManagementPort, never()).softDeleteRole(any(), any(), any());
  }

  @Test
  void should_throwSameRoleNotFound_when_deleteRoleInAnotherTenant() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(otherTenantId)));

    assertThatThrownBy(() -> service.softDeleteRole(actor, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND")
        .hasMessage("No such role");

    verifyNoInteractions(rbacAuditPort);
    verify(roleManagementPort, never()).softDeleteRole(any(), any(), any());
  }

  /** RC-35: role-subset runs before the system-role 409, so a caller without the permissions sees 403. */
  @Test
  void should_deny403BeforeTheSystemRole409_when_callerLacksTheRolesPermissions() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(systemRole("MEMBER")));
    stubRolePermissions(Set.of(P1));
    stubCallerHoldsRefs();

    assertThatThrownBy(() -> service.softDeleteRole(actor, roleId, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    verify(roleManagementPort, never()).softDeleteRole(any(), any(), any());
    verifyNoInteractions(rbacAuditPort);
  }

  @Test
  void should_throwSystemRoleImmutable_when_deleteRoleIsSystemRoleAndCallerPassesSubset() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(systemRole("MEMBER")));
    stubRolePermissions(Set.of(P1));
    stubCallerHoldsRefs(new RolePermissionRef(UUID.randomUUID(), P1));

    assertThatThrownBy(() -> service.softDeleteRole(actor, roleId, ctx))
        .isInstanceOf(SystemRoleImmutableException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_003");

    verify(roleManagementPort, never()).softDeleteRole(any(), any(), any());
  }

  /** RC-35.2: a non-administrator may not delete a holder-less admin-defining role. */
  @Test
  void should_deny403_when_nonAdministratorDeletesAnAdminDefiningRole() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    stubRolePermissions(CATALOGUE);
    // Holds every permission, but only through the role being deleted: no other administrator role.
    stubCallerHoldsRefs(new RolePermissionRef(roleId, P1), new RolePermissionRef(roleId, P2));

    assertThatThrownBy(() -> service.softDeleteRole(actor, roleId, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(roleManagementPort, never()).softDeleteRole(any(), any(), any());
  }

  /** RC-46: on an admin-defining role the set lock (M10' then M11) precedes the UPDATE. */
  @Test
  void should_takeTheSetLockBeforeTheUpdate_when_deletingAnAdminDefiningRole() {
    UUID otherAdminRoleId = UUID.randomUUID();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    stubRolePermissions(CATALOGUE);
    stubCallerHoldsRefs(
        new RolePermissionRef(otherAdminRoleId, P1), new RolePermissionRef(otherAdminRoleId, P2));
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId))
        .thenReturn(
            List.of(
                new RolePermissionRef(roleId, P1),
                new RolePermissionRef(roleId, P2),
                new RolePermissionRef(otherAdminRoleId, P1),
                new RolePermissionRef(otherAdminRoleId, P2)));
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(eq(tenantId), any()))
        .thenReturn(List.of());
    when(roleManagementPort.softDeleteRole(eq(roleId), eq(tenantId), any(Instant.class)))
        .thenReturn(1);

    service.softDeleteRole(actor, roleId, ctx);

    InOrder order = inOrder(userRoleAssignmentPort, roleManagementPort, rbacAuditPort);
    order.verify(userRoleAssignmentPort).findRolePermissionIdsForTenantRoles(tenantId);
    ArgumentCaptor<List<UUID>> lockSet = ArgumentCaptor.forClass(List.class);
    order.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), lockSet.capture());
    order.verify(roleManagementPort).softDeleteRole(eq(roleId), eq(tenantId), any(Instant.class));
    order.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(tenantId, List.of(roleId));
    order.verify(rbacAuditPort).recordRoleDeleted(any(RoleAuditEvent.class));
    assertThat(lockSet.getValue()).containsExactlyInAnyOrder(roleId, otherAdminRoleId);
  }

  @Test
  void should_throwRoleHasHoldersAndWriteNoAudit_when_anActiveAssignmentExists() {
    stubDeletableBenignRole();
    when(roleManagementPort.softDeleteRole(eq(roleId), eq(tenantId), any(Instant.class)))
        .thenReturn(1);
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(tenantId, List.of(roleId)))
        .thenReturn(List.of(holder(roleId)));

    assertThatThrownBy(() -> service.softDeleteRole(actor, roleId, ctx))
        .isInstanceOf(RoleHasHoldersException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_009");

    verifyNoInteractions(rbacAuditPort);
  }

  @Test
  void should_throwRoleNotFoundAndReadNoHolders_when_theUpdateAffectsNoRow() {
    stubDeletableBenignRole();
    when(roleManagementPort.softDeleteRole(eq(roleId), eq(tenantId), any(Instant.class)))
        .thenReturn(0);

    assertThatThrownBy(() -> service.softDeleteRole(actor, roleId, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verifyNoInteractions(rbacAuditPort);
  }

  @Test
  void should_propagateAuditFailure_when_deleteAuditWriteFails() {
    stubDeletableBenignRole();
    when(roleManagementPort.softDeleteRole(eq(roleId), eq(tenantId), any(Instant.class)))
        .thenReturn(1);
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(tenantId, List.of(roleId)))
        .thenReturn(List.of());
    RuntimeException auditFailure = new IllegalStateException("audit down");
    doThrow(auditFailure).when(rbacAuditPort).recordRoleDeleted(any(RoleAuditEvent.class));

    assertThatThrownBy(() -> service.softDeleteRole(actor, roleId, ctx)).isSameAs(auditFailure);
  }

  /**
   * A-17: with the "no active holders" precondition no holder carries the role, so a delete bumps
   * nobody. If that precondition is ever relaxed this test must be replaced by one proving
   * invalidateHolders runs only inside afterCommit.
   */
  @Test
  void should_neverBumpOrEvict_when_roleDeleted() {
    stubDeletableBenignRole();
    when(roleManagementPort.softDeleteRole(eq(roleId), eq(tenantId), any(Instant.class)))
        .thenReturn(1);
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(tenantId, List.of(roleId)))
        .thenReturn(List.of());

    service.softDeleteRole(actor, roleId, ctx);

    verifyNoInteractions(permissionFreshness, permissionCachePort);
  }

  // ---------------------------------------------------------------------------------------
  // updateRole() -- US-018 C1 (T-027): 404 -> 403 (role-subset) -> 409 RBAC_003 -> RBAC_007
  // -> UPDATE (0 rows 404, RBAC_006) -> audit
  // ---------------------------------------------------------------------------------------

  private RoleView renamed(String name, String description) {
    return new RoleView(roleId, tenantId, name, description, false, Instant.now());
  }

  @Test
  void should_renameAndAudit_when_callerHoldsTheRolesPermissions() {
    stubDeletableBenignRole();
    when(roleManagementPort.updateRole(roleId, tenantId, "Renamed", "desc")).thenReturn(1);
    when(roleManagementPort.findRole(roleId))
        .thenReturn(Optional.of(customRole(tenantId)), Optional.of(renamed("Renamed", "desc")));

    RoleView result = service.updateRole(actor, roleId, "Renamed", null, ctx);

    assertThat(result.name()).isEqualTo("Renamed");
    verify(rbacAuditPort)
        .recordRoleUpdated(
            new RoleUpdateAuditEvent(
                tenantId, roleId, "Renamed", "Custom Role", "Renamed", List.of("name"), actorId,
                ctx));
  }

  @Test
  void should_keepTheName_when_onlyTheDescriptionChanges() {
    stubDeletableBenignRole();
    when(roleManagementPort.updateRole(roleId, tenantId, "Custom Role", "new text")).thenReturn(1);
    when(roleManagementPort.findRole(roleId))
        .thenReturn(
            Optional.of(customRole(tenantId)), Optional.of(renamed("Custom Role", "new text")));

    service.updateRole(actor, roleId, null, "new text", ctx);

    ArgumentCaptor<RoleUpdateAuditEvent> event = ArgumentCaptor.forClass(RoleUpdateAuditEvent.class);
    verify(rbacAuditPort).recordRoleUpdated(event.capture());
    assertThat(event.getValue().changedFields()).containsExactly("description");
    assertThat(event.getValue().oldName()).isNull();
    assertThat(event.getValue().newName()).isNull();
  }

  /** The audit event has no field that could carry the description text. */
  @Test
  void should_neverCarryTheDescriptionText_when_auditing() {
    stubDeletableBenignRole();
    when(roleManagementPort.updateRole(any(), any(), any(), any())).thenReturn(1);
    when(roleManagementPort.findRole(roleId))
        .thenReturn(Optional.of(customRole(tenantId)), Optional.of(renamed("X", "SECRET-TEXT")));

    service.updateRole(actor, roleId, "X", "SECRET-TEXT", ctx);

    ArgumentCaptor<RoleUpdateAuditEvent> event = ArgumentCaptor.forClass(RoleUpdateAuditEvent.class);
    verify(rbacAuditPort).recordRoleUpdated(event.capture());
    assertThat(event.getValue().toString()).doesNotContain("SECRET-TEXT");
    assertThat(event.getValue().changedFields()).containsExactly("name", "description");
  }

  @Test
  void should_clearTheDescription_when_itIsEmpty() {
    stubDeletableBenignRole();
    when(roleManagementPort.updateRole(roleId, tenantId, "Custom Role", null)).thenReturn(1);
    when(roleManagementPort.findRole(roleId))
        .thenReturn(Optional.of(customRole(tenantId)), Optional.of(renamed("Custom Role", null)));

    service.updateRole(actor, roleId, null, "", ctx);

    verify(roleManagementPort).updateRole(roleId, tenantId, "Custom Role", null);
  }

  @Test
  void should_doNothing_when_noFieldActuallyChanges() {
    stubDeletableBenignRole();

    RoleView result = service.updateRole(actor, roleId, "Custom Role", "desc", ctx);

    assertThat(result.name()).isEqualTo("Custom Role");
    verify(roleManagementPort, never()).updateRole(any(), any(), any(), any());
    verifyNoInteractions(rbacAuditPort);
  }

  @Test
  void should_throwRoleNotFound_when_updateRoleIsMissingDeletedOrForeign() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.empty());
    assertThatThrownBy(() -> service.updateRole(actor, roleId, "X", null, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");

    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(otherTenantId)));
    assertThatThrownBy(() -> service.updateRole(actor, roleId, "X", null, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");

    verify(roleManagementPort, never()).updateRole(any(), any(), any(), any());
    verifyNoInteractions(rbacAuditPort);
  }

  /** RC-35.1: role-subset precedes every 409, here the reserved-name one. */
  @Test
  void should_deny403BeforeAnyConflict_when_callerLacksTheRolesPermissions() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(systemRole("MEMBER")));
    stubRolePermissions(Set.of(P1));
    stubCallerHoldsRefs();

    assertThatThrownBy(() -> service.updateRole(actor, roleId, "TENANT_ADMIN", null, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    verify(roleManagementPort, never()).updateRole(any(), any(), any(), any());
  }

  /** RC-35.2: a non-administrator may not rename an admin-defining role to a benign name. */
  @Test
  void should_deny403_when_nonAdministratorRenamesAnAdminDefiningRole() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    stubRolePermissions(CATALOGUE);
    stubCallerHoldsRefs(new RolePermissionRef(roleId, P1), new RolePermissionRef(roleId, P2));

    assertThatThrownBy(() -> service.updateRole(actor, roleId, "Read Only", null, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verify(roleManagementPort, never()).updateRole(any(), any(), any(), any());
    verifyNoInteractions(rbacAuditPort);
  }

  @Test
  void should_throwSystemRoleImmutable_when_updatingASystemRoleAndCallerPassesSubset() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(systemRole("MEMBER")));
    stubRolePermissions(Set.of(P1));
    stubCallerHoldsRefs(new RolePermissionRef(UUID.randomUUID(), P1));

    assertThatThrownBy(() -> service.updateRole(actor, roleId, "Other", null, ctx))
        .isInstanceOf(SystemRoleImmutableException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_003");
  }

  @Test
  void should_throwReservedRoleName_when_renamingToAReservedNameInAnyCase() {
    stubDeletableBenignRole();

    assertThatThrownBy(() -> service.updateRole(actor, roleId, "tenant_admin", null, ctx))
        .isInstanceOf(ReservedRoleNameException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_007");

    verify(roleManagementPort, never()).updateRole(any(), any(), any(), any());
  }

  @Test
  void should_propagateDuplicateName_when_theStoreRejectsTheNewName() {
    stubDeletableBenignRole();
    when(roleManagementPort.updateRole(any(), any(), any(), any()))
        .thenThrow(new DuplicateRoleNameException());

    assertThatThrownBy(() -> service.updateRole(actor, roleId, "Taken", null, ctx))
        .isInstanceOf(DuplicateRoleNameException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_006");

    verifyNoInteractions(rbacAuditPort);
  }

  @Test
  void should_throwRoleNotFound_when_theUpdateAffectsNoRow() {
    stubDeletableBenignRole();
    when(roleManagementPort.updateRole(any(), any(), any(), any())).thenReturn(0);

    assertThatThrownBy(() -> service.updateRole(actor, roleId, "Renamed", null, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");

    verifyNoInteractions(rbacAuditPort);
  }

  @Test
  void should_propagateAuditFailure_when_updateAuditWriteFails() {
    stubDeletableBenignRole();
    when(roleManagementPort.updateRole(any(), any(), any(), any())).thenReturn(1);
    RuntimeException auditFailure = new IllegalStateException("audit down");
    doThrow(auditFailure).when(rbacAuditPort).recordRoleUpdated(any(RoleUpdateAuditEvent.class));

    assertThatThrownBy(() -> service.updateRole(actor, roleId, "Renamed", null, ctx))
        .isSameAs(auditFailure);
  }

  /** A rename is cosmetic for authorization: no epoch bump, no cache eviction. */
  @Test
  void should_neverBumpOrEvict_when_roleRenamed() {
    stubDeletableBenignRole();
    when(roleManagementPort.updateRole(any(), any(), any(), any())).thenReturn(1);
    when(roleManagementPort.findRole(roleId))
        .thenReturn(Optional.of(customRole(tenantId)), Optional.of(renamed("Renamed", "desc")));

    service.updateRole(actor, roleId, "Renamed", null, ctx);

    verifyNoInteractions(permissionFreshness, permissionCachePort);
  }

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
