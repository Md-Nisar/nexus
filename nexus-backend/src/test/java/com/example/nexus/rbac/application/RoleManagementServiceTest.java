package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
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
import com.example.nexus.common.domain.PreconditionFailedException;
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
import com.example.nexus.rbac.domain.RoleClassificationChangedException;
import com.example.nexus.rbac.domain.RolePermissionRef;
import com.example.nexus.rbac.domain.RolePermissionSet;
import com.example.nexus.rbac.domain.RolePermissionSetVersion;
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

  // The assigner of a locked holder row; irrelevant to every test here except where named.
  private static final UUID ANY_ASSIGNER = UUID.randomUUID();

  private static final long MAX_ROLES_PER_TENANT = 500L;
  private static final String ROLE_WRITE = "role:write";
  private static final String ROLE_READ = "role:read";
  private static final UUID ROLE_WRITE_ID = RbacSeededPermissionIds.ROLE_WRITE;
  private static final UUID USER_ROLE_ASSIGN_ID = RbacSeededPermissionIds.USER_ROLE_ASSIGN;
  private static final UUID USER_DIRECTORY_READ_ID = RbacSeededPermissionIds.USER_DIRECTORY_READ;

  // Fixture catalogue: two permissions. A role carrying both is admin-defining (ADR-0021 D3).
  private static final UUID P1 = UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final UUID P2 = UUID.fromString("00000000-0000-7000-8000-000000000002");
  private static final Set<UUID> CATALOGUE = Set.of(P1, P2);
  private static final UUID REPLACE_ID = UUID.fromString("019f6839-2000-7000-8000-0000000000aa");

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
            new PiiPermissionGrantRule(true, meterRegistry),
            () -> REPLACE_ID,
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
    // The role row is live when an attach or a replace locks it (RC-64); a test may override.
    lenient().when(roleManagementPort.lockRoleRow(any(), any())).thenReturn(true);
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

    RolePermissionSet set = service.listRolePermissions(actor, roleId);

    assertThat(set.permissions()).containsExactly(permission);
    assertThat(set.version()).isEqualTo(RolePermissionSetVersion.of(roleId, List.of(permissionId)));
  }

  @Test
  void should_returnEmptyList_when_roleHasNoPermissionsAttached() {
    RoleView role = customRole(tenantId);
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(roleManagementPort.findPermissionsForRole(roleId)).thenReturn(List.of());

    assertThat(service.listRolePermissions(actor, roleId).permissions()).isEmpty();
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

  // ---------------------------------------------------------------------------------------
  // attachPermission() -- US-019 T-007: administrator-only grant of user:directory:read (RC-60)
  // ---------------------------------------------------------------------------------------

  private void stubDirectoryReadAttach() {
    permissionId = USER_DIRECTORY_READ_ID;
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(roleManagementPort.findPermission(permissionId))
        .thenReturn(
            Optional.of(
                new PermissionView(permissionId, "user:directory:read", "Read the directory")));
  }

  /** M13: one admin-defining role (the whole fixture catalogue), plus role:write and the PII id. */
  private void stubCallerIsAdministratorHoldingDirectoryRead() {
    UUID adminDefiningRoleId = UUID.randomUUID();
    stubCallerHoldsRefs(
        new RolePermissionRef(adminDefiningRoleId, P1),
        new RolePermissionRef(adminDefiningRoleId, P2),
        new RolePermissionRef(UUID.randomUUID(), ROLE_WRITE_ID),
        new RolePermissionRef(UUID.randomUUID(), USER_DIRECTORY_READ_ID));
  }

  @Test
  void should_denyNotTenantAdminWithWarnAndNoAudit_when_nonAdministratorHolderAttachesDirectoryRead() {
    stubDirectoryReadAttach();
    stubCallerHolds(USER_DIRECTORY_READ_ID);

    ListAppender<ILoggingEvent> ruleLogs = startRuleLogCapture();
    try {
      assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
          .isInstanceOfSatisfying(
              InsufficientPermissionException.class,
              e -> {
                assertThat(e.getReason()).isEqualTo(DenialReason.NOT_TENANT_ADMIN);
                assertThat(e.getRequiredPermission()).isEqualTo(ROLE_WRITE);
              });

      assertThat(ruleLogs.list)
          .singleElement()
          .satisfies(
              warn -> {
                assertThat(warn.getLevel()).isEqualTo(Level.WARN);
                assertThat(keyValueMap(warn))
                    .containsEntry("event", "RBAC_PII_PERMISSION_GRANT_DENIED")
                    .containsEntry("tenantId", tenantId)
                    .containsEntry("actorUserId", actorId)
                    .containsEntry("roleId", roleId)
                    .containsEntry("operation", "attach");
              });
    } finally {
      stopLogCapture(ruleLogs, PiiPermissionGrantRule.class);
    }

    // Before the duplicate check and the insert; Decision 7: no audit row on attach.
    verify(roleManagementPort, never()).hasPermission(any(), any());
    verify(roleManagementPort, never()).attachPermission(any(), any());
    verifyNoInteractions(rbacAuditPort, permissionCachePort);
    assertThat(meterRegistry.get("nexus.rbac.pii_permission_delegated").counter().count())
        .isZero();
  }

  /**
   * RC-66.1: an empty catalogue read makes nobody an administrator (MC-1), so the rule denies; it
   * never turns missing evidence into an allow.
   */
  @Test
  void should_deny_when_catalogueReadsBackEmpty() {
    stubDirectoryReadAttach();
    stubCallerIsAdministratorHoldingDirectoryRead();
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(Set.of());

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> assertThat(e.getReason()).isEqualTo(DenialReason.NOT_TENANT_ADMIN));
  }

  /** RC-66.1: A3 runs first, so a non-holder never learns the rule exists. */
  @Test
  void should_denyGrantExceedsCallerNeverNotTenantAdmin_when_nonHolderAttachesDirectoryRead() {
    stubDirectoryReadAttach();
    stubCallerHolds(UUID.randomUUID());

    ListAppender<ILoggingEvent> ruleLogs = startRuleLogCapture();
    try {
      assertThatThrownBy(() -> service.attachPermission(actor, roleId, permissionId, ctx))
          .isInstanceOfSatisfying(
              InsufficientPermissionException.class,
              e -> assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));
      assertThat(ruleLogs.list).isEmpty();
    } finally {
      stopLogCapture(ruleLogs, PiiPermissionGrantRule.class);
    }
  }

  @Test
  void should_attachAndEmitNothing_when_administratorAttachesDirectoryRead() {
    stubDirectoryReadAttach();
    stubCallerIsAdministratorHoldingDirectoryRead();
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(false);

    ListAppender<ILoggingEvent> ruleLogs = startRuleLogCapture();
    try {
      service.attachPermission(actor, roleId, permissionId, ctx);
      assertThat(ruleLogs.list).isEmpty();
    } finally {
      stopLogCapture(ruleLogs, PiiPermissionGrantRule.class);
    }

    verify(roleManagementPort).attachPermission(roleId, permissionId);
    assertThat(meterRegistry.get("nexus.rbac.pii_permission_delegated").counter().count())
        .isZero();
  }

  @Test
  void should_attachAndEmitDelegatedWarnAndCounterOnce_when_ruleOffAndNonAdministratorAttaches() {
    RoleManagementService ruleOffService = serviceWithRule(false);
    stubDirectoryReadAttach();
    stubCallerHolds(USER_DIRECTORY_READ_ID);
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(false);

    ListAppender<ILoggingEvent> ruleLogs = startRuleLogCapture();
    try {
      ruleOffService.attachPermission(actor, roleId, permissionId, ctx);

      assertThat(ruleLogs.list)
          .singleElement()
          .satisfies(
              warn -> {
                assertThat(warn.getLevel()).isEqualTo(Level.WARN);
                Map<String, Object> fields = keyValueMap(warn);
                assertThat(fields)
                    .containsEntry("event", "RBAC_PII_PERMISSION_DELEGATED")
                    .containsEntry("tenantId", tenantId)
                    .containsEntry("actorUserId", actorId)
                    .containsEntry("roleId", roleId);
                assertThat(fields.get("targetUserId")).isNull();
              });
    } finally {
      stopLogCapture(ruleLogs, PiiPermissionGrantRule.class);
    }

    verify(roleManagementPort).attachPermission(roleId, permissionId);
    Counter delegated = meterRegistry.find("nexus.rbac.pii_permission_delegated").counter();
    assertThat(delegated).isNotNull();
    assertThat(delegated.count()).isEqualTo(1.0);
  }

  /** The detective signal is after commit: an uncommitted attach emits nothing. */
  @Test
  void should_notEmitDelegatedSignal_when_attachDoesNotCommit() {
    RoleManagementService ruleOffService = serviceWithRule(false);
    stubDirectoryReadAttach();
    stubCallerHolds(USER_DIRECTORY_READ_ID);
    when(roleManagementPort.hasPermission(roleId, permissionId)).thenReturn(false);

    inUncommittedSynchronization(
        () -> ruleOffService.attachPermission(actor, roleId, permissionId, ctx));

    assertThat(meterRegistry.get("nexus.rbac.pii_permission_delegated").counter().count())
        .isZero();
  }

  private RoleManagementService serviceWithRule(boolean enforced) {
    return new RoleManagementService(
        roleManagementPort,
        userRoleAssignmentPort,
        rbacAuditPort,
        permissionFreshness,
        permissionCachePort,
        transactionManager,
        meterRegistry,
        new PiiPermissionGrantRule(enforced, meterRegistry),
        () -> REPLACE_ID,
        MAX_ROLES_PER_TENANT);
  }

  private static ListAppender<ILoggingEvent> startRuleLogCapture() {
    Logger logger = (Logger) LoggerFactory.getLogger(PiiPermissionGrantRule.class);
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
  // US-019 T-020 (design §10.9; RC-64, RC-56.3): attach locks the role row before its insert,
  // and a post-insert current read rolls back an attach the role outgrew (409 RBAC_012)
  // ---------------------------------------------------------------------------------------

  /** The role carries nothing in the snapshot, so attaching P1 leaves it one short. */
  private void stubNonCompletingAttach() {
    permissionId = P1;
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(roleManagementPort.findPermission(P1))
        .thenReturn(Optional.of(new PermissionView(P1, "user:read", "Read users")));
    stubCallerHolds(P1);
    when(roleManagementPort.hasPermission(roleId, P1)).thenReturn(false);
  }

  @Test
  void should_lockTheRoleRowThenInsertThenReadCurrentThenAudit_when_attaching() {
    stubNonCompletingAttach();
    when(roleManagementPort.lockPermissionIdsForRole(roleId)).thenReturn(Set.of(P1));

    inUncommittedSynchronization(() -> service.attachPermission(actor, roleId, P1, ctx));

    InOrder order = inOrder(roleManagementPort, rbacAuditPort);
    order.verify(roleManagementPort).hasPermission(roleId, P1);
    order.verify(roleManagementPort).lockRoleRow(roleId, tenantId);
    order.verify(roleManagementPort).attachPermission(roleId, P1);
    order.verify(roleManagementPort).lockPermissionIdsForRole(roleId);
    order.verify(rbacAuditPort).recordRolePermissionGranted(any());
  }

  /**
   * RC-56.3: the snapshot said this attach leaves R one short, but an attach of the other missing
   * permission committed while this one waited on the role row. The current read sees R complete:
   * 409 RBAC_012, no audit call, nothing after commit.
   */
  @Test
  void should_throw409Rbac012WithNoAuditCall_when_thePostInsertReadShowsTheAttachCompletedTheCatalogue() {
    stubNonCompletingAttach();
    when(roleManagementPort.lockPermissionIdsForRole(roleId)).thenReturn(CATALOGUE);

    assertThatThrownBy(
            () ->
                inUncommittedSynchronization(
                    () -> service.attachPermission(actor, roleId, P1, ctx)))
        .isInstanceOf(RoleClassificationChangedException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_012");

    verifyNoInteractions(rbacAuditPort, permissionCachePort, permissionFreshness);
    assertThat(
            meterRegistry
                .get("nexus.rbac.role_classification_changed")
                .tag("operation", "attach")
                .counter()
                .count())
        .isEqualTo(1.0);
  }

  /** A completing attach was already judged by RBAC_010 on its snapshot: no RBAC_012 for it. */
  @Test
  void should_attachWithoutRbac012_when_theSnapshotAlreadySaidTheAttachCompletesTheCatalogue() {
    stubCompletingAttach();
    when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId)).thenReturn(List.of());
    when(roleManagementPort.hasPermission(roleId, P2)).thenReturn(false);
    when(roleManagementPort.lockPermissionIdsForRole(roleId)).thenReturn(CATALOGUE);

    inUncommittedSynchronization(() -> service.attachPermission(actor, roleId, P2, ctx));

    verify(rbacAuditPort).recordRolePermissionGranted(any());
    assertThat(meterRegistry.find("nexus.rbac.role_classification_changed").counter()).isNull();
  }

  /** A DELETE that committed while the attach waited leaves no live row to lock: 404, no insert. */
  @Test
  void should_throwRoleNotFoundAndInsertNothing_when_theRoleRowIsGoneAtLockTime() {
    stubNonCompletingAttach();
    when(roleManagementPort.lockRoleRow(roleId, tenantId)).thenReturn(false);

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, P1, ctx))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");

    verify(roleManagementPort, never()).attachPermission(any(), any());
    verify(roleManagementPort, never()).lockPermissionIdsForRole(any());
    verifyNoInteractions(rbacAuditPort);
  }

  /** Locks only after authorization (ADR-0018 follow-on rule): a denied caller takes no lock. */
  @Test
  void should_neverLockTheRoleRow_when_a3DeniesTheAttach() {
    permissionId = P1;
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(roleManagementPort.findPermission(P1))
        .thenReturn(Optional.of(new PermissionView(P1, "user:read", "Read users")));
    stubCallerHolds();

    assertThatThrownBy(() -> service.attachPermission(actor, roleId, P1, ctx))
        .isInstanceOf(InsufficientPermissionException.class);

    verifyNoLockTaken();
  }

  // ---------------------------------------------------------------------------------------
  // US-019 T-020 (RC-56.4): the committed-state detector, after commit, on attach and B8
  // ---------------------------------------------------------------------------------------

  private static final String DETECTOR_EVENT =
      "RBAC_ADMIN_DEFINING_ROLE_HAS_NON_ADMIN_ASSIGNED_HOLDER";
  private static final String DETECTOR_COUNTER =
      "nexus.rbac.admin_defining_role_non_admin_assigned_holder";

  /**
   * A completing attach whose one holder was assigned by {@code assigner}. In the transaction the
   * tenant's only admin-defining role is another one and {@code assigner} holds it (RBAC_010
   * passes); after commit R itself is admin-defining and the administrators are {@code
   * administratorsAfterCommit}.
   */
  private void stubCompletingAttachWithHolderAssignedBy(
      UUID assigner, Set<UUID> administratorsAfterCommit) {
    stubCompletingAttach();
    when(roleManagementPort.hasPermission(roleId, P2)).thenReturn(false);
    when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId))
        .thenReturn(List.of(new HolderProvenance(UUID.randomUUID(), assigner)));
    UUID adminRoleId = UUID.randomUUID();
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId))
        .thenReturn(
            List.of(new RolePermissionRef(adminRoleId, P1), new RolePermissionRef(adminRoleId, P2)))
        .thenReturn(
            List.of(
                new RolePermissionRef(adminRoleId, P1),
                new RolePermissionRef(adminRoleId, P2),
                new RolePermissionRef(roleId, P1),
                new RolePermissionRef(roleId, P2)));
    when(userRoleAssignmentPort.findActiveHolderUserIdsForRoles(tenantId, Set.of(adminRoleId)))
        .thenReturn(Set.of(assigner));
    when(userRoleAssignmentPort.findActiveHolderUserIdsForRoles(
            tenantId, Set.of(adminRoleId, roleId)))
        .thenReturn(administratorsAfterCommit);
  }

  @Test
  void should_warnAndCountTheUntaggedPagingDetector_when_afterCommitAnAdminDefiningRoleHasANonAdministratorAssignedHolder() {
    stubCompletingAttachWithHolderAssignedBy(UUID.randomUUID(), Set.of());

    ListAppender<ILoggingEvent> appender =
        startLogCapture(AdminDefiningRoleProvenanceDetector.class);
    try {
      service.attachPermission(actor, roleId, permissionId, ctx);

      assertThat(appender.list)
          .singleElement()
          .satisfies(
              warn -> {
                assertThat(warn.getLevel()).isEqualTo(Level.WARN);
                assertThat(keyValueMap(warn))
                    .containsOnly(
                        Map.entry("event", DETECTOR_EVENT),
                        Map.entry("tenantId", tenantId),
                        Map.entry("roleId", roleId),
                        Map.entry("holderCount", 1),
                        Map.entry("nonAdminAssignedCount", 1));
              });
    } finally {
      stopLogCapture(appender, AdminDefiningRoleProvenanceDetector.class);
    }
    Counter detector = meterRegistry.get(DETECTOR_COUNTER).counter();
    assertThat(detector.count()).isEqualTo(1.0);
    assertThat(detector.getId().getTags()).isEmpty();
  }

  @Test
  void should_staySilent_when_afterCommitEveryHolderOfTheAdminDefiningRoleWasAssignedByAnAdministrator() {
    UUID administrator = UUID.randomUUID();
    stubCompletingAttachWithHolderAssignedBy(administrator, Set.of(administrator));

    ListAppender<ILoggingEvent> appender =
        startLogCapture(AdminDefiningRoleProvenanceDetector.class);
    try {
      service.attachPermission(actor, roleId, permissionId, ctx);

      assertThat(appender.list).isEmpty();
    } finally {
      stopLogCapture(appender, AdminDefiningRoleProvenanceDetector.class);
    }
    assertThat(meterRegistry.find(DETECTOR_COUNTER).counter()).isNull();
  }

  /** A non-administrator-assigned holder on a role that is not admin-defining is row 13's, not this. */
  @Test
  void should_staySilent_when_theRoleWithANonAdministratorAssignedHolderIsNotAdminDefining() {
    stubBenignAttachWithHolders(holdersAssignedBy(UUID.randomUUID(), 1), Set.of(UUID.randomUUID()));

    service.attachPermission(actor, roleId, permissionId, ctx);

    assertThat(meterRegistry.find(DETECTOR_COUNTER).counter()).isNull();
    assertThat(meterRegistry.find("nexus.rbac.attach_escalates_non_admin_assigned").counter())
        .isNotNull();
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
    return new ActiveAssignmentHolder(
            UUID.randomUUID(), UUID.randomUUID(), holderRoleId, ANY_ASSIGNER);
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

  /**
   * An admin-defining role being deleted while the caller is an administrator through {@code
   * otherAdminRoleId}: M10' and the snapshot holdings say both roles carry the whole catalogue, the
   * set lock returns the caller's row of the other role, and the locked current read returns
   * {@code currentRows}.
   */
  private void stubAdminDefiningDelete(UUID otherAdminRoleId, List<RolePermissionRef> currentRows) {
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
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(
            eq(tenantId), argThat(ids -> ids.size() == 2)))
        .thenReturn(
            List.of(
                new ActiveAssignmentHolder(
                    UUID.randomUUID(), actorId, otherAdminRoleId, ANY_ASSIGNER)));
    when(userRoleAssignmentPort.lockRolePermissionsForRoles(eq(tenantId), any()))
        .thenReturn(currentRows);
    when(roleManagementPort.softDeleteRole(eq(roleId), eq(tenantId), any(Instant.class)))
        .thenReturn(1);
  }

  /**
   * RC-46: on an admin-defining role the set lock (M10' then M11) precedes the UPDATE; RC-57.2:
   * the current read of the lock set comes after the UPDATE's role-row lock and before the holder
   * check.
   */
  @Test
  void should_takeTheSetLockBeforeTheUpdate_when_deletingAnAdminDefiningRole() {
    UUID otherAdminRoleId = UUID.randomUUID();
    stubAdminDefiningDelete(
        otherAdminRoleId,
        List.of(
            new RolePermissionRef(roleId, P1),
            new RolePermissionRef(roleId, P2),
            new RolePermissionRef(otherAdminRoleId, P1),
            new RolePermissionRef(otherAdminRoleId, P2)));
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(tenantId, List.of(roleId)))
        .thenReturn(List.of());

    service.softDeleteRole(actor, roleId, ctx);

    InOrder order = inOrder(userRoleAssignmentPort, roleManagementPort, rbacAuditPort);
    order.verify(userRoleAssignmentPort).findRolePermissionIdsForTenantRoles(tenantId);
    ArgumentCaptor<List<UUID>> lockSet = ArgumentCaptor.forClass(List.class);
    order.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(eq(tenantId), lockSet.capture());
    order.verify(roleManagementPort).softDeleteRole(eq(roleId), eq(tenantId), any(Instant.class));
    order.verify(userRoleAssignmentPort).lockRolePermissionsForRoles(tenantId, lockSet.getValue());
    order.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(tenantId, List.of(roleId));
    order.verify(rbacAuditPort).recordRoleDeleted(any(RoleAuditEvent.class));
    assertThat(lockSet.getValue()).containsExactlyInAnyOrder(roleId, otherAdminRoleId);
  }

  /**
   * RC-57.2 (SD-17): the caller's other administrator role was demoted while the delete waited on
   * the set lock. Judged from the locked rows and the current read, the caller is no longer an
   * administrator through another role: 403 GRANT_EXCEEDS_CALLER before the holder check, no audit.
   */
  @Test
  void should_deny403BeforeTheHolderCheck_when_theCallersOtherAdminRoleIsNoLongerAdminDefiningUnderTheSetLock() {
    UUID otherAdminRoleId = UUID.randomUUID();
    stubAdminDefiningDelete(
        otherAdminRoleId,
        List.of(
            new RolePermissionRef(roleId, P1),
            new RolePermissionRef(roleId, P2),
            new RolePermissionRef(otherAdminRoleId, P1)));

    assertThatThrownBy(() -> service.softDeleteRole(actor, roleId, ctx))
        .isInstanceOfSatisfying(
            InsufficientPermissionException.class,
            e -> assertThat(e.getReason()).isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER));

    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(tenantId, List.of(roleId));
    verifyNoInteractions(rbacAuditPort);
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

  // ---------------------------------------------------------------------------------------
  // replaceRolePermissions() -- US-019 B8, T-018 (design §10.3, role-row path): 404 -> 409 ->
  // 404 permission -> 403 (snapshot) -> 412 (snapshot) -> no-op -> lock -> 412 (current) -> write
  // ---------------------------------------------------------------------------------------

  private static final UUID ROLE_READ_ID = RbacSeededPermissionIds.ROLE_READ;
  private static final UUID P3 = UUID.fromString("00000000-0000-7000-8000-000000000003");
  // Five ids: a role is admin-defining only when it carries all five.
  private static final Set<UUID> REPLACE_CATALOGUE =
      Set.of(P1, P2, P3, ROLE_READ_ID, ROLE_WRITE_ID);

  /**
   * R is a custom role of the tenant carrying {@code snapshot}; the catalogue is {@link
   * #REPLACE_CATALOGUE}; the caller holds live role:read and role:write plus {@code held}, each
   * through its own random role.
   */
  private void stubReplace(Set<UUID> snapshot, UUID... held) {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(REPLACE_CATALOGUE);
    stubRolePermissions(snapshot);
    UUID[] withEndpointPermissions = Arrays.copyOf(held, held.length + 2);
    withEndpointPermissions[held.length] = ROLE_READ_ID;
    withEndpointPermissions[held.length + 1] = ROLE_WRITE_ID;
    stubCallerHoldsOnly(withEndpointPermissions);
  }

  /** Steps 8 and 9: the role row locks, and the current read returns {@code current}. */
  private void stubLockedState(Set<UUID> current) {
    when(roleManagementPort.lockRoleRow(roleId, tenantId)).thenReturn(true);
    when(roleManagementPort.lockPermissionIdsForRole(roleId)).thenReturn(current);
  }

  private String versionOf(Set<UUID> permissionIds) {
    return RolePermissionSetVersion.of(roleId, permissionIds);
  }

  private static List<PermissionView> viewsOf(UUID... ids) {
    return Arrays.stream(ids).map(id -> new PermissionView(id, "perm-" + id, "d")).toList();
  }

  private RolePermissionSet replace(Set<UUID> target, String ifMatch) {
    return service.replaceRolePermissions(actor, roleId, target, ifMatch, ctx);
  }

  private void verifyNoLockTaken() {
    verify(roleManagementPort, never()).lockRoleRow(any(), any());
    verify(roleManagementPort, never()).lockPermissionIdsForRole(any());
  }

  private void verifyNoWrite() {
    verify(roleManagementPort, never()).detachPermissions(any(), any());
    verify(roleManagementPort, never()).attachPermissions(any(), any());
    verifyNoInteractions(rbacAuditPort, permissionFreshness, permissionCachePort);
  }

  private double replaceCount(String outcome, String lockPath) {
    Counter counter =
        meterRegistry
            .find("nexus.rbac.permission_replace")
            .tag("outcome", outcome)
            .tag("lockPath", lockPath)
            .counter();
    return counter == null ? 0.0 : counter.count();
  }

  @Test
  void should_throwRoleNotFound_when_replacingOnAMissingRole() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> replace(Set.of(P1), versionOf(Set.of())))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");
    verifyNoInteractions(userRoleAssignmentPort);
    verifyNoLockTaken();
  }

  @Test
  void should_throwSameRoleNotFound_when_replacingOnAnotherTenantsRole() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(otherTenantId)));

    assertThatThrownBy(() -> replace(Set.of(P1), versionOf(Set.of())))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");
    verifyNoInteractions(userRoleAssignmentPort);
  }

  @Test
  void should_throwRbac003_when_replacingOnASystemRole() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(systemRole("MEMBER")));

    assertThatThrownBy(() -> replace(Set.of(P1), versionOf(Set.of())))
        .isInstanceOf(SystemRoleImmutableException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_003");
    verifyNoInteractions(userRoleAssignmentPort);
  }

  @Test
  void should_throwPermissionNotFound_beforeAnyAuthorizationRead_when_aTargetIdIsNotInTheCatalogue() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(REPLACE_CATALOGUE);

    assertThatThrownBy(() -> replace(Set.of(P1, UUID.randomUUID()), versionOf(Set.of())))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "PERMISSION_NOT_FOUND");
    verify(userRoleAssignmentPort, never()).findHeldRolePermissionIdsForAuthorization(any(), any());
    verifyNoLockTaken();
  }

  /** Unstubbed M13 (an empty list) means deny: no live role:write, so PERMISSION_ABSENT. */
  @Test
  void should_denyAsPermissionAbsent_when_liveHoldingsAreEmpty() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(REPLACE_CATALOGUE);
    stubRolePermissions(Set.of(P1));

    assertThatThrownBy(() -> replace(Set.of(P1), versionOf(Set.of(P1))))
        .isInstanceOf(InsufficientPermissionException.class)
        .extracting(e -> ((InsufficientPermissionException) e).getReason())
        .isEqualTo(DenialReason.PERMISSION_ABSENT);
    verifyNoLockTaken();
    verifyNoWrite();
  }

  /** L-1 on a no-op: a JWT role:write is not enough, the live M13 rows must still carry it. */
  @Test
  void should_throw403PermissionAbsent_onANoOp_when_liveHoldingsLackRoleWrite() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(REPLACE_CATALOGUE);
    stubRolePermissions(Set.of(P1));
    stubCallerHoldsOnly(ROLE_READ_ID, P1);

    assertThatThrownBy(() -> replace(Set.of(P1), versionOf(Set.of(P1))))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e -> {
              InsufficientPermissionException denial = (InsufficientPermissionException) e;
              assertThat(denial.getReason()).isEqualTo(DenialReason.PERMISSION_ABSENT);
              assertThat(denial.getRequiredPermission()).isEqualTo(ROLE_WRITE);
            });
    verify(roleManagementPort, never()).findPermissionsForRole(any());
    verifyNoLockTaken();
  }

  /** RC-58.4: a live role:read is required too, or a no-op would read the set without it. */
  @Test
  void should_throw403PermissionAbsent_onANoOp_when_liveHoldingsLackRoleRead() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(REPLACE_CATALOGUE);
    stubRolePermissions(Set.of(P1));
    stubCallerHoldsOnly(ROLE_WRITE_ID, P1);

    assertThatThrownBy(() -> replace(Set.of(P1), versionOf(Set.of(P1))))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e -> {
              InsufficientPermissionException denial = (InsufficientPermissionException) e;
              assertThat(denial.getReason()).isEqualTo(DenialReason.PERMISSION_ABSENT);
              assertThat(denial.getRequiredPermission()).isEqualTo(ROLE_READ);
            });
    verify(roleManagementPort, never()).findPermissionsForRole(any());
    verifyNoLockTaken();
  }

  /** A3: every added id must be held through an active assignment; one miss denies the PUT. */
  @Test
  void should_throw403GrantExceedsCaller_when_oneAddedPermissionIsNotHeld() {
    stubReplace(Set.of(P1), P1, P2);

    assertThatThrownBy(() -> replace(Set.of(P1, P2, P3), versionOf(Set.of(P1))))
        .isInstanceOf(InsufficientPermissionException.class)
        .extracting(e -> ((InsufficientPermissionException) e).getReason())
        .isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER);
    verifyNoLockTaken();
    verifyNoWrite();
  }

  /** Role-subset on removes: the caller must hold every permission of R. */
  @Test
  void should_throw403GrantExceedsCaller_when_removingFromARoleWhosePermissionsAreNotAllHeld() {
    stubReplace(Set.of(P1, P2), P1);

    assertThatThrownBy(() -> replace(Set.of(P1), versionOf(Set.of(P1, P2))))
        .isInstanceOf(InsufficientPermissionException.class)
        .extracting(e -> ((InsufficientPermissionException) e).getReason())
        .isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER);
    verifyNoLockTaken();
    verifyNoWrite();
  }

  /** T-I20 / RC-58.1: 403 precedes 412, so a stale tag tells an unauthorised caller nothing. */
  @Test
  void should_throw403Not412_when_anUnauthorisedRemoverSendsAStaleTag() {
    stubReplace(Set.of(P1, P2), P1);

    assertThatThrownBy(() -> replace(Set.of(P1), versionOf(Set.of(P3))))
        .isInstanceOf(InsufficientPermissionException.class);
    verifyNoLockTaken();
  }

  /** On demotion the caller must be an administrator through a role other than R. */
  @Test
  void should_throw403_when_demotingAnAdminDefiningRoleWithoutAdministratorStatusElsewhere() {
    stubReplace(REPLACE_CATALOGUE, P1, P2, P3);

    assertThatThrownBy(() -> replace(Set.of(P1), versionOf(REPLACE_CATALOGUE)))
        .isInstanceOf(InsufficientPermissionException.class)
        .extracting(e -> ((InsufficientPermissionException) e).getReason())
        .isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER);
    verifyNoLockTaken();
  }

  /** US-019 §4.8: adding user:directory:read needs an administrator while the rule is on. */
  @Test
  void should_throw403NotTenantAdmin_when_aNonAdministratorAddsTheDirectoryPermission() {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    Set<UUID> catalogue = Set.of(P1, ROLE_READ_ID, ROLE_WRITE_ID, USER_DIRECTORY_READ_ID, P2);
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(catalogue);
    stubRolePermissions(Set.of(P1));
    stubCallerHoldsOnly(ROLE_READ_ID, ROLE_WRITE_ID, P1, USER_DIRECTORY_READ_ID);

    assertThatThrownBy(
            () -> replace(Set.of(P1, USER_DIRECTORY_READ_ID), versionOf(Set.of(P1))))
        .isInstanceOf(InsufficientPermissionException.class)
        .extracting(e -> ((InsufficientPermissionException) e).getReason())
        .isEqualTo(DenialReason.NOT_TENANT_ADMIN);
    verifyNoLockTaken();
  }

  @Test
  void should_throw412WithoutTakingALock_when_ifMatchIsNotTheSnapshotVersion() {
    stubReplace(Set.of(P1), P1, P2);

    assertThatThrownBy(() -> replace(Set.of(P1, P2), versionOf(Set.of(P2))))
        .isInstanceOf(PreconditionFailedException.class)
        .hasFieldOrPropertyWithValue("code", "PRECONDITION_FAILED");
    verifyNoLockTaken();
    verifyNoWrite();
    assertThat(replaceCount("precondition_failed", "none")).isEqualTo(1.0);
  }

  /** The no-op is authorised (step 6) and then answered from the snapshot: no lock, no write. */
  @Test
  void should_returnTheSnapshotWithoutLockingOrWriting_when_theTargetEqualsTheSnapshot() {
    stubReplace(Set.of(P1, P2), P1, P2);
    List<PermissionView> views = viewsOf(P1, P2);
    when(roleManagementPort.findPermissionsForRole(roleId)).thenReturn(views);

    RolePermissionSet result = replace(Set.of(P2, P1), versionOf(Set.of(P1, P2)));

    assertThat(result.permissions()).isEqualTo(views);
    assertThat(result.version()).isEqualTo(versionOf(Set.of(P1, P2)));
    verifyNoLockTaken();
    verifyNoWrite();
    assertThat(replaceCount("noop", "none")).isEqualTo(1.0);
  }

  /**
   * RC-55.1 / T-T22: step 9 compares the locked current version with the snapshot version v0.
   * The client's tag is v0, so it passes step 7; a concurrent writer changed the set before the
   * lock, so the current read differs and the PUT is 412 with nothing written.
   */
  @Test
  void should_throw412_when_theLockedCurrentStateDiffersFromTheSnapshot() {
    stubReplace(Set.of(P1), P1, P2);
    stubLockedState(Set.of(P1, P3));

    assertThatThrownBy(() -> replace(Set.of(P1, P2), versionOf(Set.of(P1))))
        .isInstanceOf(PreconditionFailedException.class);
    verifyNoWrite();
    assertThat(replaceCount("precondition_failed", "role_row")).isEqualTo(1.0);
  }

  /**
   * T-T22: a client that offers the version of the current (concurrently written) state, not the
   * snapshot's, is refused. Membership of the current version in what the client sent is never
   * enough; only v1 == v0 under the lock passes.
   */
  @Test
  void should_throw412_when_theClientOffersTheCurrentVersionButNotTheSnapshotVersion() {
    stubReplace(Set.of(P1), P1, P2);

    assertThatThrownBy(() -> replace(Set.of(P1, P2), versionOf(Set.of(P1, P3))))
        .isInstanceOf(PreconditionFailedException.class);
    verifyNoLockTaken();
    verifyNoWrite();
  }

  @Test
  void should_throwRoleNotFound_when_theRoleRowIsGoneAtLockTime() {
    stubReplace(Set.of(P1), P1, P2);
    when(roleManagementPort.lockRoleRow(roleId, tenantId)).thenReturn(false);

    assertThatThrownBy(() -> replace(Set.of(P1, P2), versionOf(Set.of(P1))))
        .isInstanceOf(ResourceNotFoundException.class)
        .hasFieldOrPropertyWithValue("code", "ROLE_NOT_FOUND");
    verify(roleManagementPort, never()).lockPermissionIdsForRole(any());
    verifyNoWrite();
  }

  /** Locks only after authorization, and in RC-46's order: role row, then role_permissions. */
  @Test
  void should_authorizeThenLockRoleRowThenReadCurrentThenDetachThenAttach_when_replacing() {
    stubReplace(Set.of(P1, P2), P1, P2, P3);
    stubLockedState(Set.of(P1, P2));
    when(roleManagementPort.detachPermissions(roleId, Set.of(P2))).thenReturn(1);
    when(roleManagementPort.findPermissionsForRole(roleId))
        .thenReturn(viewsOf(P1, P2), viewsOf(P1, P3));

    replace(Set.of(P1, P3), versionOf(Set.of(P1, P2)));

    InOrder order = inOrder(userRoleAssignmentPort, roleManagementPort, rbacAuditPort);
    order.verify(userRoleAssignmentPort).findHeldRolePermissionIdsForAuthorization(actorId, tenantId);
    order.verify(roleManagementPort).lockRoleRow(roleId, tenantId);
    order.verify(roleManagementPort).lockPermissionIdsForRole(roleId);
    order.verify(roleManagementPort).detachPermissions(roleId, Set.of(P2));
    order.verify(roleManagementPort).attachPermissions(roleId, Set.of(P3));
    order.verify(rbacAuditPort).recordRolePermissionGranted(any());
  }

  @Test
  void should_returnTheNewSetAndItsVersion_when_replacing() {
    stubReplace(Set.of(P1, P2), P1, P2, P3);
    stubLockedState(Set.of(P1, P2));
    when(roleManagementPort.detachPermissions(roleId, Set.of(P2))).thenReturn(1);
    List<PermissionView> after = viewsOf(P1, P3);
    when(roleManagementPort.findPermissionsForRole(roleId)).thenReturn(viewsOf(P1, P2), after);

    RolePermissionSet result = replace(Set.of(P1, P3), versionOf(Set.of(P1, P2)));

    assertThat(result.roleId()).isEqualTo(roleId);
    assertThat(result.permissions()).isEqualTo(after);
    assertThat(result.version()).isEqualTo(versionOf(Set.of(P1, P3)));
    assertThat(replaceCount("replaced", "role_row")).isEqualTo(1.0);
  }

  /** §10.6: one audit row per change, all tagged operation=REPLACE and one server replaceId. */
  @Test
  void should_auditEachChangeWithOperationReplaceAndOneReplaceId_when_replacing() {
    stubReplace(Set.of(P1, P2), P1, P2, P3);
    stubLockedState(Set.of(P1, P2));
    when(roleManagementPort.detachPermissions(roleId, Set.of(P2))).thenReturn(1);
    when(roleManagementPort.findPermissionsForRole(roleId))
        .thenReturn(viewsOf(P1, P2), viewsOf(P1, P3));
    ArgumentCaptor<RoleAuditEvent> granted = ArgumentCaptor.forClass(RoleAuditEvent.class);
    ArgumentCaptor<RoleAuditEvent> revoked = ArgumentCaptor.forClass(RoleAuditEvent.class);

    replace(Set.of(P1, P3), versionOf(Set.of(P1, P2)));

    verify(rbacAuditPort).recordRolePermissionGranted(granted.capture());
    verify(rbacAuditPort).recordRolePermissionRevoked(revoked.capture());
    assertThat(granted.getValue().permissionId()).isEqualTo(P3);
    assertThat(granted.getValue().permissionName()).isEqualTo("perm-" + P3);
    assertThat(revoked.getValue().permissionId()).isEqualTo(P2);
    assertThat(revoked.getValue().permissionName()).isEqualTo("perm-" + P2);
    for (RoleAuditEvent event : List.of(granted.getValue(), revoked.getValue())) {
      assertThat(event.operation()).isEqualTo("REPLACE");
      assertThat(event.replaceId()).isEqualTo(REPLACE_ID);
      assertThat(event.actorUserId()).isEqualTo(actorId);
    }
  }

  /** Step 12: the bulk delete must remove exactly |removes| rows, otherwise nothing is audited. */
  @Test
  void should_throwIllegalStateAndAuditNothing_when_theBulkDetachAffectsFewerRows() {
    stubReplace(Set.of(P1, P2, P3), P1, P2, P3);
    stubLockedState(Set.of(P1, P2, P3));
    when(roleManagementPort.findPermissionsForRole(roleId)).thenReturn(viewsOf(P1, P2, P3));
    when(roleManagementPort.detachPermissions(roleId, Set.of(P2, P3))).thenReturn(1);

    assertThatThrownBy(() -> replace(Set.of(P1), versionOf(Set.of(P1, P2, P3))))
        .isInstanceOf(IllegalStateException.class);
    verify(roleManagementPort, never()).attachPermissions(any(), any());
    verifyNoInteractions(rbacAuditPort);
  }

  @Test
  void should_propagateAndSkipPostCommitWork_when_theAuditWriteFails() {
    stubReplace(Set.of(P1), P1, P2);
    stubLockedState(Set.of(P1));
    when(roleManagementPort.findPermissionsForRole(roleId)).thenReturn(viewsOf(P1, P2));
    doThrow(new IllegalStateException("audit down"))
        .when(rbacAuditPort)
        .recordRolePermissionGranted(any());

    assertThatThrownBy(() -> replace(Set.of(P1, P2), versionOf(Set.of(P1))))
        .isInstanceOf(IllegalStateException.class);
    verifyNoInteractions(permissionFreshness, permissionCachePort);
    assertThat(replaceCount("replaced", "role_row")).isZero();
  }

  /** ADR-0021 D2: an empty set is legal on a custom role and revokes everything it carried. */
  @Test
  void should_detachEverything_when_theTargetIsEmptyOnACustomRole() {
    stubReplace(Set.of(P1, P2), P1, P2);
    stubLockedState(Set.of(P1, P2));
    when(roleManagementPort.findPermissionsForRole(roleId))
        .thenReturn(viewsOf(P1, P2), List.of());
    when(roleManagementPort.detachPermissions(roleId, Set.of(P1, P2))).thenReturn(2);

    RolePermissionSet result = replace(Set.of(), versionOf(Set.of(P1, P2)));

    assertThat(result.permissions()).isEmpty();
    assertThat(result.version()).isEqualTo(versionOf(Set.of()));
    verify(roleManagementPort, never()).attachPermissions(any(), any());
    verify(rbacAuditPort, times(2)).recordRolePermissionRevoked(any());
  }

  /** Step 14: a set that lost permissions bumps every holder's epoch once, after commit. */
  @Test
  void should_bumpHoldersOnceAfterCommit_when_theReplaceRemovesPermissions() {
    stubReplace(Set.of(P1, P2), P1, P2);
    stubLockedState(Set.of(P1, P2));
    when(roleManagementPort.findPermissionsForRole(roleId)).thenReturn(viewsOf(P1, P2), viewsOf(P1));
    when(roleManagementPort.detachPermissions(roleId, Set.of(P2))).thenReturn(1);
    List<UUID> holders = List.of(UUID.randomUUID(), UUID.randomUUID());
    when(userRoleAssignmentPort.findActiveUserIdsForRole(roleId)).thenReturn(holders);

    TransactionSynchronizationManager.initSynchronization();
    try {
      replace(Set.of(P1), versionOf(Set.of(P1, P2)));
      verifyNoInteractions(permissionFreshness);
      fireAfterCommit();
    } finally {
      TransactionSynchronizationManager.clearSynchronization();
    }

    verify(permissionFreshness, times(1)).invalidateHolders(tenantId, holders, "replace");
    verifyNoInteractions(permissionCachePort);
  }

  /** Step 14: a set that only gained permissions evicts the holders' cache, never bumps. */
  @Test
  void should_evictHoldersOnceAndNotBump_when_theReplaceOnlyAddsPermissions() {
    stubReplace(Set.of(P1), P1, P2);
    stubLockedState(Set.of(P1));
    when(roleManagementPort.findPermissionsForRole(roleId)).thenReturn(viewsOf(P1, P2));
    List<HolderProvenance> holders = holdersAssignedBy(UUID.randomUUID(), 2);
    when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId)).thenReturn(holders);

    replace(Set.of(P1, P2), versionOf(Set.of(P1)));

    verify(permissionCachePort, times(1))
        .evict(tenantId, holders.stream().map(HolderProvenance::userId).toList());
    verify(permissionFreshness, never()).invalidateHolders(any(), any(), any());
  }

  @Test
  void should_logPermissionSetReplacedWithCountsAndReplaceId_when_replacing() {
    stubReplace(Set.of(P1, P2), P1, P2, P3);
    stubLockedState(Set.of(P1, P2));
    when(roleManagementPort.detachPermissions(roleId, Set.of(P2))).thenReturn(1);
    when(roleManagementPort.findPermissionsForRole(roleId))
        .thenReturn(viewsOf(P1, P2), viewsOf(P1, P3));
    ListAppender<ILoggingEvent> logs = startLogCapture();
    try {
      replace(Set.of(P1, P3), versionOf(Set.of(P1, P2)));
    } finally {
      stopLogCapture(logs);
    }

    ILoggingEvent replaced =
        logs.list.stream()
            .filter(e -> "RBAC_PERMISSION_SET_REPLACED".equals(keyValueMap(e).get("event")))
            .findFirst()
            .orElseThrow();
    assertThat(replaced.getLevel()).isEqualTo(Level.INFO);
    assertThat(keyValueMap(replaced))
        .containsEntry("roleId", roleId)
        .containsEntry("replaceId", REPLACE_ID)
        .containsEntry("addedCount", 1)
        .containsEntry("removedCount", 1)
        .containsEntry("replacedBy", actorId);
  }

  @Test
  void should_recordTheLockHoldTimerWithOperationReplace_when_replacing() {
    stubReplace(Set.of(P1), P1, P2);
    stubLockedState(Set.of(P1));
    when(roleManagementPort.findPermissionsForRole(roleId)).thenReturn(viewsOf(P1, P2));
    lenient().when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId))
        .thenReturn(List.of());

    replace(Set.of(P1, P2), versionOf(Set.of(P1)));

    assertThat(
            meterRegistry
                .get("nexus.rbac.privileged_revoke_lock_hold")
                .tag("operation", "replace")
                .tag("outcome", "replaced")
                .timer()
                .count())
        .isEqualTo(1L);
  }

  // ---------------------------------------------------------------------------------------
  // replaceRolePermissions() on the set-lock path -- US-019 T-019 (design §10.3 steps 8, 10, 11
  // and 14, §10.4; RC-57.1, RC-56, RC-63(f)). Demotion: set lock, then role row. Promotion: role
  // row, then set lock. Both end with role_permissions FOR SHARE: R's, then the locked roles'.
  // ---------------------------------------------------------------------------------------

  private static final Set<UUID> ONE_SHORT = Set.of(P1, P2, P3, ROLE_READ_ID);

  private static List<RolePermissionRef> refs(UUID role, Set<UUID> permissionIds) {
    return permissionIds.stream().map(id -> new RolePermissionRef(role, id)).toList();
  }

  private static List<RolePermissionRef> concat(
      List<RolePermissionRef> first, List<RolePermissionRef> second) {
    List<RolePermissionRef> all = new ArrayList<>(first);
    all.addAll(second);
    return all;
  }

  private ActiveAssignmentHolder lockedRow(UUID userId, UUID holderRoleId, UUID assignedBy) {
    return new ActiveAssignmentHolder(UUID.randomUUID(), userId, holderRoleId, assignedBy);
  }

  /**
   * R carries {@code rSnapshot}; the snapshot M10' says {@code otherAdminRole} (and R, if it is
   * complete) is admin-defining; the caller holds {@code otherAdminRole} with the whole catalogue
   * (an administrator through another role, M13). Returns the ascending lock set.
   */
  private List<UUID> stubSetLockSnapshot(Set<UUID> rSnapshot, UUID otherAdminRole) {
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(REPLACE_CATALOGUE);
    stubRolePermissions(rSnapshot);
    stubCallerHoldsRefs(
        refs(otherAdminRole, REPLACE_CATALOGUE).toArray(RolePermissionRef[]::new));
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId))
        .thenReturn(concat(refs(otherAdminRole, REPLACE_CATALOGUE), refs(roleId, rSnapshot)));
    return RoleAssignmentService.buildAscendingLockSet(Set.of(otherAdminRole), roleId);
  }

  /** Steps 8 to 10 under the set lock: the locked rows, R's row, and both current reads. */
  private void stubSetLockState(
      List<UUID> lockSet,
      List<ActiveAssignmentHolder> lockedRows,
      Set<UUID> rCurrent,
      UUID otherAdminRole,
      Set<UUID> otherCurrent) {
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(tenantId, lockSet))
        .thenReturn(lockedRows);
    stubLockedState(rCurrent);
    when(userRoleAssignmentPort.lockRolePermissionsForRoles(tenantId, lockSet))
        .thenReturn(concat(refs(roleId, rCurrent), refs(otherAdminRole, otherCurrent)));
  }

  @Test
  void should_takeTheSetLockThenTheRoleRowThenBothCurrentReads_when_demotingAnAdminDefiningRole() {
    UUID other = UUID.randomUUID();
    List<UUID> lockSet = stubSetLockSnapshot(REPLACE_CATALOGUE, other);
    stubSetLockState(
        lockSet, List.of(lockedRow(actorId, other, actorId)), REPLACE_CATALOGUE, other,
        REPLACE_CATALOGUE);
    when(roleManagementPort.detachPermissions(roleId, Set.of(P1))).thenReturn(1);

    RolePermissionSet result = replace(Set.of(P2, P3, ROLE_READ_ID, ROLE_WRITE_ID),
        versionOf(REPLACE_CATALOGUE));

    assertThat(result.version()).isEqualTo(versionOf(Set.of(P2, P3, ROLE_READ_ID, ROLE_WRITE_ID)));
    InOrder order = inOrder(userRoleAssignmentPort, roleManagementPort);
    order.verify(userRoleAssignmentPort).findHeldRolePermissionIdsForAuthorization(actorId, tenantId);
    order.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(tenantId, lockSet);
    order.verify(roleManagementPort).lockRoleRow(roleId, tenantId);
    order.verify(roleManagementPort).lockPermissionIdsForRole(roleId);
    order.verify(userRoleAssignmentPort).lockRolePermissionsForRoles(tenantId, lockSet);
    order.verify(roleManagementPort).detachPermissions(roleId, Set.of(P1));
    assertThat(replaceCount("replaced", "set_lock")).isEqualTo(1.0);
  }

  /**
   * RC-57.1, RES-28: the caller's other role was admin-defining in the snapshot (step 6 passed)
   * but a concurrent demotion committed before the set lock was granted. The current read under
   * the lock decides: the caller is no longer an administrator through another role, so 403.
   */
  @Test
  void should_throw403AndWriteNothing_when_theCallersOtherRoleIsNoLongerAdminDefiningUnderTheLock() {
    UUID other = UUID.randomUUID();
    List<UUID> lockSet = stubSetLockSnapshot(REPLACE_CATALOGUE, other);
    stubSetLockState(
        lockSet, List.of(lockedRow(actorId, other, actorId)), REPLACE_CATALOGUE, other,
        Set.of(P2, P3, ROLE_READ_ID, ROLE_WRITE_ID));

    assertThatThrownBy(
            () -> replace(Set.of(P2, P3, ROLE_READ_ID, ROLE_WRITE_ID), versionOf(REPLACE_CATALOGUE)))
        .isInstanceOf(InsufficientPermissionException.class)
        .extracting(e -> ((InsufficientPermissionException) e).getReason())
        .isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER);
    verifyNoWrite();
    assertThat(replaceCount("denied", "set_lock")).isEqualTo(1.0);
  }

  /** The administrator answer comes from the locked rows: a caller revoked meanwhile is denied. */
  @Test
  void should_throw403_when_theCallerHoldsNoLockedRowOfAnotherAdminDefiningRole() {
    UUID other = UUID.randomUUID();
    List<UUID> lockSet = stubSetLockSnapshot(REPLACE_CATALOGUE, other);
    stubSetLockState(
        lockSet, List.of(lockedRow(actorId, roleId, actorId)), REPLACE_CATALOGUE, other,
        REPLACE_CATALOGUE);

    assertThatThrownBy(
            () -> replace(Set.of(P2, P3, ROLE_READ_ID, ROLE_WRITE_ID), versionOf(REPLACE_CATALOGUE)))
        .isInstanceOf(InsufficientPermissionException.class)
        .extracting(e -> ((InsufficientPermissionException) e).getReason())
        .isEqualTo(DenialReason.GRANT_EXCEEDS_CALLER);
    verifyNoWrite();
  }

  /** A 412 under the set lock still precedes step 10: nothing is classified on a changed set. */
  @Test
  void should_throw412BeforeClassifying_when_theLockedCurrentSetDiffersOnTheSetLockPath() {
    UUID other = UUID.randomUUID();
    List<UUID> lockSet = stubSetLockSnapshot(REPLACE_CATALOGUE, other);
    when(userRoleAssignmentPort.lockActiveAssignmentHolders(tenantId, lockSet))
        .thenReturn(List.of(lockedRow(actorId, other, actorId)));
    stubLockedState(ONE_SHORT);

    assertThatThrownBy(() -> replace(ONE_SHORT, versionOf(REPLACE_CATALOGUE)))
        .isInstanceOf(PreconditionFailedException.class);
    verify(userRoleAssignmentPort, never()).lockRolePermissionsForRoles(any(), any());
    verifyNoWrite();
    assertThat(replaceCount("precondition_failed", "set_lock")).isEqualTo(1.0);
  }

  @Test
  void should_takeTheRoleRowThenTheSetLockThenBothCurrentReads_when_promotingARole() {
    UUID other = UUID.randomUUID();
    List<UUID> lockSet = stubSetLockSnapshot(ONE_SHORT, other);
    stubSetLockState(
        lockSet,
        List.of(lockedRow(actorId, other, actorId), lockedRow(UUID.randomUUID(), roleId, actorId)),
        ONE_SHORT, other, REPLACE_CATALOGUE);

    replace(REPLACE_CATALOGUE, versionOf(ONE_SHORT));

    InOrder order = inOrder(userRoleAssignmentPort, roleManagementPort);
    order.verify(roleManagementPort).lockRoleRow(roleId, tenantId);
    order.verify(userRoleAssignmentPort).lockActiveAssignmentHolders(tenantId, lockSet);
    order.verify(roleManagementPort).lockPermissionIdsForRole(roleId);
    order.verify(userRoleAssignmentPort).lockRolePermissionsForRoles(tenantId, lockSet);
    order.verify(roleManagementPort).attachPermissions(roleId, Set.of(ROLE_WRITE_ID));
    assertThat(replaceCount("replaced", "set_lock")).isEqualTo(1.0);
  }

  /**
   * Step 11 (RES-26): a locked holder of R was assigned by a user who holds no locked row of a
   * currently admin-defining role, so the promotion is 409 RBAC_010 and nothing is written.
   */
  @Test
  void should_throwRbac010AndWriteNothing_when_promotingWithALockedHolderAssignedByANonAdministrator() {
    UUID other = UUID.randomUUID();
    UUID nonAdministrator = UUID.randomUUID();
    List<UUID> lockSet = stubSetLockSnapshot(ONE_SHORT, other);
    stubSetLockState(
        lockSet,
        List.of(
            lockedRow(actorId, other, actorId),
            lockedRow(UUID.randomUUID(), roleId, nonAdministrator)),
        ONE_SHORT, other, REPLACE_CATALOGUE);

    assertThatThrownBy(() -> replace(REPLACE_CATALOGUE, versionOf(ONE_SHORT)))
        .isInstanceOf(AttachProvenanceConflictException.class)
        .hasFieldOrPropertyWithValue("code", "RBAC_010");
    verifyNoWrite();
    assertThat(replaceCount("conflict", "set_lock")).isEqualTo(1.0);
  }

  /**
   * Step 11 judges "is an administrator" against step 10's current set: the assigner holds a
   * locked row of a role that was admin-defining in the snapshot but is not any more, so 409.
   */
  @Test
  void should_throwRbac010_when_theAssignersRoleIsNoLongerAdminDefiningInTheCurrentRead() {
    UUID other = UUID.randomUUID();
    UUID assigner = UUID.randomUUID();
    List<UUID> lockSet = stubSetLockSnapshot(ONE_SHORT, other);
    stubSetLockState(
        lockSet,
        List.of(
            lockedRow(actorId, other, actorId),
            lockedRow(assigner, other, actorId),
            lockedRow(UUID.randomUUID(), roleId, assigner)),
        ONE_SHORT, other, ONE_SHORT);

    assertThatThrownBy(() -> replace(REPLACE_CATALOGUE, versionOf(ONE_SHORT)))
        .isInstanceOf(AttachProvenanceConflictException.class);
    verifyNoWrite();
  }

  /** A break-glass holder (assigned by themself, an administrator) never trips RBAC_010. */
  @Test
  void should_promote_when_everyLockedHolderWasAssignedByACurrentAdministrator() {
    UUID other = UUID.randomUUID();
    UUID breakGlassAdmin = UUID.randomUUID();
    List<UUID> lockSet = stubSetLockSnapshot(ONE_SHORT, other);
    stubSetLockState(
        lockSet,
        List.of(
            lockedRow(actorId, other, actorId),
            lockedRow(breakGlassAdmin, other, breakGlassAdmin),
            lockedRow(UUID.randomUUID(), roleId, breakGlassAdmin),
            lockedRow(UUID.randomUUID(), roleId, actorId)),
        ONE_SHORT, other, REPLACE_CATALOGUE);

    RolePermissionSet result = replace(REPLACE_CATALOGUE, versionOf(ONE_SHORT));

    assertThat(result.version()).isEqualTo(versionOf(REPLACE_CATALOGUE));
    verify(roleManagementPort).attachPermissions(roleId, Set.of(ROLE_WRITE_ID));
  }

  /**
   * RC-56.4 on B8: the promotion passed step 11 from its locked rows, but the after-commit read
   * finds R admin-defining with a holder whose assigner is not an administrator now. The detector
   * pages: WARN (ids and counts) and the untagged counter.
   */
  @Test
  void should_pageTheDetector_when_afterAPromotionCommitsAHolderOfTheRoleWasAssignedByANonAdministrator() {
    UUID other = UUID.randomUUID();
    List<UUID> lockSet = stubSetLockSnapshot(ONE_SHORT, other);
    stubSetLockState(
        lockSet,
        List.of(lockedRow(actorId, other, actorId), lockedRow(UUID.randomUUID(), roleId, actorId)),
        ONE_SHORT, other, REPLACE_CATALOGUE);
    when(userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId))
        .thenReturn(concat(refs(other, REPLACE_CATALOGUE), refs(roleId, ONE_SHORT)))
        .thenReturn(concat(refs(other, REPLACE_CATALOGUE), refs(roleId, REPLACE_CATALOGUE)));
    when(userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId))
        .thenReturn(List.of(new HolderProvenance(UUID.randomUUID(), UUID.randomUUID())));
    when(userRoleAssignmentPort.findActiveHolderUserIdsForRoles(tenantId, Set.of(other, roleId)))
        .thenReturn(Set.of(actorId));

    ListAppender<ILoggingEvent> appender =
        startLogCapture(AdminDefiningRoleProvenanceDetector.class);
    try {
      replace(REPLACE_CATALOGUE, versionOf(ONE_SHORT));

      assertThat(appender.list)
          .singleElement()
          .satisfies(
              warn ->
                  assertThat(keyValueMap(warn))
                      .containsOnly(
                          Map.entry("event", DETECTOR_EVENT),
                          Map.entry("tenantId", tenantId),
                          Map.entry("roleId", roleId),
                          Map.entry("holderCount", 1),
                          Map.entry("nonAdminAssignedCount", 1)));
    } finally {
      stopLogCapture(appender, AdminDefiningRoleProvenanceDetector.class);
    }
    assertThat(meterRegistry.get(DETECTOR_COUNTER).counter().count()).isEqualTo(1.0);
  }

  /** RC-63(f): a committed demotion emits the ceased WARN (ids and a count) and its counter. */
  @Test
  void should_warnAndCountRoleCeasedAdminDefining_when_aDemotionCommits() {
    UUID other = UUID.randomUUID();
    List<UUID> lockSet = stubSetLockSnapshot(REPLACE_CATALOGUE, other);
    stubSetLockState(
        lockSet, List.of(lockedRow(actorId, other, actorId)), REPLACE_CATALOGUE, other,
        REPLACE_CATALOGUE);
    when(roleManagementPort.detachPermissions(roleId, Set.of(P1))).thenReturn(1);
    when(userRoleAssignmentPort.findActiveUserIdsForRole(roleId))
        .thenReturn(List.of(UUID.randomUUID(), UUID.randomUUID()));
    ListAppender<ILoggingEvent> logs = startLogCapture();
    try {
      replace(Set.of(P2, P3, ROLE_READ_ID, ROLE_WRITE_ID), versionOf(REPLACE_CATALOGUE));
    } finally {
      stopLogCapture(logs);
    }

    ILoggingEvent ceased =
        logs.list.stream()
            .filter(e -> "RBAC_ROLE_CEASED_ADMIN_DEFINING".equals(keyValueMap(e).get("event")))
            .findFirst()
            .orElseThrow();
    assertThat(ceased.getLevel()).isEqualTo(Level.WARN);
    assertThat(keyValueMap(ceased))
        .containsEntry("tenantId", tenantId)
        .containsEntry("roleId", roleId)
        .containsEntry("holderCount", 2);
    assertThat(meterRegistry.get("nexus.rbac.role_ceased_admin_defining").counter().count())
        .isEqualTo(1.0);
    assertThat(meterRegistry.get("nexus.rbac.role_ceased_admin_defining").counter().getId()
            .getTags())
        .isEmpty();
  }

  /** The ceased signal still fires when the after-commit holder read fails, without a count. */
  @Test
  void should_stillWarnCeasedWithoutAHolderCount_when_theAfterCommitHolderReadFails() {
    UUID other = UUID.randomUUID();
    List<UUID> lockSet = stubSetLockSnapshot(REPLACE_CATALOGUE, other);
    stubSetLockState(
        lockSet, List.of(lockedRow(actorId, other, actorId)), REPLACE_CATALOGUE, other,
        REPLACE_CATALOGUE);
    when(roleManagementPort.detachPermissions(roleId, Set.of(P1))).thenReturn(1);
    when(userRoleAssignmentPort.findActiveUserIdsForRole(roleId))
        .thenThrow(new IllegalStateException("pool timeout"));
    ListAppender<ILoggingEvent> logs = startLogCapture();
    try {
      replace(Set.of(P2, P3, ROLE_READ_ID, ROLE_WRITE_ID), versionOf(REPLACE_CATALOGUE));
    } finally {
      stopLogCapture(logs);
    }

    ILoggingEvent ceased =
        logs.list.stream()
            .filter(e -> "RBAC_ROLE_CEASED_ADMIN_DEFINING".equals(keyValueMap(e).get("event")))
            .findFirst()
            .orElseThrow();
    assertThat(keyValueMap(ceased)).doesNotContainKey("holderCount");
    assertThat(meterRegistry.get("nexus.rbac.role_ceased_admin_defining").counter().count())
        .isEqualTo(1.0);
  }

  @Test
  void should_notSignalCeasedAdminDefining_when_theReplacedRoleWasNotAdminDefining() {
    stubReplace(Set.of(P1, P2), P1, P2);
    stubLockedState(Set.of(P1, P2));
    when(roleManagementPort.findPermissionsForRole(roleId)).thenReturn(viewsOf(P1, P2), viewsOf(P1));
    when(roleManagementPort.detachPermissions(roleId, Set.of(P2))).thenReturn(1);

    replace(Set.of(P1), versionOf(Set.of(P1, P2)));

    assertThat(meterRegistry.find("nexus.rbac.role_ceased_admin_defining").counter()).isNull();
    verify(userRoleAssignmentPort, never()).lockActiveAssignmentHolders(any(), any());
    verify(userRoleAssignmentPort, never()).lockRolePermissionsForRoles(any(), any());
  }

  /** An authorised no-op on an admin-defining role takes no lock at all. */
  @Test
  void should_returnTheNoOp_when_theRoleIsAdminDefiningAndNothingChanges() {
    UUID otherAdminRole = UUID.randomUUID();
    when(roleManagementPort.findRole(roleId)).thenReturn(Optional.of(customRole(tenantId)));
    when(userRoleAssignmentPort.findCatalogueIds()).thenReturn(REPLACE_CATALOGUE);
    stubRolePermissions(REPLACE_CATALOGUE);
    stubCallerHoldsRefs(
        REPLACE_CATALOGUE.stream()
            .map(id -> new RolePermissionRef(otherAdminRole, id))
            .toArray(RolePermissionRef[]::new));
    when(roleManagementPort.findPermissionsForRole(roleId))
        .thenReturn(viewsOf(P1, P2, P3, ROLE_READ_ID, ROLE_WRITE_ID));

    RolePermissionSet result = replace(REPLACE_CATALOGUE, versionOf(REPLACE_CATALOGUE));

    assertThat(result.version()).isEqualTo(versionOf(REPLACE_CATALOGUE));
    verifyNoLockTaken();
  }

  private ListAppender<ILoggingEvent> startLogCapture() {
    Logger logger = (Logger) LoggerFactory.getLogger(RoleManagementService.class);
    ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);
    return listAppender;
  }

  private void stopLogCapture(ListAppender<ILoggingEvent> listAppender) {
    stopLogCapture(listAppender, RoleManagementService.class);
  }

  private static ListAppender<ILoggingEvent> startLogCapture(Class<?> source) {
    Logger logger = (Logger) LoggerFactory.getLogger(source);
    ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);
    return listAppender;
  }

  private static Map<String, Object> keyValueMap(ILoggingEvent event) {
    Map<String, Object> map = new HashMap<>();
    event.getKeyValuePairs().forEach(kv -> map.put(kv.key, kv.value));
    return map;
  }
}
