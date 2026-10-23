package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.rbac.application.PermissionFreshnessService;
import com.example.nexus.rbac.application.PiiPermissionGrantRule;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.RoleChangeThrottlePort;
import com.example.nexus.rbac.application.port.out.RoleManagementPort;
import com.example.nexus.rbac.application.port.out.ThrottleStatus;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleChangeThrottledException;
import com.example.nexus.rbac.domain.RolePermissionRef;
import com.example.nexus.rbac.domain.RoleView;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * MC-8 (US-018 B3, FR-B3.a): after both services' success, denial and cross-tenant paths have run,
 * no meter in the registry carries a tenant tag key. Attribution stays in WARN fields: a
 * per-tenant series is unbounded cardinality (03b-threat-model.md T-D17).
 */
@Tag("UnitTest")
class RbacMetricCardinalityTest {

  private static final Set<String> FORBIDDEN_TAG_KEYS =
      Set.of("tenantId", "tenant_id", "tenant", "actorUserId", "userId");
  private static final UUID P1 = UUID.fromString("00000000-0000-7000-8000-000000000001");

  @Test
  void should_haveNoTenantTagOnAnyMeter_when_bothServicesRunSuccessDenialAndCrossTenantPaths() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    UUID tenantId = UUID.randomUUID();
    UUID otherTenantId = UUID.randomUUID();
    UUID actorId = UUID.randomUUID();
    UUID targetId = UUID.randomUUID();
    UUID roleId = UUID.randomUUID();
    RoleChangeActor actor = new RoleChangeActor(actorId, tenantId);

    UserRoleAssignmentPort assignmentPort = mock(UserRoleAssignmentPort.class);
    UserDirectoryPort directoryPort = mock(UserDirectoryPort.class);
    RoleChangeThrottlePort throttlePort = mock(RoleChangeThrottlePort.class);
    RoleManagementPort managementPort = mock(RoleManagementPort.class);
    RoleAssignmentService assignmentService =
        new RoleAssignmentService(
            assignmentPort, directoryPort, mock(RbacAuditPort.class),
            mock(PermissionCachePort.class), mock(PermissionFreshnessService.class),
            mock(PlatformTransactionManager.class), registry, throttlePort,
            new PiiPermissionGrantRule(true, registry), 5, 60);
    RoleManagementService managementService =
        new RoleManagementService(
            managementPort, assignmentPort, mock(RbacAuditPort.class),
            mock(PermissionFreshnessService.class), mock(PermissionCachePort.class),
            mock(PlatformTransactionManager.class), registry,
            new PiiPermissionGrantRule(true, registry), UUID::randomUUID, 500L);

    Role role = new Role(roleId, tenantId, "MEMBER", "desc", false);
    when(directoryPort.findTenantId(targetId)).thenReturn(Optional.of(tenantId));
    when(directoryPort.findTenantId(actorId)).thenReturn(Optional.of(tenantId));
    when(assignmentPort.findRole(roleId)).thenReturn(Optional.of(role));
    when(assignmentPort.findCatalogueIds()).thenReturn(Set.of(P1));
    when(assignmentPort.findPermissionIdsForRole(any(), any())).thenReturn(Optional.of(Set.of()));
    when(assignmentPort.findHeldRolePermissionIdsForAuthorization(actorId, tenantId))
        .thenReturn(List.of(new RolePermissionRef(UUID.randomUUID(), RbacSeededPermissionIds.USER_ROLE_ASSIGN)));
    when(assignmentPort.assign(targetId, roleId, tenantId, actorId)).thenReturn(UUID.randomUUID());
    when(assignmentPort.findActiveAssignmentView(targetId, roleId, tenantId))
        .thenReturn(
            Optional.of(new ActiveRoleAssignment(targetId, roleId, "MEMBER", Instant.now(), actorId)));

    // Success path.
    assignmentService.assign(actor, targetId, roleId, RequestContext.UNKNOWN);
    // Denial path (self-assignment by a non-administrator).
    assertThatThrownBy(() -> assignmentService.assign(actor, actorId, roleId, RequestContext.UNKNOWN))
        .isInstanceOf(InsufficientPermissionException.class);
    // Cross-tenant paths on both services.
    UUID foreignUser = UUID.randomUUID();
    when(directoryPort.findTenantId(foreignUser)).thenReturn(Optional.of(otherTenantId));
    assertThatThrownBy(() -> assignmentService.listActive(actor, foreignUser, 0, 20))
        .isInstanceOf(ResourceNotFoundException.class);
    UUID foreignRoleId = UUID.randomUUID();
    when(managementPort.findRole(foreignRoleId))
        .thenReturn(
            Optional.of(new RoleView(foreignRoleId, otherTenantId, "X", "d", false, Instant.now())));
    assertThatThrownBy(() -> managementService.listRolePermissions(actor, foreignRoleId))
        .isInstanceOf(ResourceNotFoundException.class);
    // Throttled path (a throttled actor is blocked on a self-target).
    when(throttlePort.throttleStatus(tenantId, actorId)).thenReturn(new ThrottleStatus(true, 30));
    assertThatThrownBy(() -> assignmentService.assign(actor, actorId, roleId, RequestContext.UNKNOWN))
        .isInstanceOf(RoleChangeThrottledException.class);

    assertThat(registry.getMeters()).as("the paths above must have emitted meters").isNotEmpty();
    for (Meter meter : registry.getMeters()) {
      assertThat(meter.getId().getTags())
          .as("meter %s must carry no tenant-identifying tag", meter.getId().getName())
          .noneMatch(tag -> FORBIDDEN_TAG_KEYS.contains(tag.getKey()));
    }
  }
}
