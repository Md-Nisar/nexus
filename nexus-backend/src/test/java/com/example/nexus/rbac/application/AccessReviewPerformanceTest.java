package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.application.port.out.UserRoleQueryPort;
import com.example.nexus.rbac.domain.EffectivePermission;
import com.example.nexus.rbac.domain.PermissionViaRole;
import com.example.nexus.rbac.domain.RoleChangeActor;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Performance unit test asserting that {@link AccessReviewService#getEffectivePermissions}
 * bounds response collection size and heap usage under large permission catalogues.
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class AccessReviewPerformanceTest {

  @Mock private UserRoleAssignmentPort assignmentPort;
  @Mock private UserRoleQueryPort queryPort;
  @Mock private UserDirectoryPort directoryPort;

  private AccessReviewService service;
  private RoleChangeActor actor;
  private UUID tenantId;
  private UUID userId;

  @BeforeEach
  void setUp() {
    service =
        new AccessReviewService(
            assignmentPort, queryPort, directoryPort, new SimpleMeterRegistry());
    tenantId = UUID.randomUUID();
    userId = UUID.randomUUID();
    actor = new RoleChangeActor(UUID.randomUUID(), tenantId);
  }

  @Test
  void should_bound_effective_permissions_heap_usage() {
    when(directoryPort.findTenantId(userId)).thenReturn(Optional.of(tenantId));

    List<PermissionViaRole> largePermissionList = new ArrayList<>(2000);
    UUID roleId = UUID.randomUUID();
    for (int i = 0; i < 2000; i++) {
      largePermissionList.add(new PermissionViaRole("perm:" + i, roleId));
    }
    when(queryPort.findActivePermissionsViaRoles(userId, tenantId)).thenReturn(largePermissionList);

    List<EffectivePermission> result = service.getEffectivePermissions(actor, userId);

    assertThat(result)
        .as("Effective permissions must be strictly bounded to prevent heap exhaustion")
        .hasSizeLessThanOrEqualTo(AccessReviewService.MAX_EFFECTIVE_PERMISSIONS);
  }
}
