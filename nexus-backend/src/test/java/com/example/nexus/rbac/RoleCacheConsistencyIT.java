package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.RolePermissionSetVersion;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

/**
 * [OR-07] Non-Atomic Role Cache Invalidation Order: Verifies that replacing role permissions
 * invalidates holder permission caches and bumps epochs to eliminate windows of stale permission serving.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class RoleCacheConsistencyIT {

  @Autowired private RoleManagementService roleManagementService;
  @Autowired private PermissionCachePort permissionCachePort;
  @Autowired private PermissionEpochPort permissionEpochPort;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private UuidGenerator uuidGenerator;

  private static final UUID ROLE_READ = RbacSeededPermissionIds.ROLE_READ;
  private static final UUID ROLE_WRITE = RbacSeededPermissionIds.ROLE_WRITE;
  private static final UUID USER_READ = RbacSeededPermissionIds.USER_READ;
  private static final UUID USER_WRITE = RbacSeededPermissionIds.USER_WRITE;
  private static final UUID AUDIT_READ = RbacSeededPermissionIds.AUDIT_READ;

  @Test
  void should_not_serve_stale_cache_during_permission_replacement() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor adminActor =
        seedEditor(tenantId, ROLE_READ, ROLE_WRITE, USER_READ, USER_WRITE, AUDIT_READ);

    User user = seedUser(tenantId);
    Role role = seedRole(tenantId, USER_READ, USER_WRITE);
    seedAssignment(tenantId, role.getId(), user.getId(), adminActor.userId());

    long initialEpoch = permissionEpochPort.current(tenantId, user.getId()).orElse(1L);

    // Populate user cache with initial permissions under current epoch
    permissionCachePort.put(
        tenantId,
        user.getId(),
        initialEpoch,
        new ResolvedPermissions(List.of(role.getName()), List.of("user:read", "user:write")));

    ResolvedPermissions cached =
        permissionCachePort.get(tenantId, user.getId(), initialEpoch).orElse(null);
    assertThat(cached).isNotNull();
    assertThat(cached.permissions()).containsExactlyInAnyOrder("user:read", "user:write");

    // Replace permissions on role to only contain USER_READ (removing USER_WRITE)
    String ifMatch = RolePermissionSetVersion.of(role.getId(), List.of(USER_READ, USER_WRITE));
    roleManagementService.replaceRolePermissions(
        adminActor,
        role.getId(),
        Set.of(USER_READ),
        ifMatch,
        RequestContext.UNKNOWN);

    // After replacement, initial epoch cache must either be evicted or epoch bumped
    long newEpoch = permissionEpochPort.current(tenantId, user.getId()).orElse(initialEpoch);
    assertThat(newEpoch).isGreaterThan(initialEpoch);

    // Reading under new epoch is a cache miss, ensuring old cached permission set is never served
    ResolvedPermissions underNewEpoch =
        permissionCachePort.get(tenantId, user.getId(), newEpoch).orElse(null);
    assertThat(underNewEpoch).isNull();
  }

  private RoleChangeActor seedEditor(UUID tenantId, UUID... permissionIds) {
    User editor = seedUser(tenantId);
    Role editorRole = seedRole(tenantId, permissionIds);
    userRoleRepository.save(
        new UserRole(
            uuidGenerator.newId(), editor.getId(), editorRole.getId(), tenantId, editor.getId()));
    return new RoleChangeActor(editor.getId(), tenantId);
  }

  private User seedUser(UUID tenantId) {
    String email = "rcc-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRepository.save(
        new User(
            uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  private Role seedRole(UUID tenantId, UUID... permissionIds) {
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, "RCC-" + UUID.randomUUID(), null, false));
    for (UUID permissionId : permissionIds) {
      rolePermissionRepository.save(new RolePermission(role.getId(), permissionId));
    }
    return role;
  }

  private void seedAssignment(UUID tenantId, UUID roleId, UUID userId, UUID assignedBy) {
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), userId, roleId, tenantId, assignedBy));
  }
}
