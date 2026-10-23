package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.application.port.out.UserRoleQueryPort;
import com.example.nexus.rbac.domain.PermissionViaRole;
import com.example.nexus.rbac.domain.RoleRef;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;

@Component
public class JpaUserRoleQueryAdapter implements UserRoleQueryPort {

  private final JpaUserRoleRepository userRoleRepository;

  public JpaUserRoleQueryAdapter(JpaUserRoleRepository userRoleRepository) {
    this.userRoleRepository = userRoleRepository;
  }

  @Override
  public List<String> findActiveRoleNames(UUID userId, UUID tenantId) {
    return userRoleRepository.findActiveRoleNames(userId, tenantId);
  }

  @Override
  public List<RoleRef> findActiveRoles(UUID userId, UUID tenantId) {
    return userRoleRepository.findActiveRoles(userId, tenantId);
  }

  @Override
  public List<String> findActivePermissionNames(UUID userId, UUID tenantId) {
    return userRoleRepository.findActivePermissionNames(userId, tenantId);
  }

  @Override
  public List<PermissionViaRole> findActivePermissionsViaRoles(UUID userId, UUID tenantId) {
    return userRoleRepository.findActivePermissionsViaRoles(userId, tenantId);
  }
}
