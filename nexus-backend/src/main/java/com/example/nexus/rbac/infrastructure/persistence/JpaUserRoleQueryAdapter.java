package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.application.port.out.UserRoleQueryPort;
import com.example.nexus.rbac.domain.PermissionViaRole;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import com.example.nexus.rbac.domain.RoleRef;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
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

  @Override
  public ResolvedPermissions findActiveRoleAndPermissionNames(UUID userId, UUID tenantId) {
    List<Object[]> rows =
        userRoleRepository.findActiveRoleAndPermissionNamesComposite(userId, tenantId);
    Set<String> roles = new LinkedHashSet<>();
    Set<String> permissions = new LinkedHashSet<>();
    for (Object[] row : rows) {
      if (row[0] != null) {
        roles.add((String) row[0]);
      }
      if (row[1] != null) {
        permissions.add((String) row[1]);
      }
    }
    return new ResolvedPermissions(new ArrayList<>(roles), new ArrayList<>(permissions));
  }
}
