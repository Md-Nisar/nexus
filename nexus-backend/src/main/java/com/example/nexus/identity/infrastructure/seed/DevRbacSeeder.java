package com.example.nexus.identity.infrastructure.seed;

import com.example.nexus.rbac.application.port.out.RoleManagementPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionView;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Creates the dev persona roles and role assignments (US-019 C1). Dev only: it writes through the
 * ports and so skips the grant-subset and A6 audit checks a real assignment goes through, exactly
 * as the original single-user seed did.
 *
 * <p>Idempotent: roles are found by name, permissions are attached only when missing, and an
 * assignment is made only when the user does not already hold the role.
 */
@Component
@Profile("dev & !break-glass & !prod")
public class DevRbacSeeder {

  private static final Logger log = LoggerFactory.getLogger(DevRbacSeeder.class);
  private static final int CATALOGUE_PAGE_SIZE = 100;

  private final RoleManagementPort roleManagementPort;
  private final UserRoleAssignmentPort userRoleAssignmentPort;

  public DevRbacSeeder(
      RoleManagementPort roleManagementPort, UserRoleAssignmentPort userRoleAssignmentPort) {
    this.roleManagementPort = roleManagementPort;
    this.userRoleAssignmentPort = userRoleAssignmentPort;
  }

  /** Ensures a custom role holding exactly the named permissions; returns the role name. */
  String ensureRole(
      UUID tenantId,
      String roleName,
      String description,
      Set<String> permissionNames,
      SeedReport report) {
    List<PermissionView> catalogue = loadCatalogue();
    List<PermissionView> wanted =
        catalogue.stream().filter(p -> permissionNames.contains(p.name())).toList();
    if (wanted.size() != permissionNames.size()) {
      throw new IllegalStateException("Dev seed role " + roleName + " names an unknown permission");
    }
    ensureRoleWith(tenantId, roleName, description, wanted, report);
    return roleName;
  }

  /** Ensures a custom role holding every catalogue row, enumerated now; returns the role name. */
  String ensureRoleWithEveryPermission(
      UUID tenantId, String roleName, String description, SeedReport report) {
    ensureRoleWith(tenantId, roleName, description, loadCatalogue(), report);
    return roleName;
  }

  /** Assigns the named role to the user unless already held; {@code assignedBy} is explicit. */
  void ensureAssignment(
      UUID tenantId, UUID userId, String roleName, UUID assignedBy, SeedReport report) {
    Optional<UUID> roleId = userRoleAssignmentPort.findRoleIdByName(tenantId, roleName);
    if (roleId.isEmpty()) {
      log.warn("dev seed role not found role={} tenantId={}", roleName, tenantId);
      report.skipped();
      return;
    }
    if (userRoleAssignmentPort.hasActiveAssignment(userId, roleId.get())) {
      report.skipped();
      return;
    }
    userRoleAssignmentPort.assign(userId, roleId.get(), tenantId, assignedBy);
    report.created();
  }

  private void ensureRoleWith(
      UUID tenantId,
      String roleName,
      String description,
      List<PermissionView> permissions,
      SeedReport report) {
    Optional<UUID> existing = userRoleAssignmentPort.findRoleIdByName(tenantId, roleName);
    UUID roleId;
    if (existing.isPresent()) {
      roleId = existing.get();
      report.skipped();
    } else {
      roleId = roleManagementPort.createRole(tenantId, roleName, description);
      report.created();
    }
    for (PermissionView permission : permissions) {
      if (!roleManagementPort.hasPermission(roleId, permission.id())) {
        roleManagementPort.attachPermission(roleId, permission.id());
      }
    }
  }

  private List<PermissionView> loadCatalogue() {
    List<PermissionView> all = new ArrayList<>();
    int page = 0;
    PageResult<PermissionView> result;
    do {
      result = roleManagementPort.findAllPermissions(page++, CATALOGUE_PAGE_SIZE);
      all.addAll(result.items());
    } while (all.size() < result.totalElements() && !result.items().isEmpty());
    return all;
  }
}
