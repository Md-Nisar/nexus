package com.example.nexus.rbac.interfaces.rest;

import com.example.nexus.common.security.RequiresPermission;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.interfaces.rest.dto.PermissionListResponse;
import com.example.nexus.rbac.interfaces.rest.dto.PermissionResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The global permission catalogue (AC6, 03-design.md §4.1/§8.4). {@code permissions} has no
 * {@code tenant_id} column, so {@link #listPermissions()} deliberately takes no {@code
 * Authentication} parameter — adding an unused actor would imply a tenant scoping that does not
 * exist.
 *
 * <p>Every handler is {@code public} and non-{@code final}, and this class is non-{@code final}
 * (T-E11/D8) — {@code RequiresPermission}'s own Javadoc warns that Spring AOP may silently never
 * enforce the annotation otherwise.
 */
@RestController
@RequestMapping("/api/v1/permissions")
@ConditionalOnProperty(
    name = "feature.nexus-us015-rbac-role-management.enabled",
    havingValue = "true")
@Tag(name = "Role Management", description = "Tenant-scoped role and role-permission management")
public class PermissionController {

  private static final String ROLE_READ = "role:read";

  private final RoleManagementService roleManagementService;

  public PermissionController(RoleManagementService roleManagementService) {
    this.roleManagementService = roleManagementService;
  }

  /**
   * Lists the full permission catalogue, ordered by name (AC6).
   *
   * @return 200 with a {@code data} envelope (03-design.md §8.4/D5)
   */
  @GetMapping
  @RequiresPermission(ROLE_READ)
  @Operation(summary = "List the full permission catalogue")
  @ApiResponse(responseCode = "200", description = "Permission catalogue")
  @ApiResponse(responseCode = "403", description = "Missing role:read")
  public PermissionListResponse listPermissions() {
    var data =
        roleManagementService.listAllPermissions().stream()
            .map(PermissionController::toResponse)
            .toList();
    return new PermissionListResponse(data);
  }

  static PermissionResponse toResponse(PermissionView view) {
    return new PermissionResponse(view.id().toString(), view.name(), view.description());
  }
}
