package com.example.nexus.rbac.interfaces.rest;

import static com.example.nexus.common.security.Permissions.ROLE_READ;

import com.example.nexus.common.security.Permissions;
import com.example.nexus.common.security.RequiresPermission;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.interfaces.rest.dto.PageLinks;
import com.example.nexus.rbac.interfaces.rest.dto.PageMetadata;
import com.example.nexus.rbac.interfaces.rest.dto.PermissionPageResponse;
import com.example.nexus.rbac.interfaces.rest.dto.PermissionResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
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


  private final RoleManagementService roleManagementService;

  public PermissionController(RoleManagementService roleManagementService) {
    this.roleManagementService = roleManagementService;
  }

  /**
   * Lists one page of the permission catalogue, ordered by name (AC6; paginated by US-018 C2).
   * {@code page} is 0-based (default 0), {@code size} defaults to 20 and is at most 100; an
   * out-of-range value is a 400, never clamped.
   *
   * @return 200 with {@code data}, {@code page} and {@code links}
   */
  @GetMapping
  @RequiresPermission(ROLE_READ)
  @Operation(summary = "List the permission catalogue, one page at a time")
  @ApiResponse(responseCode = "200", description = "A page of the permission catalogue")
  @ApiResponse(responseCode = "400", description = "page or size out of range, or not an integer")
  @ApiResponse(responseCode = "403", description = "Missing role:read")
  public PermissionPageResponse listPermissions(
      @RequestParam(name = "page", required = false) String page,
      @RequestParam(name = "size", required = false) String size) {
    PageParams params = PageParams.parse(page, size);

    PageResult<PermissionView> result =
        roleManagementService.listAllPermissions(params.page(), params.size());
    return new PermissionPageResponse(
        result.items().stream().map(PermissionController::toResponse).toList(),
        PageMetadata.of(result),
        PageLinks.of("/api/v1/permissions", result));
  }

  static PermissionResponse toResponse(PermissionView view) {
    return new PermissionResponse(
        view.id().toString(),
        view.name(),
        view.description(),
        Permissions.SENSITIVE.contains(view.name()));
  }
}
