package com.example.nexus.rbac.interfaces.rest;

import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.security.RequiresPermission;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleView;
import com.example.nexus.rbac.interfaces.rest.dto.AttachPermissionRequest;
import com.example.nexus.rbac.interfaces.rest.dto.CreateRoleRequest;
import com.example.nexus.rbac.interfaces.rest.dto.PermissionListResponse;
import com.example.nexus.rbac.interfaces.rest.dto.PermissionResponse;
import com.example.nexus.rbac.interfaces.rest.dto.RoleListResponse;
import com.example.nexus.rbac.interfaces.rest.dto.RoleResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Tenant-scoped role and role-permission management (US-015, 03-design.md §4.1/§8).
 *
 * <p><b>The only place in this request path that touches {@link Authentication} (T-E10),
 * alongside {@link PermissionController} and {@code UserRoleController}.</b> Every handler
 * unwraps it into a plain {@link RoleChangeActor} via {@link RbacControllerSupport#resolveActor}
 * and passes only that plus plain {@link UUID}s and a {@link RequestContext} into {@link
 * RoleManagementService} — never {@code Authentication}, never {@code java.security.Principal}.
 *
 * <p><b>Every handler is {@code public} and non-{@code final}, and this class is non-{@code
 * final} (D8).</b>
 *
 * <p><b>Path variables and the request body's {@code permissionId} are {@code String}, validated
 * as canonical-UUID-shaped, and parsed to {@link UUID} only after validation passes (D15).</b> A
 * {@code UUID}-typed {@code @PathVariable} or body field would let a malformed value raise an
 * exception {@code GlobalExceptionHandler} does not catch, producing a 500 instead of a 400.
 */
@RestController
@RequestMapping("/api/v1/roles")
@ConditionalOnProperty(
    name = "feature.nexus-us015-rbac-role-management.enabled",
    havingValue = "true")
@Tag(name = "Role Management", description = "Tenant-scoped role and role-permission management")
public class RoleController {

  private static final String ROLE_WRITE = "role:write";
  private static final String ROLE_READ = "role:read";
  private static final String PATH_PARAM_ROLE_ID = "roleId";
  private static final String PATH_PARAM_PERMISSION_ID = "permissionId";

  private final RoleManagementService roleManagementService;

  public RoleController(RoleManagementService roleManagementService) {
    this.roleManagementService = roleManagementService;
  }

  /**
   * Creates a custom role in the caller's own tenant (AC1, AC9, AC12).
   *
   * @return 201 with a {@code Location} header addressing the new role and its body
   */
  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  @RequiresPermission(ROLE_WRITE)
  @Operation(summary = "Create a custom role in the caller's tenant")
  @ApiResponse(responseCode = "201", description = "Role created")
  @ApiResponse(responseCode = "400", description = "Validation failed")
  @ApiResponse(responseCode = "403", description = "Missing role:write")
  @ApiResponse(responseCode = "409", description = "Duplicate or reserved role name, or role limit reached")
  public ResponseEntity<RoleResponse> createRole(
      @Valid @RequestBody CreateRoleRequest request,
      Authentication authentication,
      HttpServletRequest httpRequest) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, ROLE_WRITE);

    RoleView role =
        roleManagementService.createRole(
            actor, request.name(), request.description(), RbacControllerSupport.requestContext(httpRequest));

    return ResponseEntity.created(URI.create("/api/v1/roles/" + role.id())).body(toResponse(role));
  }

  /**
   * Lists all roles in the caller's own tenant, ordered by name (AC2, AC8, D11).
   *
   * @return 200 with a {@code data} envelope
   */
  @GetMapping
  @RequiresPermission(ROLE_READ)
  @Operation(summary = "List all roles in the caller's tenant")
  @ApiResponse(responseCode = "200", description = "Roles in the caller's tenant")
  @ApiResponse(responseCode = "403", description = "Missing role:read")
  public RoleListResponse listRoles(Authentication authentication) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, ROLE_READ);

    var data = roleManagementService.listRoles(actor).stream().map(RoleController::toResponse).toList();
    return new RoleListResponse(data);
  }

  /**
   * Lists the permissions attached to a role in the caller's own tenant (AC3, AC8). Reads against
   * a system role are allowed — AC7's guard is scoped to writes.
   *
   * @return 200 with a {@code data} envelope; empty list is a valid 200
   */
  @GetMapping("/{roleId}/permissions")
  @RequiresPermission(ROLE_READ)
  @Operation(summary = "List the permissions attached to a role in the caller's tenant")
  @ApiResponse(responseCode = "200", description = "Permissions attached to the role")
  @ApiResponse(responseCode = "403", description = "Missing role:read or cross-tenant role")
  @ApiResponse(responseCode = "404", description = "Role not found")
  public PermissionListResponse listRolePermissions(
      @PathVariable String roleId, Authentication authentication) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, ROLE_READ);
    UUID parsedRoleId = RbacControllerSupport.parsePathUuid(roleId, PATH_PARAM_ROLE_ID);

    var data =
        roleManagementService.listRolePermissions(actor, parsedRoleId).stream()
            .map(PermissionController::toResponse)
            .toList();
    return new PermissionListResponse(data);
  }

  /**
   * Attaches a permission to a role in the caller's own tenant (AC4, AC7, AC8, AC11, AC12) — the
   * story's security-critical path.
   *
   * @return 201 with a {@code Location} header addressing the pairing and the attached permission
   */
  @PostMapping("/{roleId}/permissions")
  @ResponseStatus(HttpStatus.CREATED)
  @RequiresPermission(ROLE_WRITE)
  @Operation(summary = "Attach a permission to a role in the caller's tenant")
  @ApiResponse(responseCode = "201", description = "Permission attached")
  @ApiResponse(responseCode = "400", description = "Malformed path or body UUID")
  @ApiResponse(
      responseCode = "403",
      description = "Missing role:write, cross-tenant role, or AC11 non-admin")
  @ApiResponse(responseCode = "404", description = "Role or permission not found")
  @ApiResponse(responseCode = "409", description = "System role, or already attached")
  public ResponseEntity<PermissionResponse> attachPermission(
      @PathVariable String roleId,
      @Valid @RequestBody AttachPermissionRequest request,
      Authentication authentication,
      HttpServletRequest httpRequest) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, ROLE_WRITE);
    UUID parsedRoleId = RbacControllerSupport.parsePathUuid(roleId, PATH_PARAM_ROLE_ID);
    UUID permissionId =
        RbacControllerSupport.parsePathUuid(request.permissionId(), PATH_PARAM_PERMISSION_ID);

    PermissionView permission =
        roleManagementService.attachPermission(
            actor, parsedRoleId, permissionId, RbacControllerSupport.requestContext(httpRequest));

    return ResponseEntity.created(
            URI.create("/api/v1/roles/" + roleId + "/permissions/" + permission.id()))
        .body(PermissionController.toResponse(permission));
  }

  /**
   * Detaches a permission from a role in the caller's own tenant (AC5, AC7, AC8, AC12). No AC11
   * gate — detaching reduces privilege.
   */
  @DeleteMapping("/{roleId}/permissions/{permissionId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @RequiresPermission(ROLE_WRITE)
  @Operation(summary = "Detach a permission from a role in the caller's tenant")
  @ApiResponse(responseCode = "204", description = "Permission detached")
  @ApiResponse(responseCode = "400", description = "Malformed path UUID")
  @ApiResponse(responseCode = "403", description = "Missing role:write or cross-tenant role")
  @ApiResponse(responseCode = "404", description = "Role, permission, or pairing not found")
  @ApiResponse(responseCode = "409", description = "System role")
  public void detachPermission(
      @PathVariable String roleId,
      @PathVariable String permissionId,
      Authentication authentication,
      HttpServletRequest httpRequest) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, ROLE_WRITE);
    UUID parsedRoleId = RbacControllerSupport.parsePathUuid(roleId, PATH_PARAM_ROLE_ID);
    UUID parsedPermissionId =
        RbacControllerSupport.parsePathUuid(permissionId, PATH_PARAM_PERMISSION_ID);

    roleManagementService.detachPermission(
        actor, parsedRoleId, parsedPermissionId, RbacControllerSupport.requestContext(httpRequest));
  }

  private static RoleResponse toResponse(RoleView view) {
    return new RoleResponse(
        view.id().toString(), view.name(), view.description(), view.systemRole(), view.createdAt());
  }
}
