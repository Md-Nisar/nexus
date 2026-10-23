package com.example.nexus.rbac.interfaces.rest;

import static com.example.nexus.common.security.Permissions.AUDIT_READ;

import com.example.nexus.common.security.RequiresPermission;
import com.example.nexus.common.web.ProblemResponse;
import com.example.nexus.rbac.application.AccessReviewService;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionHolder;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleHolder;
import com.example.nexus.rbac.interfaces.rest.dto.EffectivePermissionsResponse;
import com.example.nexus.rbac.interfaces.rest.dto.EffectivePermissionsResponse.EffectivePermissionEntry;
import com.example.nexus.rbac.interfaces.rest.dto.PageLinks;
import com.example.nexus.rbac.interfaces.rest.dto.PageMetadata;
import com.example.nexus.rbac.interfaces.rest.dto.PermissionHolderListResponse;
import com.example.nexus.rbac.interfaces.rest.dto.PermissionHolderResponse;
import com.example.nexus.rbac.interfaces.rest.dto.RoleHolderListResponse;
import com.example.nexus.rbac.interfaces.rest.dto.RoleHolderResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Access review for tenant auditors (US-018 C3, 03-design.md 11.3): who holds a role or a
 * permission, and what a user effectively holds. Every handler needs {@code audit:read}, the first
 * live use of that permission, and reads only the caller's own tenant (taken from the JWT, never
 * from the request). Responses carry ids only.
 *
 * <p><b>The administrator roster is disclosed to every {@code audit:read} holder (RES-37, Low,
 * accepted).</b> Only {@code assignedBy} of a role holder is redacted for a non-administrator; see
 * {@code AccessReviewService}.
 *
 * <p>Rides the {@code feature.nexus-us015-rbac-role-management} flag. Every handler is {@code
 * public} and non-{@code final}, and this class is non-{@code final} ({@code @RequiresPermission}'s
 * Spring AOP requirement, as {@link RoleController}). Path variables are validated as canonical
 * UUIDs before parsing (D15). {@code Authentication} is touched only here, via {@link
 * RbacControllerSupport#resolveActor}.
 */
@RestController
@RequestMapping("/api/v1")
@ConditionalOnProperty(
    name = "feature.nexus-us015-rbac-role-management.enabled",
    havingValue = "true")
@Tag(name = "Access Review", description = "Tenant-scoped access review reads (ids only)")
public class AccessReviewController {

  private final AccessReviewService accessReviewService;

  public AccessReviewController(AccessReviewService accessReviewService) {
    this.accessReviewService = accessReviewService;
  }

  /**
   * One page of the active holders of a role. {@code assignedBy} is omitted unless the caller is an
   * administrator.
   */
  @GetMapping("/roles/{roleId}/holders")
  @RequiresPermission(AUDIT_READ)
  @Operation(summary = "List the active holders of a role in the caller's tenant (ids only)")
  @ApiResponse(responseCode = "200", description = "A page of holders")
  @ProblemResponse(
      status = 400,
      codes = {"VALIDATION_FAILED"},
      description =
          "Malformed path UUID, or page or size out of range or not an integer")
  @ProblemResponse(
      status = 403,
      codes = {"RBAC_001"},
      description =
          "Missing audit:read")
  @ProblemResponse(
      status = 404,
      codes = {"ROLE_NOT_FOUND"},
      description =
          "Role not found, deleted, or in another tenant (indistinguishable)")
  public RoleHolderListResponse listRoleHolders(
      @PathVariable String roleId,
      @RequestParam(name = "page", required = false) String page,
      @RequestParam(name = "size", required = false) String size,
      Authentication authentication) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, AUDIT_READ);
    UUID parsedRoleId = RbacControllerSupport.parsePathUuid(roleId, "roleId");
    PageParams params = PageParams.parse(page, size);

    PageResult<RoleHolder> result =
        accessReviewService.listRoleHolders(actor, parsedRoleId, params.page(), params.size());
    return new RoleHolderListResponse(
        result.items().stream()
            .map(
                h ->
                    new RoleHolderResponse(
                        h.userId().toString(),
                        h.assignmentId().toString(),
                        h.assignedAt(),
                        h.assignedBy() == null ? null : h.assignedBy().toString()))
            .toList(),
        PageMetadata.of(result),
        PageLinks.of("/api/v1/roles/" + parsedRoleId + "/holders", result));
  }

  /** One page of the distinct users of the caller's tenant who hold a permission. */
  @GetMapping("/permissions/{permissionId}/holders")
  @RequiresPermission(AUDIT_READ)
  @Operation(summary = "List the users holding a permission in the caller's tenant (ids only)")
  @ApiResponse(responseCode = "200", description = "A page of holders, each with the granting roles")
  @ProblemResponse(
      status = 400,
      codes = {"VALIDATION_FAILED"},
      description =
          "Malformed path UUID, or page or size out of range or not an integer")
  @ProblemResponse(
      status = 403,
      codes = {"RBAC_001"},
      description =
          "Missing audit:read")
  @ProblemResponse(
      status = 404,
      codes = {"PERMISSION_NOT_FOUND"},
      description =
          "No such permission")
  public PermissionHolderListResponse listPermissionHolders(
      @PathVariable String permissionId,
      @RequestParam(name = "page", required = false) String page,
      @RequestParam(name = "size", required = false) String size,
      Authentication authentication) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, AUDIT_READ);
    UUID parsedPermissionId = RbacControllerSupport.parsePathUuid(permissionId, "permissionId");
    PageParams params = PageParams.parse(page, size);

    PageResult<PermissionHolder> result =
        accessReviewService.listPermissionHolders(
            actor, parsedPermissionId, params.page(), params.size());
    return new PermissionHolderListResponse(
        result.items().stream()
            .map(
                h ->
                    new PermissionHolderResponse(
                        h.userId().toString(), h.viaRoleIds().stream().map(UUID::toString).toList()))
            .toList(),
        PageMetadata.of(result),
        PageLinks.of("/api/v1/permissions/" + parsedPermissionId + "/holders", result));
  }

  /** Every permission a user holds in the caller's tenant, with the roles that grant it. */
  @GetMapping("/users/{userId}/effective-permissions")
  @RequiresPermission(AUDIT_READ)
  @Operation(summary = "List the effective permissions of a user in the caller's tenant")
  @ApiResponse(responseCode = "200", description = "Effective permissions (empty for a user with no role)")
  @ProblemResponse(
      status = 400,
      codes = {"VALIDATION_FAILED"},
      description =
          "Malformed path UUID")
  @ProblemResponse(
      status = 403,
      codes = {"RBAC_001"},
      description =
          "Missing audit:read")
  @ProblemResponse(
      status = 404,
      codes = {"USER_NOT_FOUND"},
      description =
          "User not found, or in another tenant (indistinguishable)")
  public EffectivePermissionsResponse getEffectivePermissions(
      @PathVariable String userId, Authentication authentication) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, AUDIT_READ);
    UUID parsedUserId = RbacControllerSupport.parsePathUuid(userId, "userId");

    var permissions =
        accessReviewService.getEffectivePermissions(actor, parsedUserId).stream()
            .map(
                p ->
                    new EffectivePermissionEntry(
                        p.name(), p.viaRoleIds().stream().map(UUID::toString).toList()))
            .toList();
    return new EffectivePermissionsResponse(parsedUserId.toString(), permissions);
  }
}
