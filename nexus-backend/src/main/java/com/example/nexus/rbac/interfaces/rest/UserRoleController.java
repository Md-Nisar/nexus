package com.example.nexus.rbac.interfaces.rest;

import static com.example.nexus.common.security.Permissions.USER_READ;
import static com.example.nexus.common.security.Permissions.USER_ROLE_ASSIGN;

import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.security.RequiresPermission;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.interfaces.rest.dto.AssignRoleRequest;
import com.example.nexus.rbac.interfaces.rest.dto.PageLinks;
import com.example.nexus.rbac.interfaces.rest.dto.PageMetadata;
import com.example.nexus.rbac.interfaces.rest.dto.RoleAssignmentListResponse;
import com.example.nexus.rbac.interfaces.rest.dto.RoleAssignmentResponse;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * First controller in the {@code rbac} bounded context: assign, list, and revoke a user's role
 * assignments within the caller's own tenant (US-012, 03-design.md §4.1/§8).
 *
 * <p><b>The only place in this request path that touches {@link Authentication} (T-E10/R-10),
 * alongside {@link RoleController} and {@link PermissionController} (US-015, D4).</b> Every
 * handler unwraps it into a plain {@link RoleChangeActor} via {@link
 * RbacControllerSupport#resolveActor} and passes only that plus plain {@link UUID}s and a {@link
 * RequestContext} into {@link RoleAssignmentService} — never {@code Authentication}, never {@code
 * java.security.Principal}, never the raw details {@code Map}.
 *
 * <p><b>Every handler is {@code public} and non-{@code final} (T-E11).</b> {@code
 * UserProfileController#me()} — the nearest in-repo template — is package-private, which per
 * {@link RequiresPermission}'s own Javadoc means Spring AOP may silently never enforce the
 * annotation on it: no error, no failing test. Do not copy that visibility here.
 *
 * <p><b>Path variables and the request body's {@code roleId} are {@code String}, validated as
 * canonical-UUID-shaped, and parsed to {@link UUID} only after validation passes (D15/R-12).</b> A
 * {@code UUID}-typed {@code @PathVariable} or body field would let a malformed value raise an
 * exception {@code GlobalExceptionHandler} (a plain {@code @RestControllerAdvice}, not {@code
 * ResponseEntityExceptionHandler}) does not catch, producing a 500 instead of a 400.
 */
@RestController
@RequestMapping("/api/v1/users")
@ConditionalOnProperty(
    name = "feature.nexus-us012-rbac-role-assignment.enabled",
    havingValue = "true")
@Tag(name = "Role Assignment", description = "Tenant-scoped role assignment and revocation")
public class UserRoleController {

  // US-018 A1 (ADR-0021 D1): local constant until the typed catalogue (B5) lands.
  private static final String PATH_PARAM_USER_ID = "userId";

  private final RoleAssignmentService roleAssignmentService;

  public UserRoleController(RoleAssignmentService roleAssignmentService) {
    this.roleAssignmentService = roleAssignmentService;
  }

  /**
   * Grants {@code request.roleId()} to the user identified by {@code userId}, within the caller's
   * own tenant.
   *
   * @param userId path-carried target user id (canonical-UUID string; parsed after validation)
   * @param request validated request body carrying {@code roleId}
   * @param authentication the current authentication; unwrapped here into a {@link RoleChangeActor}
   * @param httpRequest used to build the {@link RequestContext} for audit enrichment
   * @return 201 with a {@code Location} header addressing the new sub-resource and the created
   *     assignment
   */
  @PostMapping("/{userId}/roles")
  @ResponseStatus(HttpStatus.CREATED)
  @RequiresPermission(USER_ROLE_ASSIGN)
  @Operation(summary = "Assign a role to a user within the caller's tenant")
  @ApiResponse(responseCode = "201", description = "Assignment created")
  @ApiResponse(responseCode = "400", description = "Malformed path or body UUID")
  @ApiResponse(
      responseCode = "403",
      description =
          "Missing permission, the role carries a permission the caller does"
              + " not hold, or a self-assignment by a caller who is not an administrator")
  @ApiResponse(responseCode = "404", description = "User or role not found, or in another tenant (indistinguishable)")
  @ApiResponse(responseCode = "409", description = "Duplicate active assignment")
  public ResponseEntity<RoleAssignmentResponse> assignRole(
      @PathVariable String userId,
      @Valid @RequestBody AssignRoleRequest request,
      Authentication authentication,
      HttpServletRequest httpRequest) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, USER_ROLE_ASSIGN);
    UUID targetUserId = RbacControllerSupport.parsePathUuid(userId, PATH_PARAM_USER_ID);
    UUID roleId = RbacControllerSupport.parsePathUuid(request.roleId(), "roleId");

    ActiveRoleAssignment assignment =
        roleAssignmentService.assign(
            actor, targetUserId, roleId, RbacControllerSupport.requestContext(httpRequest));

    return ResponseEntity.created(locationUri(userId, request.roleId())).body(toResponse(assignment));
  }

  /**
   * Lists one page of the active role assignments held by {@code userId} within the caller's own
   * tenant, ordered by {@code (assignedAt, id)} (paginated by US-018 C2). {@code page} is 0-based
   * (default 0), {@code size} defaults to 20 and is at most 100; an out-of-range value is a 400,
   * never clamped.
   *
   * @param userId path-carried target user id (canonical-UUID string; parsed after validation)
   * @param authentication the current authentication; unwrapped here into a {@link RoleChangeActor}
   * @return 200 with {@code data}, {@code page} and {@code links} (03-design.md §8.3/D7)
   */
  @GetMapping("/{userId}/roles")
  @RequiresPermission(USER_READ)
  @Operation(
      summary = "List the active role assignments held by a user within the caller's tenant")
  @ApiResponse(responseCode = "200", description = "A page of active role assignments")
  @ApiResponse(
      responseCode = "400",
      description = "Malformed path UUID, or page or size out of range or not an integer")
  @ApiResponse(responseCode = "403", description = "Missing permission")
  @ApiResponse(responseCode = "404", description = "User not found, or in another tenant (indistinguishable)")
  public RoleAssignmentListResponse listRoles(
      @PathVariable String userId,
      @RequestParam(name = "page", required = false) String page,
      @RequestParam(name = "size", required = false) String size,
      Authentication authentication) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, USER_READ);
    UUID targetUserId = RbacControllerSupport.parsePathUuid(userId, PATH_PARAM_USER_ID);
    PageParams params = PageParams.parse(page, size);

    PageResult<ActiveRoleAssignment> result =
        roleAssignmentService.listActive(actor, targetUserId, params.page(), params.size());
    return new RoleAssignmentListResponse(
        result.items().stream().map(UserRoleController::toResponse).toList(),
        PageMetadata.of(result),
        PageLinks.of("/api/v1/users/" + targetUserId + "/roles", result));
  }

  /**
   * Revokes {@code roleId} from {@code userId} within the caller's own tenant.
   *
   * @param userId path-carried target user id (canonical-UUID string; parsed after validation)
   * @param roleId path-carried role id (canonical-UUID string; parsed after validation)
   * @param authentication the current authentication; unwrapped here into a {@link RoleChangeActor}
   * @param httpRequest used to build the {@link RequestContext} for audit enrichment
   */
  @DeleteMapping("/{userId}/roles/{roleId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @RequiresPermission(USER_ROLE_ASSIGN)
  @Operation(summary = "Revoke a role from a user within the caller's tenant")
  @ApiResponse(responseCode = "204", description = "Role revoked")
  @ApiResponse(responseCode = "400", description = "Malformed path UUID")
  @ApiResponse(
      responseCode = "403",
      description =
          "Missing permission, the role carries a permission the caller does"
              + " not hold, or the role is an administrator role and the caller is not an"
              + " administrator")
  @ApiResponse(responseCode = "404", description =
          "User, role, or active assignment not found, or user or role in another tenant"
              + " (indistinguishable)")
  @ApiResponse(
      responseCode = "409",
      description = "Would revoke the tenant's last active administrator assignment")
  public void revokeRole(
      @PathVariable String userId,
      @PathVariable String roleId,
      Authentication authentication,
      HttpServletRequest httpRequest) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, USER_ROLE_ASSIGN);
    UUID targetUserId = RbacControllerSupport.parsePathUuid(userId, PATH_PARAM_USER_ID);
    UUID parsedRoleId = RbacControllerSupport.parsePathUuid(roleId, "roleId");

    roleAssignmentService.revoke(
        actor, targetUserId, parsedRoleId, RbacControllerSupport.requestContext(httpRequest));
  }

  private static URI locationUri(String userId, String roleId) {
    return URI.create("/api/v1/users/" + userId + "/roles/" + roleId);
  }

  private static RoleAssignmentResponse toResponse(ActiveRoleAssignment assignment) {
    return new RoleAssignmentResponse(
        assignment.userId().toString(),
        assignment.roleId().toString(),
        assignment.roleName(),
        assignment.assignedAt(),
        assignment.assignedBy() == null ? null : assignment.assignedBy().toString());
  }
}
