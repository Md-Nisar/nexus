package com.example.nexus.rbac.interfaces.rest;

import com.example.nexus.common.domain.FieldValidationException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.security.AuthenticatedRequestDetails;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.common.security.RequiresPermission;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.interfaces.rest.dto.AssignRoleRequest;
import com.example.nexus.rbac.interfaces.rest.dto.RoleAssignmentListResponse;
import com.example.nexus.rbac.interfaces.rest.dto.RoleAssignmentResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.MDC;
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
 * First controller in the {@code rbac} bounded context: assign, list, and revoke a user's role
 * assignments within the caller's own tenant (US-012, 03-design.md §4.1/§8).
 *
 * <p><b>The only place in this request path that touches {@link Authentication} (T-E10/R-10).</b>
 * Every handler unwraps it into a plain {@link RoleChangeActor} immediately and passes only that
 * plus plain {@link UUID}s and a {@link RequestContext} into {@link RoleAssignmentService} — never
 * {@code Authentication}, never {@code java.security.Principal}, never the raw details {@code Map}.
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

  private static final String USER_WRITE = "user:write";
  private static final String USER_READ = "user:read";

  private static final Pattern CANONICAL_UUID =
      Pattern.compile(
          "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

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
  @RequiresPermission(USER_WRITE)
  @Operation(summary = "Assign a role to a user within the caller's tenant")
  @ApiResponse(responseCode = "201", description = "Assignment created")
  @ApiResponse(responseCode = "400", description = "Malformed path or body UUID")
  @ApiResponse(
      responseCode = "403",
      description = "Missing permission, cross-tenant target, or caller is not an active TENANT_ADMIN")
  @ApiResponse(responseCode = "404", description = "User or role not found")
  @ApiResponse(responseCode = "409", description = "Duplicate active assignment")
  public ResponseEntity<RoleAssignmentResponse> assignRole(
      @PathVariable String userId,
      @Valid @RequestBody AssignRoleRequest request,
      Authentication authentication,
      HttpServletRequest httpRequest) {
    RoleChangeActor actor = resolveActor(authentication, USER_WRITE);
    UUID targetUserId = parsePathUuid(userId, "userId");
    UUID roleId = parsePathUuid(request.roleId(), "roleId");

    ActiveRoleAssignment assignment =
        roleAssignmentService.assign(actor, targetUserId, roleId, requestContext(httpRequest));

    return ResponseEntity.created(locationUri(userId, request.roleId())).body(toResponse(assignment));
  }

  /**
   * Lists the active role assignments held by {@code userId} within the caller's own tenant.
   *
   * @param userId path-carried target user id (canonical-UUID string; parsed after validation)
   * @param authentication the current authentication; unwrapped here into a {@link RoleChangeActor}
   * @return 200 with a {@code data} envelope (03-design.md §8.3/D7)
   */
  @GetMapping("/{userId}/roles")
  @RequiresPermission(USER_READ)
  @Operation(summary = "List the active role assignments held by a user within the caller's tenant")
  @ApiResponse(responseCode = "200", description = "Active role assignments")
  @ApiResponse(responseCode = "400", description = "Malformed path UUID")
  @ApiResponse(responseCode = "403", description = "Missing permission or cross-tenant target")
  @ApiResponse(responseCode = "404", description = "User not found")
  public RoleAssignmentListResponse listRoles(
      @PathVariable String userId, Authentication authentication) {
    RoleChangeActor actor = resolveActor(authentication, USER_READ);
    UUID targetUserId = parsePathUuid(userId, "userId");

    List<RoleAssignmentResponse> data =
        roleAssignmentService.listActive(actor, targetUserId).stream()
            .map(UserRoleController::toResponse)
            .toList();
    return new RoleAssignmentListResponse(data);
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
  @RequiresPermission(USER_WRITE)
  @Operation(summary = "Revoke a role from a user within the caller's tenant")
  @ApiResponse(responseCode = "204", description = "Role revoked")
  @ApiResponse(responseCode = "400", description = "Malformed path UUID")
  @ApiResponse(responseCode = "403", description = "Missing permission or cross-tenant target")
  @ApiResponse(responseCode = "404", description = "User, role, or active assignment not found")
  @ApiResponse(responseCode = "409", description = "Would revoke the tenant's last active TENANT_ADMIN")
  public void revokeRole(
      @PathVariable String userId,
      @PathVariable String roleId,
      Authentication authentication,
      HttpServletRequest httpRequest) {
    RoleChangeActor actor = resolveActor(authentication, USER_WRITE);
    UUID targetUserId = parsePathUuid(userId, "userId");
    UUID parsedRoleId = parsePathUuid(roleId, "roleId");

    roleAssignmentService.revoke(actor, targetUserId, parsedRoleId, requestContext(httpRequest));
  }

  /**
   * Unwraps {@code authentication} into a {@link RoleChangeActor}. Tenant provenance is delegated
   * to {@link AuthenticatedRequestDetails#fromAuthentication}, which already fails closed
   * (malformed details → {@code MALFORMED_AUTHENTICATION}; blank/absent tenant → {@code
   * MISSING_TENANT}).
   *
   * <p><b>Principal provenance must fail closed too (T-S4).</b> {@code
   * authentication.getPrincipal()} is not guaranteed by any compile-time contract to be a
   * parseable UUID string. A null, non-{@code String}, or non-UUID principal must not be allowed
   * to throw an unhandled {@code ClassCastException}/{@code IllegalArgumentException} that falls
   * through to the generic 500 handler — it must throw {@link InsufficientPermissionException}
   * with {@link DenialReason#MALFORMED_AUTHENTICATION} instead.
   */
  private RoleChangeActor resolveActor(Authentication authentication, String requiredPermission) {
    AuthenticatedRequestDetails details =
        AuthenticatedRequestDetails.fromAuthentication(authentication, requiredPermission);

    if (!(authentication.getPrincipal() instanceof String principalId)) {
      throw new InsufficientPermissionException(
          requiredPermission, DenialReason.MALFORMED_AUTHENTICATION);
    }
    UUID actorUserId;
    try {
      actorUserId = UUID.fromString(principalId);
    } catch (IllegalArgumentException e) {
      throw new InsufficientPermissionException(
          requiredPermission, DenialReason.MALFORMED_AUTHENTICATION);
    }
    UUID tenantId;
    try {
      tenantId = UUID.fromString(details.tenantId());
    } catch (IllegalArgumentException e) {
      // Distinct from the principal-parse failure above (03-design.md §4.1, §8.4 row 4): an
      // unparseable tenantId is MISSING_TENANT, not MALFORMED_AUTHENTICATION.
      throw new InsufficientPermissionException(requiredPermission, DenialReason.MISSING_TENANT);
    }
    return new RoleChangeActor(actorUserId, tenantId);
  }

  /**
   * Validates {@code value} as a canonical-UUID-shaped string and parses it, in that order (D15).
   * A malformed value throws {@link FieldValidationException}, which {@code
   * GlobalExceptionHandler#handleFieldValidation} already maps to 400 with a {@code details[]}
   * entry naming {@code field} — never a raw {@code UUID.fromString} failure reaching an
   * unhandled-exception path.
   */
  private UUID parsePathUuid(String value, String field) {
    if (value == null || !CANONICAL_UUID.matcher(value).matches()) {
      throw new FieldValidationException("VALIDATION_FAILED", field, "must be a canonical UUID");
    }
    return UUID.fromString(value);
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

  /**
   * Constructs a {@link RequestContext} from the HTTP request, mirroring {@code
   * RegistrationController#requestContext} exactly (client IP, MDC trace ID, User-Agent header).
   */
  private RequestContext requestContext(HttpServletRequest req) {
    return RequestContext.of(req.getRemoteAddr(), MDC.get("traceId"), req.getHeader("User-Agent"));
  }
}
