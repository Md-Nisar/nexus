package com.example.nexus.rbac.interfaces.rest;

import static com.example.nexus.common.security.Permissions.ROLE_READ;
import static com.example.nexus.common.security.Permissions.ROLE_WRITE;

import com.example.nexus.common.domain.FieldValidationException;
import com.example.nexus.common.domain.PreconditionRequiredException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.security.RequiresPermission;
import com.example.nexus.common.web.ProblemResponse;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleCounts;
import com.example.nexus.rbac.domain.RolePermissionSet;
import com.example.nexus.rbac.domain.RoleView;
import com.example.nexus.rbac.interfaces.rest.dto.AttachPermissionRequest;
import com.example.nexus.rbac.interfaces.rest.dto.CreateRoleRequest;
import com.example.nexus.rbac.interfaces.rest.dto.PageLinks;
import com.example.nexus.rbac.interfaces.rest.dto.PageMetadata;
import com.example.nexus.rbac.interfaces.rest.dto.PermissionListResponse;
import com.example.nexus.rbac.interfaces.rest.dto.PermissionResponse;
import com.example.nexus.rbac.interfaces.rest.dto.ReplaceRolePermissionsRequest;
import com.example.nexus.rbac.interfaces.rest.dto.RoleListResponse;
import com.example.nexus.rbac.interfaces.rest.dto.RoleResponse;
import com.example.nexus.rbac.interfaces.rest.dto.UpdateRoleRequest;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
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

  private static final String PATH_PARAM_ROLE_ID = "roleId";
  private static final String PATH_PARAM_PERMISSION_ID = "permissionId";
  private static final String BODY_FIELD_PERMISSION_IDS = "permissionIds";

  private final RoleManagementService roleManagementService;
  private final MeterRegistry meterRegistry;
  private final Map<String, ResponseEntity<RoleResponse>> idempotencyCache =
      new ConcurrentHashMap<>();

  public RoleController(RoleManagementService roleManagementService, MeterRegistry meterRegistry) {
    this.roleManagementService = roleManagementService;
    this.meterRegistry = meterRegistry;
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
  @ProblemResponse(
      status = 400,
      codes = {"VALIDATION_FAILED"},
      description =
          "Validation failed")
  @ProblemResponse(
      status = 403,
      codes = {"RBAC_001"},
      description =
          "Missing role:write")
  @ProblemResponse(
      status = 409,
      codes = {"RBAC_006", "RBAC_007", "RBAC_008"},
      description =
          "Duplicate (RBAC_006) or reserved (RBAC_007) role name, or the tenant's role limit reached (RBAC_008)")
  @ProblemResponse(
      status = 429,
      codes = {"ROLE_CHANGE_THROTTLED"},
      description =
          "Too many role changes requested; see Retry-After")
  public ResponseEntity<RoleResponse> createRole(
      @Valid @RequestBody CreateRoleRequest request,
      Authentication authentication,
      HttpServletRequest httpRequest) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, ROLE_WRITE);

    String idempotencyKey = httpRequest != null ? httpRequest.getHeader("Idempotency-Key") : null;
    String cacheKey = (idempotencyKey != null && !idempotencyKey.isBlank())
        ? actor.tenantId() + ":" + idempotencyKey.strip()
        : null;
    if (cacheKey != null) {
      ResponseEntity<RoleResponse> cached = idempotencyCache.get(cacheKey);
      if (cached != null) {
        return cached;
      }
    }

    RoleView role =
        roleManagementService.createRole(
            actor, request.name(), request.description(), RbacControllerSupport.requestContext(httpRequest));

    ResponseEntity<RoleResponse> response =
        ResponseEntity.created(URI.create("/api/v1/roles/" + role.id()))
            .body(toResponse(role, null));

    if (cacheKey != null) {
      idempotencyCache.put(cacheKey, response);
    }

    return response;
  }

  /**
   * Lists one page of the roles in the caller's own tenant, ordered by {@code (name, id)} (AC2, AC8,
   * D11; paginated by US-018 C2). {@code page} is 0-based (default 0), {@code size} defaults to 20
   * and is at most 100; an out-of-range value is a 400, never clamped.
   *
   * @return 200 with {@code data}, {@code page} and {@code links}
   */
  @GetMapping
  @RequiresPermission(ROLE_READ)
  @Operation(summary = "List the roles in the caller's tenant, one page at a time")
  @ApiResponse(responseCode = "200", description = "A page of roles in the caller's tenant")
  @ProblemResponse(
      status = 400,
      codes = {"VALIDATION_FAILED"},
      description =
          "page or size out of range, or not an integer")
  @ProblemResponse(
      status = 403,
      codes = {"RBAC_001"},
      description =
          "Missing role:read")
  public RoleListResponse listRoles(
      @RequestParam(name = "page", required = false) String page,
      @RequestParam(name = "size", required = false) String size,
      Authentication authentication) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, ROLE_READ);
    PageParams params = PageParams.parse(page, size);

    PageResult<RoleView> result = roleManagementService.listRoles(actor, params.page(), params.size());
    Map<UUID, RoleCounts> counts =
        roleManagementService.countsForRoles(
            actor, result.items().stream().map(RoleView::id).toList());
    return new RoleListResponse(
        result.items().stream().map(view -> toResponse(view, counts.get(view.id()))).toList(),
        PageMetadata.of(result),
        PageLinks.of("/api/v1/roles", result));
  }

  /**
   * Reads one role of the caller's own tenant (US-019 B3). Missing, deleted and other-tenant ids
   * are one indistinguishable 404. There is no ETag.
   *
   * @return 200 with the role
   */
  @GetMapping("/{roleId}")
  @RequiresPermission(ROLE_READ)
  @Operation(summary = "Read one role in the caller's tenant")
  @ApiResponse(responseCode = "200", description = "The role")
  @ProblemResponse(
      status = 400,
      codes = {"VALIDATION_FAILED"},
      description =
          "Malformed path UUID")
  @ProblemResponse(
      status = 403,
      codes = {"RBAC_001"},
      description =
          "Missing role:read")
  @ProblemResponse(
      status = 404,
      codes = {"ROLE_NOT_FOUND"},
      description =
          "Role not found, deleted, or in another tenant (indistinguishable)")
  public RoleResponse getRole(@PathVariable String roleId, Authentication authentication) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, ROLE_READ);
    UUID parsedRoleId = RbacControllerSupport.parsePathUuid(roleId, PATH_PARAM_ROLE_ID);

    RoleView role = roleManagementService.getRole(actor, parsedRoleId);
    return toResponse(role, countsOf(actor, role));
  }

  /**
   * Lists the permissions attached to a role in the caller's own tenant (AC3, AC8). Reads against
   * a system role are allowed — AC7's guard is scoped to writes. US-019 B8: the {@code ETag} is the
   * version of exactly this set, the value a replace sends back in {@code If-Match}.
   *
   * @return 200 with a {@code data} envelope and an {@code ETag}; empty list is a valid 200
   */
  @GetMapping("/{roleId}/permissions")
  @RequiresPermission(ROLE_READ)
  @Operation(
      summary = "List the permissions attached to a role in the caller's tenant",
      description =
          "The ETag validates the permission set and is what PUT expects in If-Match."
              + " If-None-Match and 304 are not supported; responses are not cacheable.")
  @ApiResponse(responseCode = "200", description = "Permissions attached to the role, with an ETag")
  @ProblemResponse(
      status = 400,
      codes = {"VALIDATION_FAILED"},
      description =
          "Malformed path UUID")
  @ProblemResponse(
      status = 403,
      codes = {"RBAC_001"},
      description =
          "Missing role:read")
  @ProblemResponse(
      status = 404,
      codes = {"ROLE_NOT_FOUND"},
      description =
          "Role not found, or in another tenant (indistinguishable)")
  public ResponseEntity<PermissionListResponse> listRolePermissions(
      @PathVariable String roleId, Authentication authentication) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, ROLE_READ);
    UUID parsedRoleId = RbacControllerSupport.parsePathUuid(roleId, PATH_PARAM_ROLE_ID);

    return withEtag(roleManagementService.listRolePermissions(actor, parsedRoleId));
  }

  /**
   * Atomically replaces the permission set of a role in the caller's own tenant (US-019 B8, design
   * §10.5). {@code If-Match} must carry exactly one strong entity-tag, the {@code ETag} of the set
   * the editor read. The order of outcomes is fixed so an unauthorised caller learns nothing about
   * the set: 400, 428, 404, 409, 404 permission, 403, then 412, then an unchanged set's 200.
   *
   * @return 200 with the new set and its {@code ETag}
   */
  @PutMapping("/{roleId}/permissions")
  @RequiresPermission(ROLE_WRITE)
  @Operation(
      summary = "Replace the permission set of a role in the caller's tenant",
      description =
          "If-Match must be exactly one strong entity tag, the ETag of the set being replaced. The"
              + " ETag validates the permission set (there is no 304). An unchanged set is an"
              + " authorised no-op 200.")
  @ApiResponse(responseCode = "200", description = "Applied, or unchanged; the set and its ETag")
  @ProblemResponse(
      status = 400,
      codes = {"VALIDATION_FAILED"},
      description =
          "Malformed path UUID or body: permissionIds missing, over 100, a malformed or duplicate id")
  @ProblemResponse(
      status = 403,
      codes = {"RBAC_001"},
      description =
          "Missing role:write or role:read (also in live holdings), an added permission the caller does not hold, or a removal from a role whose permissions the caller does not all hold (for an administrator role: or is not an administrator through another role)")
  @ProblemResponse(
      status = 404,
      codes = {"ROLE_NOT_FOUND", "PERMISSION_NOT_FOUND"},
      description =
          "Role not found, deleted or in another tenant (indistinguishable), or a permission id not in the catalogue")
  @ProblemResponse(
      status = 409,
      codes = {"RBAC_003", "RBAC_010", "RBAC_012"},
      description =
          "System role (RBAC_003); the set would make the role an administrator role while a holder was assigned by a non-administrator (RBAC_010); the role's classification changed while the request waited, retry (RBAC_012)")
  @ProblemResponse(
      status = 412,
      codes = {"PRECONDITION_FAILED"},
      description =
          "The If-Match tag is not the current version of the set; the body has no state")
  @ProblemResponse(
      status = 415,
      codes = {"UNSUPPORTED_MEDIA_TYPE"},
      description =
          "Content type is not application/json")
  @ProblemResponse(
      status = 428,
      codes = {"PRECONDITION_REQUIRED"},
      description =
          "If-Match absent, *, a list, weak, empty or unparseable; the body has no state")
  @ProblemResponse(
      status = 429,
      codes = {"ROLE_CHANGE_THROTTLED"},
      description =
          "Too many role changes requested; see Retry-After")
  public ResponseEntity<PermissionListResponse> replaceRolePermissions(
      @PathVariable String roleId,
      @Valid @RequestBody ReplaceRolePermissionsRequest request,
      @RequestHeader(name = HttpHeaders.IF_MATCH, required = false) String ifMatch,
      Authentication authentication,
      HttpServletRequest httpRequest) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, ROLE_WRITE);
    UUID parsedRoleId = RbacControllerSupport.parsePathUuid(roleId, PATH_PARAM_ROLE_ID);
    Set<UUID> permissionIds = parseDistinctPermissionIds(request.permissionIds());
    String ifMatchTag;
    try {
      ifMatchTag = IfMatchHeader.parse(ifMatch);
    } catch (PreconditionRequiredException e) {
      Counter.builder(RoleManagementService.COUNTER_PERMISSION_REPLACE)
          .tag(
              RoleManagementService.TAG_OUTCOME,
              RoleManagementService.OUTCOME_PRECONDITION_REQUIRED)
          .tag(RoleManagementService.TAG_LOCK_PATH, RoleManagementService.LOCK_PATH_NONE)
          .register(meterRegistry)
          .increment();
      throw e;
    }

    return withEtag(
        roleManagementService.replaceRolePermissions(
            actor,
            parsedRoleId,
            permissionIds,
            ifMatchTag,
            RbacControllerSupport.requestContext(httpRequest)));
  }

  /**
   * Parses the body's ids (already shape-checked by bean validation) and rejects a repeated id,
   * however it is cased, as a 400 on the repeating element.
   */
  private static Set<UUID> parseDistinctPermissionIds(List<String> permissionIds) {
    Set<UUID> parsed = new LinkedHashSet<>();
    for (int i = 0; i < permissionIds.size(); i++) {
      String field = BODY_FIELD_PERMISSION_IDS + "[" + i + "]";
      if (!parsed.add(RbacControllerSupport.parsePathUuid(permissionIds.get(i), field))) {
        throw new FieldValidationException("VALIDATION_FAILED", field, "must not repeat an id");
      }
    }
    return parsed;
  }

  private static ResponseEntity<PermissionListResponse> withEtag(RolePermissionSet set) {
    return ResponseEntity.ok()
        .eTag(set.version())
        .body(
            new PermissionListResponse(
                set.permissions().stream().map(PermissionController::toResponse).toList()));
  }

  /**
   * Attaches a permission to a role in the caller's own tenant (AC4, AC7, AC8, AC12, A3) — the
   * story's security-critical path. The caller may attach only a permission they hold; an attach
   * that would make the role an administrator role is refused while a holder was assigned by a
   * non-administrator.
   *
   * @return 201 with a {@code Location} header addressing the pairing and the attached permission
   */
  @PostMapping("/{roleId}/permissions")
  @ResponseStatus(HttpStatus.CREATED)
  @RequiresPermission(ROLE_WRITE)
  @Operation(summary = "Attach a permission to a role in the caller's tenant")
  @ApiResponse(responseCode = "201", description = "Permission attached")
  @ProblemResponse(
      status = 400,
      codes = {"VALIDATION_FAILED"},
      description =
          "Malformed path or body UUID")
  @ProblemResponse(
      status = 403,
      codes = {"RBAC_001"},
      description =
          "Missing role:write, or the caller does not hold the permission being attached")
  @ProblemResponse(
      status = 404,
      codes = {"ROLE_NOT_FOUND", "PERMISSION_NOT_FOUND"},
      description =
          "Role or permission not found, or role in another tenant (indistinguishable)")
  @ProblemResponse(
      status = 409,
      codes = {"RBAC_003", "RBAC_005", "RBAC_010", "RBAC_012"},
      description =
          "System role (RBAC_003), already attached (RBAC_005), the attach would make the role an administrator role while a holder was assigned by a non-administrator (RBAC_010), or the role's classification changed while the request waited, retry (RBAC_012)")
  @ProblemResponse(
      status = 429,
      codes = {"ROLE_CHANGE_THROTTLED"},
      description =
          "Too many role changes requested; see Retry-After")
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
   * Detaches a permission from a role in the caller's own tenant (AC5, AC7, AC8, AC12). The caller
   * must hold every permission of the role (role-subset), and, when the role is an administrator
   * role, be an administrator through a different role.
   */
  @DeleteMapping("/{roleId}/permissions/{permissionId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @RequiresPermission(ROLE_WRITE)
  @Operation(summary = "Detach a permission from a role in the caller's tenant")
  @ApiResponse(responseCode = "204", description = "Permission detached")
  @ProblemResponse(
      status = 400,
      codes = {"VALIDATION_FAILED"},
      description =
          "Malformed path UUID")
  @ProblemResponse(
      status = 403,
      codes = {"RBAC_001"},
      description =
          "Missing role:write, or the caller does not hold every permission of the role (for an administrator role: or is not an administrator through another role)")
  @ProblemResponse(
      status = 404,
      codes = {"ROLE_NOT_FOUND", "PERMISSION_NOT_FOUND", "ROLE_PERMISSION_NOT_FOUND"},
      description =
          "Role, permission, or pairing not found, or role in another tenant (indistinguishable)")
  @ProblemResponse(
      status = 409,
      codes = {"RBAC_003"},
      description =
          "System role (RBAC_003)")
  @ProblemResponse(
      status = 429,
      codes = {"ROLE_CHANGE_THROTTLED"},
      description =
          "Too many role changes requested; see Retry-After")
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

  /**
   * Renames a custom role and/or changes its description (US-018 C1). Bounded by the caller's own
   * authority exactly like a detach (role-subset), so a {@code role:write} holder cannot make an
   * administrator role look harmless. There is no {@code If-Match}: an admin-only, low-contention
   * resource, last write wins.
   *
   * @return 200 with the updated role
   */
  @PatchMapping("/{roleId}")
  @RequiresPermission(ROLE_WRITE)
  @Operation(summary = "Rename a custom role or change its description in the caller's tenant")
  @ApiResponse(responseCode = "200", description = "Role updated")
  @ProblemResponse(
      status = 400,
      codes = {"VALIDATION_FAILED"},
      description =
          "Validation failed (empty body, bad name or description) or malformed path UUID")
  @ProblemResponse(
      status = 403,
      codes = {"RBAC_001"},
      description =
          "Missing role:write, or the caller does not hold every permission of the role (for an administrator role: or is not an administrator through another role)")
  @ProblemResponse(
      status = 404,
      codes = {"ROLE_NOT_FOUND"},
      description =
          "Role not found, deleted, or in another tenant (indistinguishable)")
  @ProblemResponse(
      status = 409,
      codes = {"RBAC_003", "RBAC_006", "RBAC_007"},
      description =
          "System role (RBAC_003), name already used by a live role (RBAC_006) or reserved (RBAC_007)")
  @ProblemResponse(
      status = 429,
      codes = {"ROLE_CHANGE_THROTTLED"},
      description =
          "Too many role changes requested; see Retry-After")
  public RoleResponse updateRole(
      @PathVariable String roleId,
      @Valid @RequestBody UpdateRoleRequest request,
      Authentication authentication,
      HttpServletRequest httpRequest) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, ROLE_WRITE);
    UUID parsedRoleId = RbacControllerSupport.parsePathUuid(roleId, PATH_PARAM_ROLE_ID);

    RoleView role =
        roleManagementService.updateRole(
            actor,
            parsedRoleId,
            request.name(),
            request.description(),
            RbacControllerSupport.requestContext(httpRequest));
    return toResponse(role, countsOf(actor, role));
  }

  /**
   * Soft-deletes a custom role that has no active holder (US-018 C1). Bounded by the caller's own
   * authority exactly like a detach: the caller must hold every permission of the role (and, for an
   * administrator role, be an administrator through another role). The role stays in the audit
   * trail; its name stays reserved until the V10 contract step.
   */
  @DeleteMapping("/{roleId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @RequiresPermission(ROLE_WRITE)
  @Operation(summary = "Delete a custom role in the caller's tenant (soft delete)")
  @ApiResponse(responseCode = "204", description = "Role deleted")
  @ProblemResponse(
      status = 400,
      codes = {"VALIDATION_FAILED"},
      description =
          "Malformed path UUID")
  @ProblemResponse(
      status = 403,
      codes = {"RBAC_001"},
      description =
          "Missing role:write, or the caller does not hold every permission of the role (for an administrator role: or is not an administrator through another role)")
  @ProblemResponse(
      status = 404,
      codes = {"ROLE_NOT_FOUND"},
      description =
          "Role not found, already deleted, or in another tenant (indistinguishable)")
  @ProblemResponse(
      status = 409,
      codes = {"RBAC_003", "RBAC_009"},
      description =
          "System role (RBAC_003), or the role still has active holders (RBAC_009)")
  @ProblemResponse(
      status = 429,
      codes = {"ROLE_CHANGE_THROTTLED"},
      description =
          "Too many role changes requested; see Retry-After")
  public void softDeleteRole(
      @PathVariable String roleId, Authentication authentication, HttpServletRequest httpRequest) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, ROLE_WRITE);
    UUID parsedRoleId = RbacControllerSupport.parsePathUuid(roleId, PATH_PARAM_ROLE_ID);

    roleManagementService.softDeleteRole(
        actor, parsedRoleId, RbacControllerSupport.requestContext(httpRequest));
  }

  private RoleCounts countsOf(RoleChangeActor actor, RoleView role) {
    return roleManagementService.countsForRoles(actor, List.of(role.id())).get(role.id());
  }

  /** A {@code null} {@code counts} (a new role, or no entry) reports 0 members and 0 permissions. */
  private static RoleResponse toResponse(RoleView view, RoleCounts counts) {
    return new RoleResponse(
        view.id().toString(),
        view.name(),
        view.description(),
        view.systemRole(),
        view.createdAt(),
        counts == null ? 0L : counts.memberCount(),
        counts == null ? 0 : counts.permissionCount());
  }
}
