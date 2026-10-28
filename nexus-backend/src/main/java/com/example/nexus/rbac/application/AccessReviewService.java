package com.example.nexus.rbac.application;

import static com.example.nexus.common.security.Permissions.AUDIT_READ;

import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.application.port.out.UserRoleQueryPort;
import com.example.nexus.rbac.domain.EffectivePermission;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionHolder;
import com.example.nexus.rbac.domain.PermissionViaRole;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleHolder;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Access review (US-018 C3, 03-design.md 11.3): who holds a role, who holds a permission, and what a
 * user effectively holds, always inside the caller's own tenant (taken from the JWT by the
 * controller), ids only (no email, no name; the client joins ids to names under identity's own
 * permissions). Every method is read-only and non-locking.
 *
 * <p><b>Repeatable Read Snapshot Semantics:</b> Reads are executed under transaction-level snapshot
 * isolation ({@code readOnly = true}) without locking. Concurrent modifications committed after the
 * snapshot is established are invisible to the review display.
 *
 * <p><b>Disclosure (RES-37, Low, accepted).</b> This is the first live use of {@code audit:read}, and
 * the role-holders and permission-holders reads disclose the tenant's administrator roster. The one
 * control inside this class is the {@code assignedBy} redaction: it is shown only to an administrator
 * by the one definition ({@link RoleAssignmentService#isCallerAdministrator}), the same rule and
 * shape as {@code listActive} (R1-4). Without it an {@code audit:read} holder could read who assigned
 * whom, bypassing that rule (T-I17).
 *
 * <p><b>Tenant isolation (B1).</b> A role or user of another tenant is the same 404 as a missing one
 * (byte-identical body), with the WARN {@code RBAC_CROSS_TENANT_TARGET} and the {@code
 * permission_denied} counter as evidence. A permission is global, so its only 404 is "no such
 * permission", decided against the catalogue; the tenant filter is in the holder query. Each
 * successful query logs INFO {@code RBAC_ACCESS_REVIEW_QUERY} (actor, tenant, endpoint, subject id)
 * and counts {@code nexus.rbac.access_review_query{endpoint}}.
 *
 * <p>Self-policed design invariant, as {@link RoleAssignmentService}'s: every public method accepts
 * only {@link RoleChangeActor}, {@link UUID} and ints, never an authentication object.
 */
@Service
@Transactional(readOnly = true)
public class AccessReviewService {

  private static final Logger log = LoggerFactory.getLogger(AccessReviewService.class);

  private static final String ENDPOINT_ROLE_HOLDERS = "role_holders";
  private static final String ENDPOINT_PERMISSION_HOLDERS = "permission_holders";
  private static final String ENDPOINT_EFFECTIVE_PERMISSIONS = "effective_permissions";

  public static final int MAX_EFFECTIVE_PERMISSIONS = 1000;
  private static final String COUNTER_ACCESS_REVIEW_QUERY = "nexus.rbac.access_review_query";
  private static final String COUNTER_PERMISSION_DENIED = "nexus.rbac.permission_denied";
  private static final String MESSAGE_NO_SUCH_ROLE = "No such role";
  private static final String MESSAGE_NO_SUCH_USER = "No such user";
  private static final String MESSAGE_NO_SUCH_PERMISSION = "No such permission";

  private final UserRoleAssignmentPort userRoleAssignmentPort;
  private final UserRoleQueryPort userRoleQueryPort;
  private final UserDirectoryPort userDirectoryPort;
  private final MeterRegistry meterRegistry;

  public AccessReviewService(
      UserRoleAssignmentPort userRoleAssignmentPort,
      UserRoleQueryPort userRoleQueryPort,
      UserDirectoryPort userDirectoryPort,
      MeterRegistry meterRegistry) {
    this.userRoleAssignmentPort = userRoleAssignmentPort;
    this.userRoleQueryPort = userRoleQueryPort;
    this.userDirectoryPort = userDirectoryPort;
    this.meterRegistry = meterRegistry;
  }

  /**
   * One page of the active holders of {@code roleId}. 404 {@code ROLE_NOT_FOUND} for a missing,
   * deleted or foreign role. {@code assignedBy} is {@code null} unless the caller is an
   * administrator.
   */
  public PageResult<RoleHolder> listRoleHolders(
      RoleChangeActor actor, UUID roleId, int page, int size) {
    Role role =
        userRoleAssignmentPort
            .findRole(roleId)
            .orElseThrow(() -> new ResourceNotFoundException("ROLE_NOT_FOUND", MESSAGE_NO_SUCH_ROLE));
    if (!role.getTenantId().equals(actor.tenantId())) {
      throw crossTenantNotFound(actor, "role", "ROLE_NOT_FOUND", MESSAGE_NO_SUCH_ROLE);
    }
    recordQuery(actor, ENDPOINT_ROLE_HOLDERS, roleId);

    PageResult<RoleHolder> holders =
        userRoleAssignmentPort.findActiveRoleHolders(roleId, actor.tenantId(), page, size);
    if (RoleAssignmentService.isCallerAdministrator(userRoleAssignmentPort, actor)) {
      return holders;
    }
    return holders.map(RoleHolder::withAssignedByRedacted);
  }

  /**
   * One page, ordered by user id, of the users of the caller's tenant who hold {@code permissionId},
   * each with the live roles that grant it. 404 {@code PERMISSION_NOT_FOUND} when the permission is
   * not in the catalogue.
   */
  public PageResult<PermissionHolder> listPermissionHolders(
      RoleChangeActor actor, UUID permissionId, int page, int size) {
    if (!userRoleAssignmentPort.findCatalogueIds().contains(permissionId)) {
      throw new ResourceNotFoundException("PERMISSION_NOT_FOUND", MESSAGE_NO_SUCH_PERMISSION);
    }
    recordQuery(actor, ENDPOINT_PERMISSION_HOLDERS, permissionId);
    return userRoleAssignmentPort.findPermissionHolders(
        permissionId, actor.tenantId(), page, size);
  }

  /**
   * Every permission {@code userId} holds in the caller's tenant, each with the live roles that grant
   * it, ordered by name. Unpaginated: bounded by the catalogue. 404 {@code USER_NOT_FOUND} for a
   * missing or foreign user. A user with no role has an empty list.
   */
  public List<EffectivePermission> getEffectivePermissions(RoleChangeActor actor, UUID userId) {
    UUID userTenantId =
        userDirectoryPort
            .findTenantId(userId)
            .orElseThrow(() -> new ResourceNotFoundException("USER_NOT_FOUND", MESSAGE_NO_SUCH_USER));
    if (!userTenantId.equals(actor.tenantId())) {
      throw crossTenantNotFound(actor, "user", "USER_NOT_FOUND", MESSAGE_NO_SUCH_USER);
    }
    recordQuery(actor, ENDPOINT_EFFECTIVE_PERMISSIONS, userId);

    Map<String, List<UUID>> rolesByPermission = new LinkedHashMap<>();
    for (PermissionViaRole row :
        userRoleQueryPort.findActivePermissionsViaRoles(userId, actor.tenantId())) {
      if (rolesByPermission.size() >= MAX_EFFECTIVE_PERMISSIONS
          && !rolesByPermission.containsKey(row.permissionName())) {
        break;
      }
      rolesByPermission
          .computeIfAbsent(row.permissionName(), name -> new ArrayList<>())
          .add(row.roleId());
    }
    return rolesByPermission.entrySet().stream()
        .limit(MAX_EFFECTIVE_PERMISSIONS)
        .map(e -> new EffectivePermission(e.getKey(), e.getValue()))
        .toList();
  }

  /** INFO {@code RBAC_ACCESS_REVIEW_QUERY} and the per-endpoint counter (ids only, no tenant tag). */
  private void recordQuery(RoleChangeActor actor, String endpoint, UUID subjectId) {
    log.atInfo()
        .addKeyValue("event", "RBAC_ACCESS_REVIEW_QUERY")
        .addKeyValue("actorUserId", actor.userId())
        .addKeyValue("tenantId", actor.tenantId())
        .addKeyValue("endpoint", endpoint)
        .addKeyValue("subjectId", subjectId)
        .log("Access review query");
    Counter.builder(COUNTER_ACCESS_REVIEW_QUERY)
        .tag("endpoint", endpoint)
        .register(meterRegistry)
        .increment();
  }

  /**
   * The cross-tenant 404 (B1): the same code and message as a genuine not-found, so the body is
   * byte-identical. The evidence is the WARN {@code RBAC_CROSS_TENANT_TARGET} (no foreign id) and the
   * {@code permission_denied} series. No audit row, as everywhere in B1.
   */
  private ResourceNotFoundException crossTenantNotFound(
      RoleChangeActor actor, String targetKind, String code, String message) {
    log.atWarn()
        .addKeyValue("event", "RBAC_CROSS_TENANT_TARGET")
        .addKeyValue("tenantId", actor.tenantId())
        .addKeyValue("actorUserId", actor.userId())
        .addKeyValue("targetKind", targetKind)
        .addKeyValue("operation", "access_review")
        .log("Refused an access review read: the target belongs to another tenant");
    Counter.builder(COUNTER_PERMISSION_DENIED)
        .tag("permission", AUDIT_READ)
        .tag("reason", DenialReason.CROSS_TENANT_TARGET.name())
        .register(meterRegistry)
        .increment();
    return new ResourceNotFoundException(code, message);
  }
}
