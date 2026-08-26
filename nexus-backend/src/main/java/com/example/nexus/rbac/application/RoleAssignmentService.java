package com.example.nexus.rbac.application;

import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.application.port.out.RbacAuditEvent;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentRef;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.LastAdminRoleException;
import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Assigns, revokes, and lists tenant-scoped role assignments (03-design.md §4.2, §3.1-§3.3).
 *
 * <p>This is the <b>only</b> place AC4 (tenant isolation), AC5 (last-admin lockout), and AC8 (only
 * an active {@code TENANT_ADMIN} may grant {@code TENANT_ADMIN}) are enforced — {@code
 * @RequiresPermission}/{@code TenantAwarePermissionEvaluator} check nothing but flat JWT {@code
 * permissions[]} membership and cannot express any of them (threat model T-E7/T-E8/T-E9/T-E10).
 *
 * <p><b>Design invariant, self-policed (not compiler-enforced):</b> every public method on this
 * class accepts only {@link RoleChangeActor}, {@link UUID}, and {@link RequestContext} as
 * parameter types — never {@code org.springframework.security.core.Authentication}, never {@code
 * java.security.Principal}, never {@code java.util.Map}, never {@code
 * common.security.AuthenticatedRequestDetails}. ArchUnit's {@code
 * domain_and_application_must_not_depend_on_spring_security} rule only catches types living in a
 * banned package — {@code Principal}/{@code Map} do not, and would compile fine while
 * reintroducing raw authentication data into this layer (T-E10).
 */
@Service
public class RoleAssignmentService {

  private static final Logger log = LoggerFactory.getLogger(RoleAssignmentService.class);

  private static final String USER_WRITE = "user:write";
  private static final String USER_READ = "user:read";

  private static final String LOG_KEY_EVENT = "event";
  private static final String LOG_KEY_TENANT_ID = "tenantId";
  private static final String LOG_KEY_TARGET_USER_ID = "targetUserId";
  private static final String LOG_KEY_ROLE_ID = "roleId";

  private final UserRoleAssignmentPort userRoleAssignmentPort;
  private final UserDirectoryPort userDirectoryPort;
  private final RbacAuditPort rbacAuditPort;
  private final PermissionCachePort permissionCachePort;

  public RoleAssignmentService(
      UserRoleAssignmentPort userRoleAssignmentPort,
      UserDirectoryPort userDirectoryPort,
      RbacAuditPort rbacAuditPort,
      PermissionCachePort permissionCachePort) {
    this.userRoleAssignmentPort = userRoleAssignmentPort;
    this.userDirectoryPort = userDirectoryPort;
    this.rbacAuditPort = rbacAuditPort;
    this.permissionCachePort = permissionCachePort;
  }

  /**
   * Grants {@code roleId} to {@code targetUserId} within the actor's own tenant (AC1, AC4, AC6,
   * AC7, AC8). Returns the created assignment, including its DB-generated {@code assignedAt}.
   *
   * <p><b>Security note (07-security-review.md M-3, accepted/deferred — same class of forward-
   * tracked gap as {@link #revoke}'s T-E9 note, and should be closed alongside it):</b> the AC8
   * guard below matches on the role's <em>name</em> ({@code TENANT_ADMIN}), not on the privilege
   * it confers. Any caller holding {@code user:write} may grant any role in the tenant that is
   * <em>not literally named</em> {@code TENANT_ADMIN} — including granting it to themselves,
   * since nothing here restricts {@code targetUserId == actor.userId()}. This is unreachable
   * today (only {@code TENANT_ADMIN} itself carries {@code user:write} pre-US-015), but the
   * moment a future story lets a tenant create a custom role carrying {@code user:write} (or
   * {@code role:write}/{@code tenant:write}), a non-admin can self-grant admin-equivalent
   * authority through that role with AC8 never firing. A custom-roles story must close this by
   * gating any role carrying such a permission on an active {@code TENANT_ADMIN} check (reusing
   * {@link UserRoleAssignmentPort#hasActiveAdminAssignment}), not by extending the name match.
   */
  @Transactional
  public ActiveRoleAssignment assign(
      RoleChangeActor actor, UUID targetUserId, UUID roleId, RequestContext requestContext) {
    Role role;
    try {
      verifySameTenant(targetUserId, actor, USER_WRITE);
      role = resolveRoleInTenant(roleId, actor, USER_WRITE);
    } catch (InsufficientPermissionException e) {
      // roleName is null by construction here: T1 runs before the role is resolved, and T2's
      // resolveRoleInTenant throws without returning the (foreign-tenant) Role. A denial row
      // therefore never carries another tenant's role name.
      recordDenial(actor, targetUserId, roleId, null, e.getReason(), requestContext);
      throw e;
    }

    if (RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(role.getName())) {
      // AC8: only an active TENANT_ADMIN may grant TENANT_ADMIN. This MUST be a live,
      // locking (M5) DB read on the CALLER -- never derived from actor or any JWT claim.
      // RoleChangeActor carries no permission/role data, so there is no way to get this
      // wrong "by construction" -- but the reason this call exists and must stay a live
      // read is that a JWT's roles[]/permissions[] claim can be up to ~15 minutes stale
      // (threat model T-E7): a caller whose admin assignment was revoked out-of-band but
      // who still holds a valid, unexpired JWT must not be able to mint a new admin.
      boolean callerIsActiveAdmin =
          userRoleAssignmentPort.hasActiveAdminAssignment(
              actor.userId(), role.getId(), actor.tenantId());
      if (!callerIsActiveAdmin) {
        recordDenial(
            actor, targetUserId, roleId, role.getName(), DenialReason.NOT_TENANT_ADMIN,
            requestContext);
        throw new InsufficientPermissionException(USER_WRITE, DenialReason.NOT_TENANT_ADMIN);
      }
    }

    if (userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)) {
      // Deliberately DEBUG, not WARN: a duplicate-assignment attempt is a benign client bug,
      // not a security signal (contrast the WARN below on the last-admin lockout guard).
      // nexus.domain.conflict{code="RBAC_004"} already provides the trend-line metric.
      log.atDebug()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_DUPLICATE_ASSIGNMENT")
          .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
          .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
          .addKeyValue(LOG_KEY_ROLE_ID, roleId)
          .log("Duplicate active role assignment attempted");
      throw new DuplicateRoleAssignmentException();
    }

    // assignedBy is ALWAYS actor.userId() -- never derived from targetUserId or any other
    // path/request-supplied value (T-S3).
    userRoleAssignmentPort.assign(targetUserId, roleId, actor.tenantId(), actor.userId());

    // Re-read via the M4a projection rather than the just-persisted entity: a projection
    // reads DB-generated values (assignedAt) directly, whereas the entity instance in the
    // session would still show a null assignedAt.
    ActiveRoleAssignment assignment =
        userRoleAssignmentPort
            .findActiveAssignmentView(targetUserId, roleId, actor.tenantId())
            .orElseThrow(); // structurally impossible: the row was just inserted above

    registerPostCommitSideEffects(
        () -> {
          permissionCachePort.evict(actor.tenantId(), targetUserId);
          rbacAuditPort.recordRoleAssigned(
              new RbacAuditEvent(
                  actor.tenantId(),
                  targetUserId,
                  roleId,
                  role.getName(),
                  actor.userId(),
                  requestContext));
          // Operator-visible confirmation independent of the audit table's own availability
          // (the audit write above is itself best-effort — see RbacAuditPort's contract).
          log.atInfo()
              .addKeyValue(LOG_KEY_EVENT, "ROLE_ASSIGNED")
              .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
              .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
              .addKeyValue(LOG_KEY_ROLE_ID, roleId)
              .addKeyValue("assignedBy", actor.userId())
              .log("Role assigned");
        });

    return assignment;
  }

  /**
   * Revokes {@code roleId} from {@code targetUserId} within the actor's own tenant (AC2, AC4,
   * AC5, AC6, AC7).
   *
   * <p><b>Security note (T-E9, accepted/deferred):</b> revocation of {@code TENANT_ADMIN} is
   * gated only by the caller holding {@code user:write} (enforced upstream by {@code
   * @RequiresPermission}, not in this class) plus this method's own last-admin guard below —
   * there is <b>no</b> symmetric check requiring the caller to already be an active {@code
   * TENANT_ADMIN} to <em>revoke</em> one, unlike {@link #assign}'s AC8 check for <em>granting</em>
   * one. This is a deliberate, currently-unreachable gap (today only {@code TENANT_ADMIN} itself
   * holds {@code user:write}) that a future story enabling custom roles with {@code user:write}
   * must close with a symmetric "only an active TENANT_ADMIN may revoke TENANT_ADMIN" check before
   * it ships.
   */
  @Transactional
  public void revoke(
      RoleChangeActor actor, UUID targetUserId, UUID roleId, RequestContext requestContext) {
    Role role;
    try {
      verifySameTenant(targetUserId, actor, USER_WRITE);
      role = resolveRoleInTenant(roleId, actor, USER_WRITE);
    } catch (InsufficientPermissionException e) {
      // roleName is null by construction here -- same rationale as assign()'s catch above.
      recordDenial(actor, targetUserId, roleId, null, e.getReason(), requestContext);
      throw e;
    }

    // Resolved once, ahead of the admin-lockout check: this covers "never assigned" and
    // "already revoked" identically for both admin and non-admin roles, and its id is what
    // the lockout check below needs to test set-membership against.
    ActiveAssignmentRef ref = findAssignmentRefOrThrow(targetUserId, roleId, actor.tenantId());

    if (RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(role.getName())) {
      List<UUID> lockedActiveAdminIds =
          userRoleAssignmentPort.lockActiveAssignmentIds(actor.tenantId(), role.getId());
      // AC5, actor-agnostic: fires for ANY caller revoking the tenant's last active
      // TENANT_ADMIN assignment, not only self-revocation.
      if (lockedActiveAdminIds.size() <= 1 && lockedActiveAdminIds.contains(ref.id())) {
        // WARN, not DEBUG: an operator needs to know which tenant nearly locked itself out
        // and who tried, independent of the nexus.domain.conflict{code="RBAC_002"} counter.
        log.atWarn()
            .addKeyValue(LOG_KEY_EVENT, "RBAC_LAST_ADMIN_REVOCATION_BLOCKED")
            .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
            .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
            .addKeyValue("actorUserId", actor.userId())
            .addKeyValue(LOG_KEY_ROLE_ID, roleId)
            .log("Blocked revocation of the tenant's last active TENANT_ADMIN assignment");
        throw new LastAdminRoleException();
      }
    }

    // App-side clamp, not a DB-side FUNCTION('now', 6): this codebase's pinned Hibernate
    // version rejects that HQL construct at parse time ("Function now() has 0 parameters, but
    // 1 arguments given"). max(now, assignedAt) can never violate the revoked_at >= assigned_at
    // CHECK constraint, by construction (03-design.md §5.2 M6's own anticipated fallback).
    Instant now = Instant.now();
    Instant revokedAt = now.isBefore(ref.assignedAt()) ? ref.assignedAt() : now;

    int affectedRows = userRoleAssignmentPort.revoke(ref.id(), revokedAt);
    if (affectedRows == 0) {
      // Lost race: someone else revoked this exact assignment between the read above and
      // this write.
      throw assignmentNotFound();
    }

    registerPostCommitSideEffects(
        () -> {
          permissionCachePort.evict(actor.tenantId(), targetUserId);
          rbacAuditPort.recordRoleRevoked(
              new RbacAuditEvent(
                  actor.tenantId(),
                  targetUserId,
                  roleId,
                  role.getName(),
                  actor.userId(),
                  requestContext));
          log.atInfo()
              .addKeyValue(LOG_KEY_EVENT, "ROLE_REVOKED")
              .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
              .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
              .addKeyValue(LOG_KEY_ROLE_ID, roleId)
              .addKeyValue("revokedBy", actor.userId())
              .log("Role revoked");
        });
  }

  /**
   * Lists the active role assignments held by {@code targetUserId} within the actor's own tenant
   * (AC3, AC4).
   *
   * <p>{@code assignedBy} is omitted (nulled out) unless the caller holds an active {@code
   * TENANT_ADMIN} assignment in this tenant (O-10/T-I5) — narrowing the admin-roster/granter graph
   * to admins, since every self-registered {@code MEMBER} otherwise holds {@code user:read}.
   */
  @Transactional(readOnly = true)
  public List<ActiveRoleAssignment> listActive(RoleChangeActor actor, UUID targetUserId) {
    // MANDATORY, not redundant with M4's own tenant predicates (T-E8): without this
    // explicit check, a cross-tenant GET would silently return 200 {"data":[]} instead of a
    // 403, destroying the WARN log + denial metric that makes cross-tenant probing
    // detectable.
    verifySameTenant(targetUserId, actor, USER_READ);

    List<ActiveRoleAssignment> assignments =
        userRoleAssignmentPort.findActiveAssignmentViews(targetUserId, actor.tenantId());

    if (callerHoldsActiveTenantAdmin(actor)) {
      return assignments;
    }
    return assignments.stream().map(RoleAssignmentService::withAssignedByRedacted).toList();
  }

  /**
   * Whether {@code actor} holds an active {@code TENANT_ADMIN} assignment in their own tenant.
   *
   * <p>{@link UserRoleAssignmentPort#hasActiveAdminAssignment} needs the tenant's {@code
   * TENANT_ADMIN} {@code roleId} up front, and the port exposes no "find role by (tenant, name)"
   * lookup. Rather than adding a new port method for this minor visibility nuance, this reuses the
   * already-existing M4 projection ({@link UserRoleAssignmentPort#findActiveAssignmentViews}) —
   * already used above for the response itself — to inspect the caller's own active role names.
   * This is a plain (non-locking) read, which is appropriate here: unlike AC8's live-admin check,
   * this only decides whether to redact one response field, not whether to authorize a mutation.
   */
  private boolean callerHoldsActiveTenantAdmin(RoleChangeActor actor) {
    return userRoleAssignmentPort
        .findActiveAssignmentViews(actor.userId(), actor.tenantId())
        .stream()
        .anyMatch(a -> RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(a.roleName()));
  }

  private static ActiveRoleAssignment withAssignedByRedacted(ActiveRoleAssignment assignment) {
    return new ActiveRoleAssignment(
        assignment.userId(), assignment.roleId(), assignment.roleName(), assignment.assignedAt(),
        null);
  }

  /**
   * AC4 tenant-isolation check on the subject ({@code targetUserId}): empty ⇒ 404 {@code
   * USER_NOT_FOUND}; a tenant other than {@code actor.tenantId()} ⇒ 403 {@code
   * CROSS_TENANT_TARGET}.
   */
  private void verifySameTenant(UUID targetUserId, RoleChangeActor actor, String requiredPermission) {
    UUID targetTenantId =
        userDirectoryPort
            .findTenantId(targetUserId)
            .orElseThrow(
                () -> new ResourceNotFoundException("USER_NOT_FOUND", "No such user"));
    if (!targetTenantId.equals(actor.tenantId())) {
      throw new InsufficientPermissionException(requiredPermission, DenialReason.CROSS_TENANT_TARGET);
    }
  }

  /**
   * AC4 tenant-isolation check on the role: empty ⇒ 404 {@code ROLE_NOT_FOUND}; a tenant other
   * than {@code actor.tenantId()} ⇒ 403 {@code CROSS_TENANT_TARGET}.
   */
  private Role resolveRoleInTenant(UUID roleId, RoleChangeActor actor, String requiredPermission) {
    Role role =
        userRoleAssignmentPort
            .findRole(roleId)
            .orElseThrow(
                () -> new ResourceNotFoundException("ROLE_NOT_FOUND", "No such role"));
    if (!role.getTenantId().equals(actor.tenantId())) {
      throw new InsufficientPermissionException(requiredPermission, DenialReason.CROSS_TENANT_TARGET);
    }
    return role;
  }

  private ActiveAssignmentRef findAssignmentRefOrThrow(UUID targetUserId, UUID roleId, UUID tenantId) {
    return userRoleAssignmentPort
        .findActiveAssignmentRef(targetUserId, roleId, tenantId)
        .orElseThrow(this::assignmentNotFound);
  }

  private ResourceNotFoundException assignmentNotFound() {
    return new ResourceNotFoundException(
        "ROLE_ASSIGNMENT_NOT_FOUND", "This role assignment does not exist or was already revoked");
  }

  /**
   * Emits a {@code ROLE_ASSIGNMENT_DENIED} audit row for a 403 authorization denial (US-014 AC4).
   * Called INLINE, before the caller rethrows, from a transaction about to roll back -- never via
   * {@link #registerPostCommitSideEffects}, since {@code afterCommit} never fires on a doomed
   * transaction. {@code actor.tenantId()}: the row is always written under the actor's tenant,
   * never the target's.
   */
  private void recordDenial(
      RoleChangeActor actor,
      UUID targetUserId,
      UUID roleId,
      String roleName,
      DenialReason reason,
      RequestContext requestContext) {
    try {
      rbacAuditPort.recordRoleAssignmentDenied(
          new RbacAuditEvent(
              actor.tenantId(), targetUserId, roleId, roleName, actor.userId(), requestContext),
          reason);
    } catch (RuntimeException e) {
      // Defense in depth: RbacAuditPort's contract already says implementations must never
      // throw, but the denial itself must win regardless of whether a future implementation
      // honors that contract.
      log.atError()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_AUDIT_DENIAL_CALL_SITE_FAILED")
          .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
          .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
          .log("recordRoleAssignmentDenied threw despite its never-throw contract", e);
    }
  }

  /**
   * Runs {@code sideEffects} (cache evict + audit) after the enclosing transaction commits. If no
   * transaction synchronization is active — the normal situation in a plain unit test with no real
   * transaction, or any caller invoking {@link #assign}/{@link #revoke} outside a Spring-managed
   * transaction — {@code sideEffects} is run inline immediately instead of being silently dropped.
   * This fallback is deliberate, not a bug: it is the only way a unit test can ever observe these
   * side effects firing.
   */
  private void registerPostCommitSideEffects(Runnable sideEffects) {
    if (TransactionSynchronizationManager.isSynchronizationActive()) {
      TransactionSynchronizationManager.registerSynchronization(
          new TransactionSynchronization() {
            @Override
            public void afterCommit() {
              sideEffects.run();
            }
          });
    } else {
      sideEffects.run();
    }
  }
}
