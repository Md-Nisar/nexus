package com.example.nexus.rbac.application;

import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.application.port.out.RbacAuditEvent;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.RoleChangeThrottlePort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.ActiveAssignmentRef;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.LastAdminRoleException;
import com.example.nexus.rbac.domain.RbacAdministrators;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermissionRef;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Assigns, revokes, and lists tenant-scoped role assignments (03-design.md §4, §5.3).
 *
 * <p>This is the <b>only</b> place the assignment rules are enforced; {@code
 * @RequiresPermission} checks nothing but flat JWT {@code permissions[]} membership and cannot
 * express any of them. The rules, in the order they apply (ADR-0021):
 *
 * <ul>
 *   <li><b>Tenant isolation.</b> The target user and the role must belong to the caller's tenant;
 *       a missing one is 404, a foreign one 403.
 *   <li><b>One definition of "administrator".</b> A role is admin-defining iff it carries every
 *       permission of the catalogue, and a user is an administrator iff they actively hold such a
 *       role ({@link RbacAdministrators}). Names do not matter.
 *   <li><b>A caller may only hand out what they hold.</b> Assigning a role requires the caller to
 *       hold every permission of that role (the union of their live holdings); revoking it
 *       requires the same, and revoking an admin-defining role additionally requires the caller to
 *       be an administrator, so a partial holder cannot strip an administrator.
 *   <li><b>No self-assignment unless administrator.</b> A caller who is not an administrator
 *       cannot assign any role to themselves.
 *   <li><b>The last administrator stays.</b> A revoke that would leave the tenant without a
 *       distinct holder of an admin-defining role is refused (409).
 * </ul>
 *
 * <p><b>Locking.</b> When the target role is admin-defining, one single-statement lock over every
 * active assignment of the tenant's admin-defining roles plus the target role is taken first, in
 * ascending unsigned byte order (ADR-0018 D5 to D7). On that path the caller's administrator
 * status comes from the rows that lock returns, which are current, and never from the snapshot
 * read that feeds the subset comparisons (ADR-0021 D2). A benign target takes no lock.
 *
 * <p><b>Self-policed design invariant:</b> every public method accepts only {@link
 * RoleChangeActor}, {@link UUID}, and {@link RequestContext} as parameter types, never an
 * authentication object, {@code java.security.Principal} or {@code java.util.Map}. See {@code
 * docs/adr/0021-grant-subset-authorization-model.md}.
 */
@Service
public class RoleAssignmentService {

  private static final Logger log = LoggerFactory.getLogger(RoleAssignmentService.class);

  /**
   * US-018 A1 (ADR-0021 D1): the endpoint permission for assign and revoke, and therefore the
   * {@code requiredPermission} of every 403 they raise. Local constant until the typed catalogue
   * (B5) lands.
   */
  private static final String USER_ROLE_ASSIGN = "user:role:assign";
  private static final String USER_READ = "user:read";

  private static final String OPERATION_ASSIGN = "assign";
  private static final String OPERATION_REVOKE = "revoke";

  private static final String TIMER_PRIVILEGED_REVOKE_LOCK_HOLD =
      "nexus.rbac.privileged_revoke_lock_hold";
  private static final String TAG_OUTCOME = "outcome";
  private static final String OUTCOME_DENIED = "denied";
  private static final String OUTCOME_LOCKOUT = "lockout";
  private static final String OUTCOME_REVOKED = "revoked";
  private static final String OUTCOME_ASSIGNED = "assigned";
  private static final String OUTCOME_CONFLICT = "conflict";
  private static final String OUTCOME_ERROR = "error";

  private static final String COUNTER_ADMIN_ROLE_ASSIGNED = "nexus.rbac.admin_role_assigned";
  private static final String COUNTER_SELF_ASSIGN_ADMIN_DISAGREEMENT =
      "nexus.rbac.self_assign_admin_disagreement";
  private static final String TAG_SELF_TARGET = "selfTarget";
  private static final String METRIC_ADMIN_DEFINING_LOCK_SET_SIZE =
      "nexus.rbac.admin_equivalent_lock_set_size";

  private static final String LOG_KEY_EVENT = "event";
  private static final String LOG_KEY_TENANT_ID = "tenantId";
  private static final String LOG_KEY_TARGET_USER_ID = "targetUserId";
  private static final String LOG_KEY_ACTOR_USER_ID = "actorUserId";
  private static final String LOG_KEY_ROLE_ID = "roleId";
  private static final String LOG_KEY_OPERATION = "operation";
  private static final String LOG_KEY_MISSING_COUNT = "missingCount";
  private static final String LOG_KEY_MAX_DENIALS = "maxDenials";
  private static final String LOG_KEY_WINDOW_SECONDS = "windowSeconds";

  private static final String COUNTER_DENIAL_THROTTLED = "nexus.rbac.denial_throttled";
  private static final String COUNTER_LAST_ADMIN_LOCKOUT_BLOCKED =
      "nexus.rbac.last_admin_lockout_blocked";

  /**
   * The total order the set lock's deterministic acquisition proof rests on. "Ascending" means
   * unsigned byte-wise order of the 16-byte UUID representation, matching MySQL's {@code
   * BINARY(16)} comparison, never {@link UUID#compareTo}, which compares {@code mostSigBits} as a
   * SIGNED {@code long} and would silently diverge from the database's own order for an id whose
   * high bit is set (MC-E).
   */
  private static final Comparator<UUID> UNSIGNED_BYTEWISE_UUID_ORDER =
      (a, b) -> {
        int cmp = Long.compareUnsigned(a.getMostSignificantBits(), b.getMostSignificantBits());
        return cmp != 0
            ? cmp
            : Long.compareUnsigned(a.getLeastSignificantBits(), b.getLeastSignificantBits());
      };

  private final UserRoleAssignmentPort userRoleAssignmentPort;
  private final UserDirectoryPort userDirectoryPort;
  private final RbacAuditPort rbacAuditPort;
  private final PermissionCachePort permissionCachePort;
  private final PermissionFreshnessService permissionFreshnessService;
  private final MeterRegistry meterRegistry;
  private final RoleChangeThrottlePort throttlePort;
  private final int maxDenials;
  private final int windowSeconds;

  public RoleAssignmentService(
      UserRoleAssignmentPort userRoleAssignmentPort,
      UserDirectoryPort userDirectoryPort,
      RbacAuditPort rbacAuditPort,
      PermissionCachePort permissionCachePort,
      PermissionFreshnessService permissionFreshnessService,
      MeterRegistry meterRegistry,
      RoleChangeThrottlePort throttlePort,
      @Value("${nexus.rbac.denial-throttle.max-denials}") int maxDenials,
      @Value("${nexus.rbac.denial-throttle.window-seconds}") int windowSeconds) {
    this.userRoleAssignmentPort = userRoleAssignmentPort;
    this.userDirectoryPort = userDirectoryPort;
    this.rbacAuditPort = rbacAuditPort;
    this.permissionCachePort = permissionCachePort;
    this.permissionFreshnessService = permissionFreshnessService;
    this.meterRegistry = meterRegistry;
    this.throttlePort = throttlePort;
    this.maxDenials = maxDenials;
    this.windowSeconds = windowSeconds;
  }

  /**
   * Grants {@code roleId} to {@code targetUserId} within the actor's own tenant. Returns the
   * created assignment, including its DB-generated {@code assignedAt}.
   *
   * <p>Order: tenant checks (404/403), throttle, classify the target role (is it admin-defining?),
   * the set lock when it is, the caller's live holdings, then in this order the {@code
   * user:role:assign} re-check (07-security-review.md L-1), A4 (self-assignment needs an
   * administrator), A2 (the role's permissions must be a subset of the caller's), the duplicate
   * 409 and the insert. One denial row carries the first reason. Neither A4 nor A2 closes RES-26
   * (pre-positioning through a second account).
   *
   * <p>A4's "is the caller an administrator?" comes from the set lock's rows when the target is
   * admin-defining and from the snapshot otherwise; A2 compares against the snapshot's union in
   * both cases (RES-27).
   */
  @Transactional
  public ActiveRoleAssignment assign(
      RoleChangeActor actor, UUID targetUserId, UUID roleId, RequestContext requestContext) {
    Role role;
    try {
      verifySameTenant(targetUserId, actor, USER_ROLE_ASSIGN);
      role = resolveRoleInTenant(roleId, actor, USER_ROLE_ASSIGN);
    } catch (InsufficientPermissionException e) {
      // roleName is null by construction here: the target check runs before the role is resolved,
      // and resolveRoleInTenant throws without returning the (foreign-tenant) Role. A denial row
      // therefore never carries another tenant's role name.
      recordDenial(
          actor, targetUserId, roleId, null, e.getReason(), OPERATION_ASSIGN, requestContext, null);
      throw e;
    }

    requireNotThrottled(actor, OPERATION_ASSIGN, requestContext);

    TargetClassification target =
        classifyTarget(actor, targetUserId, role, OPERATION_ASSIGN, requestContext);
    SetLock setLock = target.adminDefining() ? acquireSetLock(actor, target, role) : null;
    Timer.Sample lockHoldSample = setLock == null ? null : setLock.holdTimer();

    try {
      List<RolePermissionRef> heldRolePermissions =
          userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(
              actor.userId(), actor.tenantId());
      requireCallerStillHoldsUserRoleAssign(
          actor, targetUserId, role, heldRolePermissions, OPERATION_ASSIGN, requestContext);

      boolean selfTarget = targetUserId.equals(actor.userId());
      boolean callerIsAdministrator =
          selfTarget && callerIsAdministrator(actor, setLock, heldRolePermissions, target);
      if (selfTarget && !callerIsAdministrator) {
        denySelfAssignment(actor, targetUserId, role, requestContext);
      }
      requireGrantWithinCallerHoldings(
          actor, targetUserId, role, target, heldRolePermissions, OPERATION_ASSIGN,
          requestContext);

      if (userRoleAssignmentPort.hasActiveAssignment(targetUserId, roleId)) {
        // Deliberately DEBUG, not WARN: a duplicate-assignment attempt is a benign client bug,
        // not a security signal. nexus.domain.conflict{code="RBAC_004"} is the trend-line metric.
        log.atDebug()
            .addKeyValue(LOG_KEY_EVENT, "RBAC_DUPLICATE_ASSIGNMENT")
            .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
            .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
            .addKeyValue(LOG_KEY_ROLE_ID, roleId)
            .log("Duplicate active role assignment attempted");
        throw new DuplicateRoleAssignmentException();
      }

      // Row 7 (RC-28.1): the independent check runs BEFORE the insert. After it, a self-assignment
      // of an admin-defining role would see the row this very request creates and could never
      // disagree (US-017 RES-25). It records a signal for a request A4 has already decided.
      if (selfTarget) {
        captureIndependentAdministratorCheck(actor, role, callerIsAdministrator);
      }

      // assignedBy is ALWAYS actor.userId(), never derived from targetUserId or any
      // request-supplied value (T-S3).
      userRoleAssignmentPort.assign(targetUserId, roleId, actor.tenantId(), actor.userId());

      // Re-read via the projection rather than the just-persisted entity: a projection reads
      // DB-generated values (assignedAt) directly.
      ActiveRoleAssignment assignment =
          userRoleAssignmentPort
              .findActiveAssignmentView(targetUserId, roleId, actor.tenantId())
              .orElseThrow(); // structurally impossible: the row was just inserted above

      // A6 (design §6.2): the success audit is written INLINE, inside this transaction. The port
      // contract requires it to throw on failure, so a lost audit write rolls this transaction back
      // and surfaces as a 500 rather than committing a role change with no audit trail.
      rbacAuditPort.recordRoleAssigned(
          new RbacAuditEvent(
              actor.tenantId(), targetUserId, roleId, role.getName(), actor.userId(),
              requestContext));

      registerPostCommitSideEffects(
          () -> {
            permissionCachePort.evict(actor.tenantId(), targetUserId);
            log.atInfo()
                .addKeyValue(LOG_KEY_EVENT, "ROLE_ASSIGNED")
                .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
                .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
                .addKeyValue(LOG_KEY_ROLE_ID, roleId)
                .addKeyValue("assignedBy", actor.userId())
                .log("Role assigned");
            // Stopped from afterCommit(), the true "at commit" point.
            stopLockHoldTimer(lockHoldSample, OPERATION_ASSIGN, OUTCOME_ASSIGNED);
            // Row 9: an administrator was minted. Ticket, never page: a self-target by an
            // administrator is legitimate. Bounded tag, no tenant tag.
            if (target.adminDefining()) {
              Counter.builder(COUNTER_ADMIN_ROLE_ASSIGNED)
                  .tag(TAG_SELF_TARGET, Boolean.toString(selfTarget))
                  .register(meterRegistry)
                  .increment();
            }
          });

      return assignment;
    } catch (InsufficientPermissionException e) {
      stopLockHoldTimer(lockHoldSample, OPERATION_ASSIGN, OUTCOME_DENIED);
      throw e;
    } catch (DuplicateRoleAssignmentException e) {
      stopLockHoldTimer(lockHoldSample, OPERATION_ASSIGN, OUTCOME_CONFLICT);
      throw e;
    } catch (RuntimeException e) {
      stopLockHoldTimer(lockHoldSample, OPERATION_ASSIGN, OUTCOME_ERROR);
      throw e;
    }
  }

  /**
   * Revokes {@code roleId} from {@code targetUserId} within the actor's own tenant.
   *
   * <p>Order (design §5.3): tenant checks (404/403), the assignment lookup (404), throttle, classify
   * the target role, the set lock when it is admin-defining, then <b>revoke-subset</b> (403): when
   * the role is admin-defining the caller must be an administrator according to the set lock's own
   * rows ({@code NOT_TENANT_ADMIN}, evaluated first because it needs no other read), then the
   * {@code user:role:assign} re-check (L-1), then the caller must hold every permission of the role
   * ({@code GRANT_EXCEEDS_CALLER}); then the distinct-holder lockout (409); then the update. A 403
   * always precedes the 409, so the 409 never tells an unauthorized caller that a role guards the
   * last administrator (ADR-0017 D4).
   */
  @Transactional
  public void revoke(
      RoleChangeActor actor, UUID targetUserId, UUID roleId, RequestContext requestContext) {
    Role role;
    try {
      verifySameTenant(targetUserId, actor, USER_ROLE_ASSIGN);
      role = resolveRoleInTenant(roleId, actor, USER_ROLE_ASSIGN);
    } catch (InsufficientPermissionException e) {
      // roleName is null by construction here -- same rationale as assign()'s catch above.
      recordDenial(
          actor, targetUserId, roleId, null, e.getReason(), OPERATION_REVOKE, requestContext, null);
      throw e;
    }

    // Resolved once, ahead of the lockout check: this covers "never assigned" and "already
    // revoked" identically for every role, and its id is what the lockout check excludes.
    ActiveAssignmentRef ref = findAssignmentRefOrThrow(targetUserId, roleId, actor.tenantId());

    requireNotThrottled(actor, OPERATION_REVOKE, requestContext);

    TargetClassification target =
        classifyTarget(actor, targetUserId, role, OPERATION_REVOKE, requestContext);
    SetLock setLock = target.adminDefining() ? acquireSetLock(actor, target, role) : null;
    Timer.Sample lockHoldSample = setLock == null ? null : setLock.holdTimer();

    try {
      // The administrator requirement first: it needs only the rows the set lock just returned,
      // and it keeps the reason a non-administrator sees on an admin-defining role stable
      // (NOT_TENANT_ADMIN, A-13) whatever else they lack.
      if (setLock != null) {
        requireAdministratorFromSetLock(actor, targetUserId, role, setLock, requestContext);
      }
      List<RolePermissionRef> heldRolePermissions =
          userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(
              actor.userId(), actor.tenantId());
      requireCallerStillHoldsUserRoleAssign(
          actor, targetUserId, role, heldRolePermissions, OPERATION_REVOKE, requestContext);
      requireGrantWithinCallerHoldings(
          actor, targetUserId, role, target, heldRolePermissions, OPERATION_REVOKE,
          requestContext);
      if (setLock != null) {
        // The last-admin lockout: distinct holders of admin-defining roles, not rows, excluding
        // the assignment being revoked (by assignment id, never by user id, so a user's OTHER
        // admin-defining assignment still counts them). Always evaluated AFTER the 403s above.
        if (wouldLeaveTenantWithoutAdministrator(
            setLock.lockedHolders(), ref.id(), setLock.adminDefiningRoleIds())) {
          // WARN, not DEBUG: an operator needs to know which tenant nearly locked itself out and
          // who tried, independent of the nexus.domain.conflict{code="RBAC_002"} counter.
          log.atWarn()
              .addKeyValue(LOG_KEY_EVENT, "RBAC_LAST_ADMIN_REVOCATION_BLOCKED")
              .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
              .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
              .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
              .addKeyValue(LOG_KEY_ROLE_ID, roleId)
              .addKeyValue("adminDefiningRoleCount", setLock.adminDefiningRoleIds().size())
              .addKeyValue("lockedRowCount", setLock.lockedHolders().size())
              .log("Blocked revocation of the tenant's last active administrator assignment");
          Counter.builder(COUNTER_LAST_ADMIN_LOCKOUT_BLOCKED).register(meterRegistry).increment();
          throw new LastAdminRoleException();
        }
      }

      // App-side clamp, not a DB-side FUNCTION('now', 6): this codebase's pinned Hibernate
      // version rejects that HQL construct at parse time. max(now, assignedAt) can never violate
      // the revoked_at >= assigned_at CHECK constraint, by construction.
      Instant now = Instant.now();
      Instant revokedAt = now.isBefore(ref.assignedAt()) ? ref.assignedAt() : now;

      int affectedRows = userRoleAssignmentPort.revoke(ref.id(), revokedAt);
      if (affectedRows == 0) {
        // Lost race: someone else revoked this exact assignment between the read above and this
        // write.
        throw assignmentNotFound();
      }

      // A6 (design §6.2): the success audit is written INLINE, inside this transaction.
      rbacAuditPort.recordRoleRevoked(
          new RbacAuditEvent(
              actor.tenantId(), targetUserId, roleId, role.getName(), actor.userId(),
              requestContext));

      registerPostCommitSideEffects(
          () -> {
            permissionCachePort.evict(actor.tenantId(), targetUserId);
            log.atInfo()
                .addKeyValue(LOG_KEY_EVENT, "ROLE_REVOKED")
                .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
                .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
                .addKeyValue(LOG_KEY_ROLE_ID, roleId)
                .addKeyValue("revokedBy", actor.userId())
                .log("Role revoked");
            // Stopped here, not right after registration: this runnable only executes from
            // afterCommit(), strictly after doCommit() returns, so this is the true "at commit"
            // point the timer is meant to measure (RC-9.5).
            stopLockHoldTimer(lockHoldSample, OPERATION_REVOKE, OUTCOME_REVOKED);
            // A9 (MC-7b): every token the target holds becomes stale. After commit only, so a mint
            // in the gap cannot read the new epoch with pre-commit permissions; after the timer,
            // so the bump's Redis latency does not inflate the lock-hold measurement.
            permissionFreshnessService.invalidateUser(
                actor.tenantId(), targetUserId, OPERATION_REVOKE);
          });
    } catch (InsufficientPermissionException e) {
      stopLockHoldTimer(lockHoldSample, OPERATION_REVOKE, OUTCOME_DENIED);
      throw e;
    } catch (LastAdminRoleException e) {
      stopLockHoldTimer(lockHoldSample, OPERATION_REVOKE, OUTCOME_LOCKOUT);
      throw e;
    } catch (RuntimeException e) {
      // Covers the lost-race 404 and any unexpected failure from the lock, the reads or the audit
      // write: neither is an authorization decision nor a successful revoke, so both are bucketed
      // under the bounded outcome set {denied, lockout, revoked, error}.
      stopLockHoldTimer(lockHoldSample, OPERATION_REVOKE, OUTCOME_ERROR);
      throw e;
    }
  }

  /**
   * Lists the active role assignments held by {@code targetUserId} within the actor's own tenant.
   *
   * <p>{@code assignedBy} is omitted (nulled out) unless the caller is an administrator
   * (03-design.md §2.1; O-10/T-I5): the one definition, a small stated widening of the former
   * literal-name test. A plain snapshot read, appropriate because it decides only whether to
   * redact one response field, never whether to authorize a mutation.
   */
  @Transactional(readOnly = true)
  public List<ActiveRoleAssignment> listActive(RoleChangeActor actor, UUID targetUserId) {
    // MANDATORY, not redundant with the repository's own tenant predicates (T-E8): without this
    // explicit check, a cross-tenant GET would silently return 200 {"data":[]} instead of a 403,
    // destroying the WARN log + denial metric that makes cross-tenant probing detectable.
    verifySameTenant(targetUserId, actor, USER_READ);

    List<ActiveRoleAssignment> assignments =
        userRoleAssignmentPort.findActiveAssignmentViews(targetUserId, actor.tenantId());

    boolean callerIsAdministrator =
        RbacAdministrators.isAdministrator(
            userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(
                actor.userId(), actor.tenantId()),
            userRoleAssignmentPort.findCatalogueIds());
    if (callerIsAdministrator) {
      return assignments;
    }
    return assignments.stream().map(RoleAssignmentService::withAssignedByRedacted).toList();
  }

  /**
   * What the target role is, decided once from M14 (its permission ids) and M15 (the catalogue).
   * {@code adminDefining} drives the set lock; the ids are reused by the subset comparison so the
   * decision and the comparison can never read two different states.
   */
  private record TargetClassification(
      Set<UUID> targetPermissionIds, Set<UUID> catalogueIds, boolean adminDefining) {}

  /**
   * The set lock and what it returned. {@code lockedHolders} are current and X-locked rows, so
   * {@link #callerHoldsAdministratorRole} answers "is the caller an administrator?" without
   * touching the snapshot (ADR-0021 D2).
   */
  private record SetLock(
      Set<UUID> adminDefiningRoleIds,
      List<ActiveAssignmentHolder> lockedHolders,
      Timer.Sample holdTimer) {

    boolean callerHoldsAdministratorRole(UUID callerUserId) {
      return lockedHolders.stream()
          .anyMatch(
              holder ->
                  holder.userId().equals(callerUserId)
                      && adminDefiningRoleIds.contains(holder.roleId()));
    }
  }

  /**
   * Classifies the target role: M14 for its permission ids and M15 for the catalogue. An empty M14
   * {@code Optional} (the role is not in the caller's tenant) denies with {@code
   * CROSS_TENANT_TARGET} and no role name: it is unreachable today (the tenant check ran first and
   * a role's tenant is immutable), so reaching it means an invariant broke, and "grants nothing"
   * would be the wrong reading (07-security-review.md L-2). A read failure propagates (500).
   */
  private TargetClassification classifyTarget(
      RoleChangeActor actor,
      UUID targetUserId,
      Role role,
      String operation,
      RequestContext requestContext) {
    Optional<Set<UUID>> targetPermissionIdsInTenant =
        userRoleAssignmentPort.findPermissionIdsForRole(role.getId(), actor.tenantId());
    if (targetPermissionIdsInTenant.isEmpty()) {
      log.atWarn()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_GRANT_CHECK_ROLE_NOT_IN_TENANT")
          .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
          .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
          .addKeyValue(LOG_KEY_ROLE_ID, role.getId())
          .addKeyValue(LOG_KEY_OPERATION, operation)
          .log("Denied a role change: the role's permissions are not readable in the caller's tenant");
      recordDenial(
          actor, targetUserId, role.getId(), null, DenialReason.CROSS_TENANT_TARGET, operation,
          requestContext, null);
      throw new InsufficientPermissionException(
          USER_ROLE_ASSIGN, DenialReason.CROSS_TENANT_TARGET);
    }
    Set<UUID> catalogueIds = userRoleAssignmentPort.findCatalogueIds();
    return new TargetClassification(
        targetPermissionIdsInTenant.get(),
        catalogueIds,
        RbacAdministrators.isAdminDefining(targetPermissionIdsInTenant.get(), catalogueIds));
  }

  /**
   * Takes the set lock for an admin-defining target: M10' for the tenant's roles, the admin-defining
   * ones among them, then ONE statement locking every active assignment of those roles plus the
   * target role, in ascending unsigned byte order (ADR-0018 D5 to D7, upheld). The target role is
   * always in the set, which is what makes an insert contained.
   */
  private SetLock acquireSetLock(RoleChangeActor actor, TargetClassification target, Role role) {
    Set<UUID> adminDefiningRoleIds =
        resolveAdminDefiningRoleIds(userRoleAssignmentPort, actor.tenantId(), target.catalogueIds());
    List<UUID> lockSet = buildAscendingLockSet(adminDefiningRoleIds, role.getId());
    List<ActiveAssignmentHolder> lockedHolders =
        userRoleAssignmentPort.lockActiveAssignmentHolders(actor.tenantId(), lockSet);
    recordLockSetSize(lockedHolders.size());
    return new SetLock(adminDefiningRoleIds, lockedHolders, Timer.start(meterRegistry));
  }

  /**
   * The ids of the tenant's admin-defining roles, from ONE M10' read and the catalogue. Static and
   * package-private so the break-glass service primes the lock exactly as {@code assign()} and
   * {@code revoke()} do, never a second copy that could drift.
   */
  static Set<UUID> resolveAdminDefiningRoleIds(
      UserRoleAssignmentPort userRoleAssignmentPort, UUID tenantId, Set<UUID> catalogueIds) {
    return RbacAdministrators.adminDefiningRoleIds(
        userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId), catalogueIds);
  }

  /**
   * The ascending-sorted lock set for one change: the tenant's admin-defining role ids and the
   * target role itself. "Ascending" is {@link #UNSIGNED_BYTEWISE_UUID_ORDER}, a port contract of
   * {@link UserRoleAssignmentPort#lockActiveAssignmentHolders}, not a caller convention.
   */
  static List<UUID> buildAscendingLockSet(Set<UUID> adminDefiningRoleIds, UUID targetRoleId) {
    Set<UUID> lockSet = new TreeSet<>(UNSIGNED_BYTEWISE_UUID_ORDER);
    lockSet.addAll(adminDefiningRoleIds);
    lockSet.add(targetRoleId);
    return List.copyOf(lockSet);
  }

  /**
   * The lockout predicate: {@code true} iff the DISTINCT {@code userId}s of {@code lockedHolders}
   * whose {@code roleId} is admin-defining, EXCLUDING the row whose {@code assignmentId} equals
   * {@code revokedAssignmentId}, is empty. Distinct holders, not rows: one user holding two
   * admin-defining roles counts once (MC-D), and the exclusion is by assignment id, never by user
   * id.
   *
   * <p>The lock population and the holder population are the same set, so no separate filter is
   * needed. Package-private so the break-glass service decides "the tenant has no administrator"
   * with the same predicate, passing {@code null} for {@code revokedAssignmentId}: nothing is being
   * revoked there, and {@code null} excludes no row.
   */
  static boolean wouldLeaveTenantWithoutAdministrator(
      List<ActiveAssignmentHolder> lockedHolders,
      UUID revokedAssignmentId,
      Set<UUID> adminDefiningRoleIds) {
    return lockedHolders.stream()
        .filter(holder -> !holder.assignmentId().equals(revokedAssignmentId))
        .filter(holder -> adminDefiningRoleIds.contains(holder.roleId()))
        .map(ActiveAssignmentHolder::userId)
        .distinct()
        .findAny()
        .isEmpty();
  }

  /**
   * Stops the lock-hold timer with the given {@code operation}/{@code outcome} tags. A no-op when
   * {@code sample} is {@code null}: the timer only starts on the set-lock path (an admin-defining
   * target), so a benign role change never participates in it.
   *
   * <p>{@code operation} ({@code assign}/{@code revoke}) is a tag because {@code assign()} holds
   * the same lock; the metric name is historical and kept rather than churning the shipped alert.
   */
  private void stopLockHoldTimer(Timer.Sample sample, String operation, String outcome) {
    if (sample == null) {
      return;
    }
    sample.stop(
        Timer.builder(TIMER_PRIVILEGED_REVOKE_LOCK_HOLD)
            .tag(LOG_KEY_OPERATION, operation)
            .tag(TAG_OUTCOME, outcome)
            .register(meterRegistry));
  }

  /**
   * Records the size of the list the set lock just returned. Untagged (1 series) and recorded on
   * BOTH verbs, immediately after the lock statement executes.
   */
  private void recordLockSetSize(int size) {
    DistributionSummary.builder(METRIC_ADMIN_DEFINING_LOCK_SET_SIZE)
        .register(meterRegistry)
        .record(size);
  }

  /**
   * D14 (03-design.md §4.8, §6.1): after the 404s and before every authorization read, the audit
   * write and the metric. Bounds the cost of repeated authorization denials on {@code
   * assign()}/{@code revoke()} (T-D10, T-D11, RES-8).
   *
   * <p>Defense in depth (MC-7(i)): {@link RoleChangeThrottlePort#isThrottled} is documented to
   * fail safe and never throw, but a throwing implementation must not turn an availability
   * problem into a false block here — any exception is swallowed and treated as "not throttled",
   * falling through to the real gate, which remains authoritative.
   */
  private void requireNotThrottled(
      RoleChangeActor actor, String operation, RequestContext requestContext) {
    boolean throttled;
    try {
      throttled = throttlePort.isThrottled(actor.tenantId(), actor.userId());
    } catch (RuntimeException e) {
      log.atError()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_THROTTLE_IS_THROTTLED_CALL_FAILED")
          .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
          .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
          .addKeyValue(LOG_KEY_OPERATION, operation)
          .log("isThrottled threw despite its never-throw contract", e);
      throttled = false;
    }
    if (!throttled) {
      return;
    }
    Counter.builder(COUNTER_DENIAL_THROTTLED)
        .tag("operation", operation)
        .register(meterRegistry)
        .increment();
    throw new InsufficientPermissionException(USER_ROLE_ASSIGN, DenialReason.NOT_TENANT_ADMIN);
  }

  /**
   * D14 / A-3: records this denial against the throttle and, when it is the transition into the
   * throttled state, emits the one-time WARN {@code RBAC_DENIAL_THROTTLE_ENGAGED}. Defense in
   * depth: a throwing {@link RoleChangeThrottlePort} must never prevent the real {@link
   * InsufficientPermissionException} from being thrown at this method's call site (the gate's own
   * throw in {@link #denyPrivilegedRoleChange}).
   */
  private void recordThrottleDenialAndMaybeWarn(RoleChangeActor actor, String operation) {
    boolean crossedBound;
    try {
      crossedBound = throttlePort.recordDenial(actor.tenantId(), actor.userId());
    } catch (RuntimeException e) {
      log.atError()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_THROTTLE_RECORD_DENIAL_CALL_FAILED")
          .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
          .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
          .addKeyValue(LOG_KEY_OPERATION, operation)
          .log("recordDenial threw despite its never-throw contract", e);
      return;
    }
    if (!crossedBound) {
      return;
    }
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_DENIAL_THROTTLE_ENGAGED")
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_OPERATION, operation)
        .addKeyValue(LOG_KEY_MAX_DENIALS, maxDenials)
        .addKeyValue(LOG_KEY_WINDOW_SECONDS, windowSeconds)
        .log("Denial throttle engaged for this actor");
  }

  /**
   * Whether the caller is an administrator, for A4. On the set-lock path the answer comes from the
   * lock's rows, never from the snapshot (RC-25.1): the snapshot's read view can predate a wait on
   * the lock. Otherwise it comes from the snapshot's per-role rows and the catalogue, never the
   * union across roles.
   */
  private boolean callerIsAdministrator(
      RoleChangeActor actor,
      SetLock setLock,
      List<RolePermissionRef> heldRolePermissions,
      TargetClassification target) {
    if (setLock != null) {
      return setLock.callerHoldsAdministratorRole(actor.userId());
    }
    return RbacAdministrators.isAdministrator(heldRolePermissions, target.catalogueIds());
  }

  /**
   * A4 (ADR-0021 D4): a caller may assign a role to themselves only if they are an administrator.
   * This closes the literal self-target step only; the same pre-positioning through a second
   * account is not prevented here (RES-26, T-E32). Always throws.
   */
  private void denySelfAssignment(
      RoleChangeActor actor, UUID targetUserId, Role role, RequestContext requestContext) {
    recordThrottleDenialAndMaybeWarn(actor, OPERATION_ASSIGN);
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_SELF_ASSIGNMENT_DENIED")
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_ROLE_ID, role.getId())
        .log("Blocked a self-assignment by a caller who is not an administrator");
    recordDenial(
        actor, targetUserId, role.getId(), role.getName(), DenialReason.SELF_ASSIGNMENT,
        OPERATION_ASSIGN, requestContext, null);
    throw new InsufficientPermissionException(USER_ROLE_ASSIGN, DenialReason.SELF_ASSIGNMENT);
  }

  /**
   * The administrator requirement of revoke-subset on an admin-defining role (ADR-0021 D5): the
   * caller must hold an admin-defining role according to the set lock's own rows. This is what
   * stops a union-holder, who passes the subset comparison, from stripping an administrator
   * (T-E34); it keeps {@code NOT_TENANT_ADMIN} as the reason (A-13).
   */
  private void requireAdministratorFromSetLock(
      RoleChangeActor actor,
      UUID targetUserId,
      Role role,
      SetLock setLock,
      RequestContext requestContext) {
    if (setLock.callerHoldsAdministratorRole(actor.userId())) {
      return;
    }
    recordThrottleDenialAndMaybeWarn(actor, OPERATION_REVOKE);
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_ADMINISTRATOR_REQUIRED_DENIED")
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_ROLE_ID, role.getId())
        .addKeyValue(LOG_KEY_OPERATION, OPERATION_REVOKE)
        .log("Blocked the revocation of an admin-defining role by a caller who is not an administrator");
    recordDenial(
        actor, targetUserId, role.getId(), role.getName(), DenialReason.NOT_TENANT_ADMIN,
        OPERATION_REVOKE, requestContext, null);
    throw new InsufficientPermissionException(USER_ROLE_ASSIGN, DenialReason.NOT_TENANT_ADMIN);
  }

  /**
   * Row 7 (RC-28.1, RC-50(b)): the independent check on a successful self-target assignment. One
   * non-locking statement over the caller's own active roles, grouped by role, that shares no input
   * with the snapshot read A4 used. When it disagrees with A4's verdict, ERROR {@code
   * RBAC_SELF_ASSIGN_ADMIN_DISAGREEMENT} (ids only) and the counter that pages. Never consulted for
   * authorization: the request has already been decided. A read failure propagates (fail closed).
   */
  private void captureIndependentAdministratorCheck(
      RoleChangeActor actor, Role role, boolean a4SaidAdministrator) {
    boolean independentlyAdministrator =
        !userRoleAssignmentPort.findHeldAdminDefiningRoleIds(actor.userId(), actor.tenantId())
            .isEmpty();
    if (independentlyAdministrator == a4SaidAdministrator) {
      return;
    }
    log.atError()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_SELF_ASSIGN_ADMIN_DISAGREEMENT")
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_ROLE_ID, role.getId())
        .log("A self-assignment passed A4 but the independent administrator check disagrees");
    Counter.builder(COUNTER_SELF_ASSIGN_ADMIN_DISAGREEMENT).register(meterRegistry).increment();
  }

  /**
   * US-018 07-security-review.md L-1: {@code @RequiresPermission} reads the JWT's {@code
   * permissions[]}, which can outlive a revoke for up to the token lifetime. This re-checks, from
   * the SAME fresh M13 rows A4/A2/revoke-subset use (no extra read), that the caller still holds
   * {@code user:role:assign} by its seeded id. Missing means deny: 403 {@code PERMISSION_ABSENT},
   * one denial row, a throttle denial, and a WARN carrying ids only. M7 (epoch freshness) remains
   * the systemic fix; this closes the window for these two verbs.
   */
  private void requireCallerStillHoldsUserRoleAssign(
      RoleChangeActor actor,
      UUID targetUserId,
      Role role,
      List<RolePermissionRef> heldRolePermissions,
      String operation,
      RequestContext requestContext) {
    boolean stillHeld =
        heldRolePermissions.stream()
            .anyMatch(ref -> RbacSeededPermissionIds.USER_ROLE_ASSIGN.equals(ref.permissionId()));
    if (stillHeld) {
      return;
    }
    recordThrottleDenialAndMaybeWarn(actor, operation);
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_ENDPOINT_PERMISSION_NOT_HELD")
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
        .addKeyValue(LOG_KEY_ROLE_ID, role.getId())
        .addKeyValue(LOG_KEY_OPERATION, operation)
        .log("Blocked a role change by a caller whose live holdings lack the endpoint permission");
    recordDenial(
        actor, targetUserId, role.getId(), role.getName(), DenialReason.PERMISSION_ABSENT,
        operation, requestContext, null);
    throw new InsufficientPermissionException(USER_ROLE_ASSIGN, DenialReason.PERMISSION_ABSENT);
  }

  /**
   * A2 (ADR-0021 D2, 03-design.md §4.3, §4.4), and on {@code revoke()} the union part of
   * revoke-subset: denies unless every permission of the target role (M14, already read by {@link
   * #classifyTarget}) is in the union of the caller's held permission ids (M13). Ids only, from the
   * one authorization read, never a JWT claim.
   *
   * <p>Fails closed: an empty M13 result denies any permissioned target. A target role with no
   * permissions passes (EC7): it grants nothing.
   *
   * <p>The 403's {@code requiredPermission} is the endpoint permission, and the denial row and WARN
   * carry only the COUNT of missing permissions, never their ids, so neither is an oracle on the
   * role's contents.
   */
  private void requireGrantWithinCallerHoldings(
      RoleChangeActor actor,
      UUID targetUserId,
      Role role,
      TargetClassification target,
      List<RolePermissionRef> heldRolePermissions,
      String operation,
      RequestContext requestContext) {
    Set<UUID> heldPermissionIds =
        heldRolePermissions.stream()
            .map(RolePermissionRef::permissionId)
            .collect(Collectors.toSet());
    int missingCount =
        (int)
            target.targetPermissionIds().stream()
                .filter(id -> !heldPermissionIds.contains(id))
                .count();
    if (missingCount == 0) {
      return;
    }
    recordThrottleDenialAndMaybeWarn(actor, operation);
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_GRANT_EXCEEDS_CALLER")
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
        .addKeyValue(LOG_KEY_ROLE_ID, role.getId())
        .addKeyValue(LOG_KEY_OPERATION, operation)
        .addKeyValue(LOG_KEY_MISSING_COUNT, missingCount)
        .log("Blocked a role change involving permissions the caller does not hold");
    recordDenial(
        actor, targetUserId, role.getId(), role.getName(), DenialReason.GRANT_EXCEEDS_CALLER,
        operation, requestContext, missingCount);
    throw new InsufficientPermissionException(
        USER_ROLE_ASSIGN, DenialReason.GRANT_EXCEEDS_CALLER);
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
   * Not to be confused with {@link RoleChangeThrottlePort#recordDenial}, which books a denial
   * against the D14 throttle window -- unrelated bookkeeping that happens to share this name.
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
      String operation,
      RequestContext requestContext,
      Integer missingCount) {
    try {
      RbacAuditEvent event =
          new RbacAuditEvent(
              actor.tenantId(), targetUserId, roleId, roleName, actor.userId(), requestContext);
      if (missingCount == null) {
        rbacAuditPort.recordRoleAssignmentDenied(event, reason, operation);
      } else {
        rbacAuditPort.recordRoleAssignmentDenied(event, reason, operation, missingCount);
      }
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
