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
import com.example.nexus.rbac.domain.ActiveAssignmentRef;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.LastAdminRoleException;
import com.example.nexus.rbac.domain.RbacDangerousPermissions;
import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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

  private static final String OPERATION_ASSIGN = "assign";
  private static final String OPERATION_REVOKE = "revoke";

  private static final String MATCHED_ON_ROLE_NAME = "ROLE_NAME";
  private static final String MATCHED_ON_DANGEROUS_PERMISSION = "DANGEROUS_PERMISSION";

  private static final String TIMER_PRIVILEGED_REVOKE_LOCK_HOLD =
      "nexus.rbac.privileged_revoke_lock_hold";
  private static final String TAG_OUTCOME = "outcome";
  private static final String OUTCOME_DENIED = "denied";
  private static final String OUTCOME_LOCKOUT = "lockout";
  private static final String OUTCOME_REVOKED = "revoked";
  private static final String OUTCOME_ERROR = "error";

  private static final String LOG_KEY_EVENT = "event";
  private static final String LOG_KEY_TENANT_ID = "tenantId";
  private static final String LOG_KEY_TARGET_USER_ID = "targetUserId";
  private static final String LOG_KEY_ACTOR_USER_ID = "actorUserId";
  private static final String LOG_KEY_ROLE_ID = "roleId";
  private static final String LOG_KEY_ROLE_NAME = "roleName";
  private static final String LOG_KEY_OPERATION = "operation";
  private static final String LOG_KEY_MATCHED_ON = "matchedOn";
  private static final String LOG_KEY_MAX_DENIALS = "maxDenials";
  private static final String LOG_KEY_WINDOW_SECONDS = "windowSeconds";

  private static final String COUNTER_DENIAL_THROTTLED = "nexus.rbac.denial_throttled";

  private final UserRoleAssignmentPort userRoleAssignmentPort;
  private final UserDirectoryPort userDirectoryPort;
  private final RbacAuditPort rbacAuditPort;
  private final PermissionCachePort permissionCachePort;
  private final MeterRegistry meterRegistry;
  private final RoleChangeThrottlePort throttlePort;
  private final int maxDenials;
  private final int windowSeconds;

  public RoleAssignmentService(
      UserRoleAssignmentPort userRoleAssignmentPort,
      UserDirectoryPort userDirectoryPort,
      RbacAuditPort rbacAuditPort,
      PermissionCachePort permissionCachePort,
      MeterRegistry meterRegistry,
      RoleChangeThrottlePort throttlePort,
      @Value("${nexus.rbac.denial-throttle.max-denials}") int maxDenials,
      @Value("${nexus.rbac.denial-throttle.window-seconds}") int windowSeconds) {
    this.userRoleAssignmentPort = userRoleAssignmentPort;
    this.userDirectoryPort = userDirectoryPort;
    this.rbacAuditPort = rbacAuditPort;
    this.permissionCachePort = permissionCachePort;
    this.meterRegistry = meterRegistry;
    this.throttlePort = throttlePort;
    this.maxDenials = maxDenials;
    this.windowSeconds = windowSeconds;
  }

  /**
   * Grants {@code roleId} to {@code targetUserId} within the actor's own tenant (AC1, AC4, AC6,
   * AC7, AC8). Returns the created assignment, including its DB-generated {@code assignedAt}.
   *
   * <p><b>Security note (M-3 / T-E9 — CLOSED by US-016; RES-1 PARTIALLY closed).</b> This gate is
   * privilege-based, not name-based: it denies granting <em>and</em> revoking any role that is
   * literally named {@code TENANT_ADMIN} <b>or</b> carries any {@code RbacDangerousPermissions}
   * member, unless the caller holds an active {@code TENANT_ADMIN} assignment in this tenant,
   * verified by a fresh locking read (never a JWT claim — T-E7).
   *
   * <p><b>Closed:</b> T-E9 (no symmetric admin check on {@link #revoke}); T-E17 (administrator
   * stripping); T-E16 <b>for the direct propagate path only</b> (a non-admin can no longer assign
   * a role that is dangerous <em>at assign time</em>).
   *
   * <p><b>NOT closed, deliberately:</b> the attach-after-assign path — a non-admin may self-assign
   * a benign role, which an administrator may later make dangerous via {@code
   * RoleManagementService.attachPermission}; no gate evaluates at that moment. Carried forward as
   * <b>US-016 T-E21 / RES-1(b)</b> ({@code docs/features/US-016/03b-threat-model.md} §3, §5).
   * Mitigated, not closed, by the mint-side holder-count signal in {@code
   * RoleManagementService.attachPermission} (US-016 D13) — do not delete that signal without
   * re-opening this note.
   *
   * <p>Also surviving: AC5's last-admin lockout still protects only the literally-named {@code
   * TENANT_ADMIN} (RES-3), and the <b>caller</b>-side admin test remains name-based (RES-9).
   *
   * <p>See {@code docs/features/US-016/03-design.md} and ADR-0017.
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
      recordDenial(actor, targetUserId, roleId, null, e.getReason(), OPERATION_ASSIGN, requestContext);
      throw e;
    }

    requireNotThrottled(actor, OPERATION_ASSIGN, requestContext);

    // D4: one unified, privilege-based gate (FR-1, FR-3), name-first so the pre-existing
    // name-match behaviour never depends on the new dangerous-permission read.
    boolean nameMatch = isNamedTenantAdmin(role);
    boolean privileged = nameMatch || carriesDangerousPermission(role.getId());
    if (privileged) {
      requireActiveTenantAdmin(
          actor, targetUserId, role, USER_WRITE, OPERATION_ASSIGN, nameMatch, requestContext);
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

          // RC-7 (T-005, 03-design.md §9.2/§10.2): unconditional exploitation-side detection
          // signal for the M-3/T-E16 propagate-side escalation chain. Deliberately no new
          // query and no dangerous-permission lookup -- actorUserId and targetUserId are
          // already in hand at this point on every successful assignment. The severity
          // distinction (whether the assigned role is actually dangerous) is made at alert
          // time by composing this counter with nexus.rbac.dangerous_permission_granted, not
          // here.
          if (targetUserId.equals(actor.userId())) {
            // D7 + D15 (§9.2), fixed per 07-security-review.md M-2 (RC-11.2's canary had no
            // reachable firing path): callerIsAdmin must come from a SECOND, INDEPENDENT
            // source, not from `privileged` (the gate's own control-flow variable) -- deriving
            // it from control flow made "false" definitionally unreachable, since reaching this
            // line already proves requireActiveTenantAdmin's M5 locking read returned true.
            // callerHoldsActiveTenantAdmin(actor) answers the same question via a deliberately
            // different mechanism (a non-locking M4 projection over role names, keyed off the
            // caller's own assignments) than M5 (a locking read keyed off an M8-resolved role
            // id). A future T-E22-class bug that makes M5 answer the wrong question and still
            // let the gate pass now surfaces as a disagreement between the two -- observable --
            // instead of being tautologically "true". "n_a" is kept when the gate never ran
            // (privileged=false), so the extra read only happens on this self-assignment path.
            boolean callerIsAdmin = privileged && callerHoldsActiveTenantAdmin(actor);
            Counter.builder("nexus.rbac.self_role_assignment")
                .tag("tenantId", actor.tenantId().toString())
                .tag("privileged", Boolean.toString(privileged))
                .tag("callerIsAdmin", privileged ? Boolean.toString(callerIsAdmin) : "n_a")
                .register(meterRegistry)
                .increment();
            log.atWarn()
                .addKeyValue(LOG_KEY_EVENT, "RBAC_SELF_ROLE_ASSIGNMENT")
                .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
                .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
                .addKeyValue(LOG_KEY_ROLE_ID, roleId)
                .log("Actor assigned a role to themselves");
          }
        });

    return assignment;
  }

  /**
   * Revokes {@code roleId} from {@code targetUserId} within the actor's own tenant (AC2, AC4,
   * AC5, AC6, AC7).
   *
   * <p><b>Security note (M-3 / T-E9 — CLOSED by US-016; RES-1 PARTIALLY closed).</b> This gate is
   * privilege-based, not name-based: it denies granting <em>and</em> revoking any role that is
   * literally named {@code TENANT_ADMIN} <b>or</b> carries any {@code RbacDangerousPermissions}
   * member, unless the caller holds an active {@code TENANT_ADMIN} assignment in this tenant,
   * verified by a fresh locking read (never a JWT claim — T-E7).
   *
   * <p><b>Closed:</b> T-E9 (no symmetric admin check on {@code revoke()}); T-E17 (administrator
   * stripping); T-E16 <b>for the direct propagate path only</b> (a non-admin can no longer assign
   * a role that is dangerous <em>at assign time</em>).
   *
   * <p><b>NOT closed, deliberately:</b> the attach-after-assign path — a non-admin may self-assign
   * a benign role, which an administrator may later make dangerous via {@code
   * RoleManagementService.attachPermission}; no gate evaluates at that moment. Carried forward as
   * <b>US-016 T-E21 / RES-1(b)</b> ({@code docs/features/US-016/03b-threat-model.md} §3, §5).
   * Mitigated, not closed, by the mint-side holder-count signal in {@code
   * RoleManagementService.attachPermission} (US-016 D13) — do not delete that signal without
   * re-opening this note.
   *
   * <p>Also surviving: AC5's last-admin lockout still protects only the literally-named {@code
   * TENANT_ADMIN} (RES-3), and the <b>caller</b>-side admin test remains name-based (RES-9).
   *
   * <p>See {@code docs/features/US-016/03-design.md} and ADR-0017.
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
      recordDenial(actor, targetUserId, roleId, null, e.getReason(), OPERATION_REVOKE, requestContext);
      throw e;
    }

    // Resolved once, ahead of the admin-lockout check: this covers "never assigned" and
    // "already revoked" identically for both admin and non-admin roles, and its id is what
    // the lockout check below needs to test set-membership against.
    ActiveAssignmentRef ref = findAssignmentRefOrThrow(targetUserId, roleId, actor.tenantId());

    requireNotThrottled(actor, OPERATION_REVOKE, requestContext);

    // T-009 / D4: the same unified, privilege-based gate as assign() (D2/§7.2: M7 runs before
    // M1, outside the locked region, on every path -- name-first short-circuit means M7 is
    // never evaluated when nameMatch is true).
    boolean nameMatch = isNamedTenantAdmin(role);
    boolean privileged = nameMatch || carriesDangerousPermission(role.getId());

    // D2, pinned lock order: the X set lock (M1) is acquired FIRST, before the gate's S read
    // (M5), whenever the AC5 lockout could apply. This is a lock-ordering step, not a check --
    // no decision is taken here (§7.2).
    List<UUID> lockedActiveAdminIds =
        nameMatch
            ? userRoleAssignmentPort.lockActiveAssignmentIds(actor.tenantId(), role.getId())
            : List.of();
    // D18: the composed lock-hold timer only participates on the nameMatch path -- M1 is the
    // only lock this story adds to revoke(), and it never runs on the dangerous-custom-role
    // (non-name-match) path (§7.5).
    Timer.Sample lockHoldSample = nameMatch ? Timer.start(meterRegistry) : null;

    try {
      if (privileged) {
        requireActiveTenantAdmin(
            actor, targetUserId, role, USER_WRITE, OPERATION_REVOKE, nameMatch, requestContext);
      }

      // AC5, actor-agnostic: fires for ANY caller revoking the tenant's last active
      // TENANT_ADMIN assignment, not only self-revocation. D1: always evaluated AFTER the
      // privilege gate above, so a non-admin caller sees 403 before this 409 can ever fire.
      if (nameMatch && lockedActiveAdminIds.size() <= 1 && lockedActiveAdminIds.contains(ref.id())) {
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
            // D18/§7.5: stopped here, not right after registration -- this runnable only
            // executes from afterCommit(), which Spring invokes strictly after doCommit()
            // returns, so this is the true "at commit" point the timer is meant to measure.
            // Stopping it immediately after registerPostCommitSideEffects() returns would
            // measure only up to the register call, missing the COMMIT round-trip itself --
            // exactly the interval this instrument exists to catch (RC-9.5).
            stopLockHoldTimer(lockHoldSample, OUTCOME_REVOKED);
          });
    } catch (InsufficientPermissionException e) {
      stopLockHoldTimer(lockHoldSample, OUTCOME_DENIED);
      throw e;
    } catch (LastAdminRoleException e) {
      stopLockHoldTimer(lockHoldSample, OUTCOME_LOCKOUT);
      throw e;
    } catch (RuntimeException e) {
      // Covers both the M6 lost-race 404 (assignmentNotFound()) and any unexpected propagating
      // failure from M8/M5/the audit write -- neither is an authorization decision nor a
      // successful revoke by this transaction, so both are bucketed under the bounded, 4-value
      // outcome set (D18 fixes the cardinality at {denied, lockout, revoked, error}).
      stopLockHoldTimer(lockHoldSample, OUTCOME_ERROR);
      throw e;
    }
  }

  /**
   * D18: stops the composed X-lock-hold timer with the given {@code outcome} tag. A no-op when
   * {@code sample} is {@code null} -- the timer only ever starts on the {@code nameMatch} path
   * (M1 is the only lock this story adds to {@link #revoke}), so a dangerous-custom-role
   * (non-name-match) revocation never participates in this timer (03-design.md §7.5).
   */
  private void stopLockHoldTimer(Timer.Sample sample, String outcome) {
    if (sample == null) {
      return;
    }
    sample.stop(
        Timer.builder(TIMER_PRIVILEGED_REVOKE_LOCK_HOLD)
            .tag(TAG_OUTCOME, outcome)
            .register(meterRegistry));
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

  /** FR-3's half of the unified gate condition (D4) — the source of {@code matchedOn}. */
  private static boolean isNamedTenantAdmin(Role role) {
    return RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(role.getName());
  }

  /**
   * FR-1's half of the unified gate condition (D4). Non-locking (D5, MC-1): calls M7 and streams
   * over {@link RbacDangerousPermissions#contains}, never the reverse — the dangerous-permission
   * set never crosses {@link UserRoleAssignmentPort} in either direction. An empty permission set
   * means NOT privileged (Edge Case 1).
   */
  private boolean carriesDangerousPermission(UUID roleId) {
    return userRoleAssignmentPort.findPermissionNamesForRole(roleId).stream()
        .anyMatch(RbacDangerousPermissions::contains);
  }

  /**
   * D14 (03-design.md §4.8, §6.1): check 3.5 — after the 404s, before M1/M7/M8/M5, the audit
   * write, and the metric. Bounds the cost of repeated authorization denials on {@code
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
    throw new InsufficientPermissionException(USER_WRITE, DenialReason.NOT_TENANT_ADMIN);
  }

  /**
   * D14 / A-3: records this denial against the throttle and, when it is the transition into the
   * throttled state, emits the one-time WARN {@code RBAC_DENIAL_THROTTLE_ENGAGED}. Defense in
   * depth: a throwing {@link RoleChangeThrottlePort} must never prevent the real {@link
   * InsufficientPermissionException} from being thrown at this method's call site (the gate's own
   * throw in {@link #requireActiveTenantAdmin}).
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
   * The ONE call site of {@link UserRoleAssignmentPort#hasActiveAdminAssignment} on the privilege
   * gate (D4). {@code void}, not {@code boolean}, deliberately: a caller cannot ignore a thrown
   * exception the way it can ignore an unchecked boolean return value.
   *
   * <p>{@code adminRoleId} (M8) and {@code actor.userId()} — <b>never</b> {@code role.getId()} and
   * <b>never</b> {@code targetUserId} — are the two arguments {@link
   * UserRoleAssignmentPort#hasActiveAdminAssignment} is called with (MC-3, RC-14): passing the
   * target role asks "does the caller hold the custom role?" (true the moment an attacker holds it
   * once); passing the target user asks "is the target an admin?" (fails open on {@code revoke()}
   * against the highest-value targets in the tenant). Both compile; both fail open; MC-3 pins both.
   *
   * <p>M8 empty ⇒ deny, fail closed, WITHOUT calling M5 (R-10/T-E18) — a legitimately un-seeded
   * tenant on the privilege path, or a data-consistency bug on the name-match path (impossible
   * otherwise, since the resolved role IS named {@code TENANT_ADMIN} there).
   */
  private void requireActiveTenantAdmin(
      RoleChangeActor actor,
      UUID targetUserId,
      Role role,
      String requiredPermission,
      String operation,
      boolean nameMatch,
      RequestContext requestContext) {
    Optional<UUID> adminRoleId =
        userRoleAssignmentPort.findRoleIdByName(actor.tenantId(), RbacRoleNames.TENANT_ADMIN);
    boolean callerIsActiveAdmin =
        adminRoleId.isPresent()
            && userRoleAssignmentPort.hasActiveAdminAssignment(
                actor.userId(), adminRoleId.get(), actor.tenantId());
    if (callerIsActiveAdmin) {
      return;
    }
    String matchedOn = nameMatch ? MATCHED_ON_ROLE_NAME : MATCHED_ON_DANGEROUS_PERMISSION;
    recordThrottleDenialAndMaybeWarn(actor, operation);
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED")
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_ROLE_ID, role.getId())
        .addKeyValue(LOG_KEY_ROLE_NAME, role.getName())
        .addKeyValue(LOG_KEY_OPERATION, operation)
        .addKeyValue(LOG_KEY_MATCHED_ON, matchedOn)
        .log("Blocked privileged role change by a non-admin caller");
    Counter.builder("nexus.rbac.privileged_role_change_blocked")
        .tag("operation", operation)
        .tag("matchedOn", matchedOn)
        .register(meterRegistry)
        .increment();
    recordDenial(
        actor, targetUserId, role.getId(), role.getName(), DenialReason.NOT_TENANT_ADMIN,
        operation, requestContext);
    throw new InsufficientPermissionException(requiredPermission, DenialReason.NOT_TENANT_ADMIN);
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
      RequestContext requestContext) {
    try {
      rbacAuditPort.recordRoleAssignmentDenied(
          new RbacAuditEvent(
              actor.tenantId(), targetUserId, roleId, roleName, actor.userId(), requestContext),
          reason,
          operation);
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
