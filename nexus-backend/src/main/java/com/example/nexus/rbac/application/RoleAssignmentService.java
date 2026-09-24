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
import com.example.nexus.rbac.domain.RbacAdminEquivalence;
import com.example.nexus.rbac.domain.RbacDangerousPermissions;
import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermissionName;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashSet;
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
  private static final String MATCHED_ON_ALL_DANGEROUS_PERMISSIONS = "ALL_DANGEROUS_PERMISSIONS";

  private static final String TIMER_PRIVILEGED_REVOKE_LOCK_HOLD =
      "nexus.rbac.privileged_revoke_lock_hold";
  private static final String TAG_OUTCOME = "outcome";
  private static final String OUTCOME_DENIED = "denied";
  private static final String OUTCOME_LOCKOUT = "lockout";
  private static final String OUTCOME_REVOKED = "revoked";
  private static final String OUTCOME_ASSIGNED = "assigned";
  private static final String OUTCOME_CONFLICT = "conflict";
  private static final String OUTCOME_ERROR = "error";

  private static final String COUNTER_PRIVILEGED_ROLE_CHANGE_ALLOWED =
      "nexus.rbac.privileged_role_change_allowed";
  private static final String TAG_CALLER_MATCHED_ON = "callerMatchedOn";
  private static final String COUNTER_ADMIN_MINTED_BY_NON_NAMED_ADMIN =
      "nexus.rbac.admin_minted_by_non_named_admin";
  private static final String TAG_SELF_TARGET = "selfTarget";
  private static final String METRIC_ADMIN_EQUIVALENT_LOCK_SET_SIZE =
      "nexus.rbac.admin_equivalent_lock_set_size";

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
  private static final String COUNTER_LAST_ADMIN_LOCKOUT_BLOCKED =
      "nexus.rbac.last_admin_lockout_blocked";

  /**
   * D6 (US-017, M11's port Javadoc): the total order M11's deterministic acquisition proof rests
   * on. "Ascending" means unsigned byte-wise order of the 16-byte UUID representation, matching
   * MySQL's {@code BINARY(16)} comparison — NEVER {@link UUID#compareTo}, which compares {@code
   * mostSigBits} as a SIGNED {@code long} and would silently diverge from the database's own order
   * for an id whose high bit is set (MC-E).
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
   * <p><b>Closed by US-017:</b> RES-3 — the last-admin lockout now protects the tenant-wide set
   * of <b>distinct holders</b> of <b>any</b> admin-equivalent role (literal {@code TENANT_ADMIN}
   * or any {@code RbacDangerousPermissions} member), and {@code
   * RbacZeroActiveAdminsHealthIndicator} detects the same population. RES-9 — the
   * <b>caller</b>-side admin test is privilege-based, using a deliberately <b>narrower</b>
   * predicate than the target-side one: literal {@code TENANT_ADMIN} <b>or all three</b>
   * dangerous permissions ({@code RbacAdminEquivalence#isFullyAdminEquivalent}). <b>Do not
   * "simplify" the caller-side test to the target-side ANY predicate: it is vacuous, because
   * every caller who reaches this code holds {@code user:write}, which is itself in the
   * dangerous set</b> (ADR-0018 D2).
   *
   * <p><b>Relocated, not closed — and NOT a containment:</b> the <em>mint</em>-side AC11 caller
   * test on {@code RoleManagementService.attachPermission}/{@code detachPermission} remains
   * name-based (US-017 RES-13). It is narrower <b>by construction</b>, but it bounds nothing: a
   * fully admin-equivalent caller may self-assign the literal {@code TENANT_ADMIN} in a
   * <b>single request</b> and is thereafter a mint-side administrator. Do not read this
   * asymmetry as a control to preserve.
   *
   * <p><b>Amplified, not closed — read this before assuming the surviving escalation path is
   * unaffected:</b> US-016 <b>RES-1(b) / T-E21</b>, the attach-after-assign pre-positioning path,
   * is <b>not</b> closed here and this change <b>increases its payoff</b>. A {@code user:write}
   * holder who self-assigned a benign custom role is silently escalated when an administrator
   * later attaches dangerous permissions to it. Before US-017 that yielded admin-equivalent
   * <em>permissions</em>, effective at the next token mint and insufficient to pass this gate.
   * <b>After US-017 it yields caller-side administrative capability, effective on the next
   * request from a live DB read, and the literal {@code TENANT_ADMIN} one self-assignment
   * later.</b> Likelihood unchanged; impact materially increased. Detection, not prevention:
   * {@code RBAC_ROLE_BECAME_FULLY_ADMIN_EQUIVALENT} (US-017 D22) reports the moment a role
   * crosses the threshold.
   *
   * <p>See {@code docs/features/US-017/03-design.md} and ADR-0018.
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
    boolean privileged =
        nameMatch
            || RbacAdminEquivalence.isAdminEquivalent(
                role.getName(), userRoleAssignmentPort.findPermissionNamesForRole(role.getId()));

    // US-017 D7/RES-10 fix, §7.2/§7.3: acquire the SAME M11 union lock FIRST -- before M5b,
    // before M2's duplicate check, before the INSERT -- exactly mirroring revoke()'s order, so
    // the acquisition order is now total across both verbs. The benign path costs +0: no M10,
    // no M8, no M11 (unchanged property).
    AdminEquivalentRoles roles;
    Timer.Sample lockHoldSample;
    if (privileged) {
      roles = resolveAdminEquivalentRoles(actor.tenantId(), role, nameMatch);
      List<UUID> lockSet = buildAscendingAdminEquivalentLockSet(roles, role.getId());
      List<ActiveAssignmentHolder> lockedHolders =
          userRoleAssignmentPort.lockActiveAssignmentHolders(actor.tenantId(), lockSet);
      recordLockSetSize(lockedHolders.size());
      lockHoldSample = Timer.start(meterRegistry);
    } else {
      roles = null;
      lockHoldSample = null;
    }

    try {
      if (privileged) {
        // FR-3/D8: the SAME caller gate as revoke() (M5b over the caller-qualifying set,
        // contained inside the X region M11 just acquired) -- 403 before 409, position unchanged.
        requireCallerHoldsAdminEquivalentRole(
            actor, targetUserId, role, USER_WRITE, OPERATION_ASSIGN, nameMatch, roles,
            requestContext);
      }

      // 07-security-review.md M-1 (2026-09-24): the canary's M12-based caller-status read MUST
      // run BEFORE the INSERT below, never after. Reading it post-commit (as originally shipped)
      // meant that on a self-assignment of a role that is ITSELF fully admin-equivalent, the read
      // would see the row this very request is about to create, making callerIsAdmin=true
      // unconditionally reachable and callerIsAdmin=false structurally UNREACHABLE for exactly
      // the highest-severity target (TENANT_ADMIN or an ALL-three role) -- the one case this
      // canary most needs to catch a gate bypass for. Computed only on the one path where it is
      // ever used (a privileged self-assignment); MC-G is undisturbed, since this result is never
      // used to authorize anything -- the gate above has already decided -- only to compute this
      // already-decided request's canary signal from the caller's PRE-request state.
      boolean callerWasAdminBeforeThisAssignment =
          privileged
              && targetUserId.equals(actor.userId())
              && callerHoldsActiveAdminEquivalentRole(actor);

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
            // D18/§7.5: stopped from afterCommit(), the true "at commit" point -- same rationale
            // as revoke()'s stop site.
            stopLockHoldTimer(lockHoldSample, OPERATION_ASSIGN, OUTCOME_ASSIGNED);

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
              // it from control flow made "false" definitionally unreachable, since reaching
              // this line already proves requireCallerHoldsAdminEquivalentRole's M5b locking
              // read returned true. callerHoldsActiveAdminEquivalentRole(actor) answers the
              // same question via a deliberately different mechanism AND a deliberately
              // different data source (US-017 D24/RC-17.1): M12, a non-locking, USER-scoped
              // read driven off fk_user_roles_user -- never M10, the gate's own tenant-scoped
              // read, so an over-broad M10 can no longer silence this detector (§9.3). A future
              // T-E22-class bug that makes M5b answer the wrong question and still let the gate
              // pass now surfaces as a disagreement between the two -- observable -- instead of
              // being tautologically "true".
              //
              // M-1 fix (07-security-review.md, 2026-09-24): the read itself must happen BEFORE
              // the INSERT, not here (post-commit) -- see callerWasAdminBeforeThisAssignment's own
              // comment above the INSERT. Re-using that pre-computed value, not re-reading here,
              // is what stops this from silently reverting to the post-commit (bugged) read.
              boolean callerIsAdmin = callerWasAdminBeforeThisAssignment;
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
   * <p><b>Closed by US-017:</b> RES-3 — the last-admin lockout now protects the tenant-wide set
   * of <b>distinct holders</b> of <b>any</b> admin-equivalent role (literal {@code TENANT_ADMIN}
   * or any {@code RbacDangerousPermissions} member), and {@code
   * RbacZeroActiveAdminsHealthIndicator} detects the same population. RES-9 — the
   * <b>caller</b>-side admin test is privilege-based, using a deliberately <b>narrower</b>
   * predicate than the target-side one: literal {@code TENANT_ADMIN} <b>or all three</b>
   * dangerous permissions ({@code RbacAdminEquivalence#isFullyAdminEquivalent}). <b>Do not
   * "simplify" the caller-side test to the target-side ANY predicate: it is vacuous, because
   * every caller who reaches this code holds {@code user:write}, which is itself in the
   * dangerous set</b> (ADR-0018 D2).
   *
   * <p><b>Relocated, not closed — and NOT a containment:</b> the <em>mint</em>-side AC11 caller
   * test on {@code RoleManagementService.attachPermission}/{@code detachPermission} remains
   * name-based (US-017 RES-13). It is narrower <b>by construction</b>, but it bounds nothing: a
   * fully admin-equivalent caller may self-assign the literal {@code TENANT_ADMIN} in a
   * <b>single request</b> and is thereafter a mint-side administrator. Do not read this
   * asymmetry as a control to preserve.
   *
   * <p><b>Amplified, not closed — read this before assuming the surviving escalation path is
   * unaffected:</b> US-016 <b>RES-1(b) / T-E21</b>, the attach-after-assign pre-positioning path,
   * is <b>not</b> closed here and this change <b>increases its payoff</b>. A {@code user:write}
   * holder who self-assigned a benign custom role is silently escalated when an administrator
   * later attaches dangerous permissions to it. Before US-017 that yielded admin-equivalent
   * <em>permissions</em>, effective at the next token mint and insufficient to pass this gate.
   * <b>After US-017 it yields caller-side administrative capability, effective on the next
   * request from a live DB read, and the literal {@code TENANT_ADMIN} one self-assignment
   * later.</b> Likelihood unchanged; impact materially increased. Detection, not prevention:
   * {@code RBAC_ROLE_BECAME_FULLY_ADMIN_EQUIVALENT} (US-017 D22) reports the moment a role
   * crosses the threshold.
   *
   * <p>See {@code docs/features/US-017/03-design.md} and ADR-0018.
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

    // D4/D5: the same unified, privilege-based gate condition as assign() (§7.2: M7 runs
    // before M10/M11, outside the locked region, on every path -- name-first short-circuit
    // means M7 is never evaluated when nameMatch is true).
    boolean nameMatch = isNamedTenantAdmin(role);
    boolean privileged =
        nameMatch
            || RbacAdminEquivalence.isAdminEquivalent(
                role.getName(), userRoleAssignmentPort.findPermissionNamesForRole(role.getId()));

    // D5/D6/§7.2: on the privileged path (name-match OR dangerous-permission, never
    // conditioned on nameMatch alone any more), resolve the tenant's admin-equivalent role
    // sets from ONE M10 read plus M8, build the ascending-sorted union lock set, and acquire
    // it (M11) BEFORE the caller gate (M5b) below. The benign path costs +0: no M10, no M8,
    // no M11 -- "one condition, one call site" is preserved (§7.2).
    List<UUID> lockSet;
    List<ActiveAssignmentHolder> lockedHolders;
    AdminEquivalentRoles roles;
    Timer.Sample lockHoldSample;
    if (privileged) {
      roles = resolveAdminEquivalentRoles(actor.tenantId(), role, nameMatch);
      lockSet = buildAscendingAdminEquivalentLockSet(roles, role.getId());
      lockedHolders = userRoleAssignmentPort.lockActiveAssignmentHolders(actor.tenantId(), lockSet);
      recordLockSetSize(lockedHolders.size());
      // D18/US-017 §9.5: the timer's population widens from `nameMatch` to `privileged` --
      // M11 is now acquired for every privileged revocation, not only the literally-named
      // TENANT_ADMIN (the "dangerous-custom-role revocation never participates" caveat no
      // longer holds).
      lockHoldSample = Timer.start(meterRegistry);
    } else {
      roles = null;
      lockSet = List.of();
      lockedHolders = List.of();
      lockHoldSample = null;
    }

    try {
      if (privileged) {
        // FR-3/D8: the caller gate is now M5b over the caller-qualifying set (ALL ⊆ ANY ⊆
        // lockSet), contained inside the X region M11 just acquired -- 403 before 409,
        // position unchanged (Gate 1 Resolution 2).
        requireCallerHoldsAdminEquivalentRole(
            actor, targetUserId, role, USER_WRITE, OPERATION_REVOKE, nameMatch, roles,
            requestContext);
      }

      // D5, AC5 widened: fires for ANY caller revoking the tenant's last DISTINCT HOLDER able
      // to pass the caller gate (H-1, 2026-09-24: caller-qualifying, not merely ANY
      // admin-equivalent), not only self-revocation and not only literally-named TENANT_ADMIN.
      // Always evaluated AFTER the privilege gate above, so a non-admin caller sees 403 before
      // this 409 can ever fire.
      if (privileged
          && wouldLeaveTenantWithoutCallerQualifyingHolder(
              lockedHolders, ref.id(), roles.callerQualifyingIds())) {
        String matchedOn = nameMatch ? MATCHED_ON_ROLE_NAME : MATCHED_ON_DANGEROUS_PERMISSION;
        // WARN, not DEBUG: an operator needs to know which tenant nearly locked itself out
        // and who tried, independent of the nexus.domain.conflict{code="RBAC_002"} counter.
        log.atWarn()
            .addKeyValue(LOG_KEY_EVENT, "RBAC_LAST_ADMIN_REVOCATION_BLOCKED")
            .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
            .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
            .addKeyValue("actorUserId", actor.userId())
            .addKeyValue(LOG_KEY_ROLE_ID, roleId)
            .addKeyValue(LOG_KEY_MATCHED_ON, matchedOn)
            .addKeyValue("adminEquivalentRoleCount", lockSet.size())
            .addKeyValue("lockedRowCount", lockedHolders.size())
            .log("Blocked revocation of the tenant's last active admin-equivalent role assignment");
        Counter.builder(COUNTER_LAST_ADMIN_LOCKOUT_BLOCKED)
            .tag(LOG_KEY_MATCHED_ON, matchedOn)
            .register(meterRegistry)
            .increment();
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
            stopLockHoldTimer(lockHoldSample, OPERATION_REVOKE, OUTCOME_REVOKED);
          });
    } catch (InsufficientPermissionException e) {
      stopLockHoldTimer(lockHoldSample, OPERATION_REVOKE, OUTCOME_DENIED);
      throw e;
    } catch (LastAdminRoleException e) {
      stopLockHoldTimer(lockHoldSample, OPERATION_REVOKE, OUTCOME_LOCKOUT);
      throw e;
    } catch (RuntimeException e) {
      // Covers both the M6 lost-race 404 (assignmentNotFound()) and any unexpected propagating
      // failure from M8/M5/the audit write -- neither is an authorization decision nor a
      // successful revoke by this transaction, so both are bucketed under the bounded, 4-value
      // outcome set (D18 fixes the cardinality at {denied, lockout, revoked, error}).
      stopLockHoldTimer(lockHoldSample, OPERATION_REVOKE, OUTCOME_ERROR);
      throw e;
    }
  }

  /**
   * D18: stops the composed X-lock-hold timer with the given {@code operation}/{@code outcome}
   * tags. A no-op when {@code sample} is {@code null} -- the timer only ever starts on the {@code
   * privileged} path (US-017 D5/D6/§7.2 widens the timer's population from {@code nameMatch} to
   * every privileged role change, since M11 is now acquired whenever {@code privileged} is true,
   * not only for the literally-named {@code TENANT_ADMIN}), so a benign (non-privileged) role
   * change never participates in this timer.
   *
   * <p>US-017 D7/§9.2: {@code operation} ({@code assign}/{@code revoke}) is a new tag -- {@code
   * assign()} now holds the same lock, so the metric name is historical (it predates {@code
   * assign()} participating) but is kept rather than churning the shipped alert for no benefit.
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
   * US-017 RES-17/RC-20.4 (A-2): records the size of the list M11 just returned. Untagged (1
   * series) and recorded on BOTH verbs, immediately after M11 executes -- restricting it to
   * {@code revoke()} would halve the sample the soak-derived p99 threshold (design §10.3 step 2)
   * is computed from, since {@code assign()}'s privileged path now acquires M11 too (D7).
   */
  private void recordLockSetSize(int size) {
    DistributionSummary.builder(METRIC_ADMIN_EQUIVALENT_LOCK_SET_SIZE)
        .register(meterRegistry)
        .record(size);
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
   * A small carrier for the tenant's admin-equivalence sets (US-017 D3/D9, §4.2), returned
   * together so the two id sets can never be built from two different M10 reads.
   */
  record AdminEquivalentRoles(
      Set<UUID> adminEquivalentIds, Set<UUID> fullyAdminEquivalentIds, Optional<UUID> namedAdminRoleId) {

    /**
     * The tenant's CALLER-QUALIFYING role ids (post-06-code-review.md H-1, 2026-09-24) — literal
     * {@code TENANT_ADMIN} (when seeded) UNION every role carrying ALL THREE dangerous
     * permissions. The SAME population {@link
     * RoleAssignmentService#requireCallerHoldsAdminEquivalentRole} admits, deliberately narrower
     * than {@link #adminEquivalentIds()} (ANY) — see {@link
     * RoleAssignmentService#wouldLeaveTenantWithoutCallerQualifyingHolder}.
     */
    Set<UUID> callerQualifyingIds() {
      Set<UUID> ids = new HashSet<>(fullyAdminEquivalentIds);
      namedAdminRoleId.ifPresent(ids::add);
      return ids;
    }
  }

  /**
   * Resolves the tenant's two admin-equivalence role-id sets from ONE M10 read plus M8 (US-017
   * D3, D9, §7.2) — never two separate reads that could disagree with each other. {@code
   * targetRole} and {@code nameMatch} are accepted per the approved signature (03-design.md §4.2)
   * for the lock-set construction its callers (T-002/T-003) build around this result.
   *
   * <p>Wired up by {@code revoke()} (US-017 T-002); {@code assign()} (T-003) is still pending.
   */
  private AdminEquivalentRoles resolveAdminEquivalentRoles(
      UUID tenantId, Role targetRole, boolean nameMatch) {
    List<RolePermissionName> tenantRolePermissions =
        userRoleAssignmentPort.findPermissionNamesForTenantRoles(tenantId);

    Set<UUID> adminEquivalentIds = new HashSet<>();
    Set<UUID> fullyAdminEquivalentIds = new HashSet<>();
    tenantRolePermissions.stream()
        .collect(
            Collectors.groupingBy(
                RolePermissionName::roleId,
                Collectors.mapping(RolePermissionName::permissionName, Collectors.toList())))
        .forEach(
            (roleId, permissionNames) -> {
              if (RbacDangerousPermissions.carriesAny(permissionNames)) {
                adminEquivalentIds.add(roleId);
              }
              if (RbacDangerousPermissions.carriesAll(permissionNames)) {
                fullyAdminEquivalentIds.add(roleId);
              }
            });

    Optional<UUID> namedAdminRoleId =
        userRoleAssignmentPort.findRoleIdByName(tenantId, RbacRoleNames.TENANT_ADMIN);

    return new AdminEquivalentRoles(
        Set.copyOf(adminEquivalentIds), Set.copyOf(fullyAdminEquivalentIds), namedAdminRoleId);
  }

  /**
   * D6/§7.2: the ascending-sorted union lock set for one privileged role change — the tenant's
   * ANY-admin-equivalent role ids, the literal {@code TENANT_ADMIN} role id when seeded, and the
   * target role itself (always included when privileged — this is what makes {@code assign()}'s
   * INSERT insert-intention contained, and what makes M11 fail toward more locking on any
   * M7/M10 disagreement). "Ascending" is {@link #UNSIGNED_BYTEWISE_UUID_ORDER}, a port contract
   * of {@link UserRoleAssignmentPort#lockActiveAssignmentHolders}, not a caller convention.
   */
  private static List<UUID> buildAscendingAdminEquivalentLockSet(
      AdminEquivalentRoles roles, UUID targetRoleId) {
    Set<UUID> lockSet = new TreeSet<>(UNSIGNED_BYTEWISE_UUID_ORDER);
    lockSet.addAll(roles.adminEquivalentIds());
    roles.namedAdminRoleId().ifPresent(lockSet::add);
    lockSet.add(targetRoleId);
    return List.copyOf(lockSet);
  }

  /**
   * D5's predicate, restricted post-06-code-review.md H-1 (2026-09-24) to the tenant's
   * CALLER-QUALIFYING holders, not the broader ANY-admin-equivalent lock-set population: {@code
   * true} iff the DISTINCT {@code userId}s of {@code lockedHolders} whose {@code roleId} is in
   * {@code callerQualifyingRoleIds}, EXCLUDING the row whose {@code assignmentId} equals {@code
   * revokedAssignmentId}, is empty. Distinct holders, not rows (§7.2) — one user holding two
   * caller-qualifying roles counts once (MC-D), and the exclusion is by assignment id, never by
   * user id, so a user's OTHER caller-qualifying assignment still counts them as a holder.
   *
   * <p><b>Why not the ANY population (H-1):</b> a holder of a role carrying only ONE dangerous
   * permission (e.g. {@code tenant:write} alone) can never pass {@link
   * #requireCallerHoldsAdminEquivalentRole}'s caller gate — counting them as a "remaining admin"
   * let a revocation succeed that left the tenant with zero callers able to ever administer it
   * again, while both this guard and {@code RbacZeroActiveAdminsHealthIndicator} kept reporting
   * healthy. The lock set (§7.2) still spans the wider ANY population — that stays correct for
   * deadlock-freedom (D6/D7) and for making M11 fail toward more locking on any M7/M10
   * disagreement — but only the caller-qualifying subset of what it locked is what this specific
   * guard must never zero out.
   */
  private static boolean wouldLeaveTenantWithoutCallerQualifyingHolder(
      List<ActiveAssignmentHolder> lockedHolders,
      UUID revokedAssignmentId,
      Set<UUID> callerQualifyingRoleIds) {
    return lockedHolders.stream()
        .filter(holder -> !holder.assignmentId().equals(revokedAssignmentId))
        .filter(holder -> callerQualifyingRoleIds.contains(holder.roleId()))
        .map(ActiveAssignmentHolder::userId)
        .distinct()
        .findAny()
        .isEmpty();
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
   * US-017 D2/D8/FR-3: the shared caller gate for both {@code assign()} and {@code revoke()},
   * generalised from M5 (one literally-named role) to M5b (the caller-qualifying set — literal
   * {@code TENANT_ADMIN} OR a role carrying ALL THREE dangerous permissions, {@code
   * RbacAdminEquivalence#isFullyAdminEquivalent}). {@code roles} is the SAME {@link
   * AdminEquivalentRoles} the caller already resolved for the lock set (§7.2), so this never
   * issues a second, possibly-disagreeing M10/M8 read.
   *
   * <p>US-017 T-003(a): checked as TWO SEQUENTIAL queries — the literal {@code TENANT_ADMIN} role
   * id alone, then the ALL-three set alone — rather than one query over their union. This is what
   * lets {@code callerMatchedOn} (§9.2) be attributed correctly: a single combined boolean cannot
   * say WHICH set answered yes. The literal-admin check is the SAME one query every caller paid
   * before FR-3; only a caller who does NOT hold it pays the second, FR-3-introduced query — the
   * new population {@code nexus.rbac.privileged_role_change_allowed} exists to make visible.
   *
   * <p>An empty caller-qualifying set means the caller has no way to qualify: fail closed WITHOUT
   * calling M5b at all (D9, R-10/T-E18 precedent, generalised from "M8 empty" to "the whole
   * caller-qualifying set is empty") — preserved here since the named-admin branch short-circuits
   * on {@code isPresent()} and the ALL-three branch short-circuits on {@code isEmpty()}.
   */
  private void requireCallerHoldsAdminEquivalentRole(
      RoleChangeActor actor,
      UUID targetUserId,
      Role role,
      String requiredPermission,
      String operation,
      boolean nameMatch,
      AdminEquivalentRoles roles,
      RequestContext requestContext) {
    boolean callerHoldsNamedAdmin =
        roles.namedAdminRoleId().isPresent()
            && userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(
                actor.userId(), List.of(roles.namedAdminRoleId().get()), actor.tenantId());
    if (callerHoldsNamedAdmin) {
      recordPrivilegedRoleChangeAllowed(
          actor, targetUserId, role, operation, nameMatch, MATCHED_ON_ROLE_NAME, requestContext);
      return;
    }

    Set<UUID> fullyAdminEquivalentIds = roles.fullyAdminEquivalentIds();
    boolean callerHoldsFullyAdminEquivalent =
        !fullyAdminEquivalentIds.isEmpty()
            && userRoleAssignmentPort.hasActiveAssignmentOfAnyRole(
                actor.userId(), List.copyOf(fullyAdminEquivalentIds), actor.tenantId());
    if (callerHoldsFullyAdminEquivalent) {
      recordPrivilegedRoleChangeAllowed(
          actor, targetUserId, role, operation, nameMatch, MATCHED_ON_ALL_DANGEROUS_PERMISSIONS,
          requestContext);
      return;
    }

    denyPrivilegedRoleChange(
        actor, targetUserId, role, requiredPermission, operation, nameMatch, requestContext);
  }

  /**
   * US-017 D23/§9.2: the caller-gate PASS-point signal — the only observable evidence that FR-3's
   * loosening is actually exercised. {@code callerMatchedOn} names WHICH of the two mechanisms
   * qualified the caller (see the split-query note on the caller above), never a guess.
   *
   * <p>For the {@code ALL_DANGEROUS_PERMISSIONS} population only (RC-16.3/T-R11): an INFO log
   * companion with a subject — the metric alone has no id to investigate from, and D15's "no ids
   * in a metric" boundary is why this lives in the log, not a new tag.
   *
   * <p>On {@code assign()} specifically, when the target role is the literal {@code TENANT_ADMIN}
   * (D23/RC-16.2): a caller who is not themselves a named admin is minting a NEW one — the single
   * most sensitive operation FR-3 newly permits, and the one for which the re-derived canary
   * correctly reports {@code callerIsAdmin=true}, producing no signal at all without this WARN.
   * Gated on {@code operation}, not just on the role/caller match: the identical condition reached
   * from {@code revoke()} is removing an admin, not minting one.
   */
  private void recordPrivilegedRoleChangeAllowed(
      RoleChangeActor actor,
      UUID targetUserId,
      Role role,
      String operation,
      boolean nameMatch,
      String callerMatchedOn,
      RequestContext requestContext) {
    Counter.builder(COUNTER_PRIVILEGED_ROLE_CHANGE_ALLOWED)
        .tag(LOG_KEY_OPERATION, operation)
        .tag(TAG_CALLER_MATCHED_ON, callerMatchedOn)
        .register(meterRegistry)
        .increment();

    if (!MATCHED_ON_ALL_DANGEROUS_PERMISSIONS.equals(callerMatchedOn)) {
      return;
    }

    log.atInfo()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_PRIVILEGED_ROLE_CHANGE_ALLOWED")
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
        .addKeyValue(LOG_KEY_ROLE_ID, role.getId())
        .addKeyValue(LOG_KEY_ROLE_NAME, role.getName())
        .addKeyValue(LOG_KEY_OPERATION, operation)
        .log("Privileged role change allowed for a caller qualifying via all three dangerous permissions");

    if (!OPERATION_ASSIGN.equals(operation) || !nameMatch) {
      return;
    }

    boolean selfTarget = targetUserId.equals(actor.userId());
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_ADMIN_MINTED_BY_NON_NAMED_ADMIN")
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)
        .addKeyValue(LOG_KEY_ROLE_ID, role.getId())
        .log("A caller who is not a named TENANT_ADMIN minted a new TENANT_ADMIN via all three dangerous permissions");
    Counter.builder(COUNTER_ADMIN_MINTED_BY_NON_NAMED_ADMIN)
        .tag(TAG_SELF_TARGET, Boolean.toString(selfTarget))
        .register(meterRegistry)
        .increment();
  }

  /**
   * The tail of {@link #requireCallerHoldsAdminEquivalentRole}'s two failed branches: the WARN,
   * the counter, the denial audit row, and the throw.
   */
  private void denyPrivilegedRoleChange(
      RoleChangeActor actor,
      UUID targetUserId,
      Role role,
      String requiredPermission,
      String operation,
      boolean nameMatch,
      RequestContext requestContext) {
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

  /**
   * US-017 D24/RC-17 (03-design.md §9.3): the {@code assign()} self-assignment canary's SECOND,
   * INDEPENDENT mechanism, re-derived after FR-3 widened the gate's own caller-side question.
   * REVISION 2 (RC-17.1): shares NO INPUT with the gate — driven off M12 (non-locking, keyed by
   * {@code fk_user_roles_user}), never M10 (the gate's own tenant-scoped read), so an over-broad
   * M10 cannot silence this detector. Deliberately NOT {@link #callerHoldsActiveTenantAdmin} (kept
   * for {@link #listActive}'s unrelated, deliberately name-based D17 redaction decision) and
   * deliberately NOT reusing the gate's own {@code AdminEquivalentRoles} result.
   */
  private boolean callerHoldsActiveAdminEquivalentRole(RoleChangeActor actor) {
    List<ActiveRoleAssignment> views =
        userRoleAssignmentPort.findActiveAssignmentViews(actor.userId(), actor.tenantId());
    List<RolePermissionName> permsByRole =
        userRoleAssignmentPort.findPermissionNamesForActiveAssignmentsOfUser(
            actor.userId(), actor.tenantId());
    return views.stream()
        .anyMatch(
            a ->
                RbacAdminEquivalence.isFullyAdminEquivalent(
                    a.roleName(), permissionNamesOf(permsByRole, a.roleId())));
  }

  private static List<String> permissionNamesOf(List<RolePermissionName> permsByRole, UUID roleId) {
    return permsByRole.stream()
        .filter(p -> p.roleId().equals(roleId))
        .map(RolePermissionName::permissionName)
        .toList();
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
