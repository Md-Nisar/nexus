package com.example.nexus.rbac.application;

import static com.example.nexus.common.security.Permissions.ROLE_READ;
import static com.example.nexus.common.security.Permissions.ROLE_WRITE;

import com.example.nexus.common.domain.PreconditionFailedException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.RoleAuditEvent;
import com.example.nexus.rbac.application.port.out.RoleManagementPort;
import com.example.nexus.rbac.application.port.out.RoleUpdateAuditEvent;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.AttachProvenanceConflictException;
import com.example.nexus.rbac.domain.DuplicateRolePermissionException;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.HolderProvenance;
import com.example.nexus.rbac.domain.IdGenerator;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.RbacAdministrators;
import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.ReservedRoleNameException;
import com.example.nexus.rbac.domain.RoleCounts;
import com.example.nexus.rbac.domain.RoleHasHoldersException;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleClassificationChangedException;
import com.example.nexus.rbac.domain.RoleLimitExceededException;
import com.example.nexus.rbac.domain.RolePermissionRef;
import com.example.nexus.rbac.domain.RolePermissionSet;
import com.example.nexus.rbac.domain.RolePermissionSetVersion;
import com.example.nexus.rbac.domain.RoleView;
import com.example.nexus.rbac.domain.SystemRoleImmutableException;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Creates and manages tenant-scoped custom roles and their attached permissions (03-design.md §4,
 * §5). This is the <b>only</b> place system-role immutability, tenant isolation and the grant rules
 * for role definitions are enforced; {@code @RequiresPermission} checks nothing but flat JWT {@code
 * permissions[]} membership and cannot express any of them. The rules (ADR-0021):
 *
 * <ul>
 *   <li><b>Attach (A3).</b> The caller may attach a permission only if they hold it through an
 *       active assignment (M13), whatever the permission is.
 *   <li><b>Detach (role-subset).</b> The caller may detach a permission from a role only if they
 *       hold every permission of that role. When the role is admin-defining (carries the whole
 *       catalogue) the caller must also be an administrator through a role other than that one, so
 *       a union-holder cannot demote an administrator role and no single detach removes the last
 *       administrator status the caller relies on.
 *   <li><b>Narrow provenance rule on attach.</b> An attach that would make a role admin-defining
 *       is refused (409 {@code RBAC_010}) while the role has an active holder whose assigner is not
 *       currently an administrator.
 * </ul>
 *
 * <p>After an attach commits, every holder's cached permission set is evicted and the escalation
 * signals are derived from one holder read (who holds the role, and who assigned them) against the
 * tenant's administrator users. After a detach commits, every active holder's permission epoch is
 * bumped ({@link PermissionFreshnessService#invalidateHolders}). Both read the holders in their own
 * read-only transaction, so an assignment committed before that read is never missed (A10, design
 * §9.3, §9.4). Detach is deliberately not added to the set-lock family: two concurrent detaches can
 * still leave a tenant without an administrator (RES-28), which the zero-admin health indicator
 * detects.
 *
 * <p><b>Self-policed design invariant, mirroring {@link RoleAssignmentService}'s:</b> every public
 * method accepts only {@link RoleChangeActor}, {@link UUID} (or a collection of them), {@link
 * String} and {@link RequestContext}, never an authentication object, {@code
 * java.security.Principal} or {@code java.util.Map}. See {@code
 * docs/adr/0021-grant-subset-authorization-model.md}.
 */
@Service
public class RoleManagementService {

  private static final Logger log = LoggerFactory.getLogger(RoleManagementService.class);


  private static final String LOG_KEY_EVENT = "event";
  private static final String LOG_KEY_TENANT_ID = "tenantId";
  private static final String LOG_KEY_ROLE_ID = "roleId";
  private static final String LOG_KEY_ROLE_NAME = "roleName";
  private static final String LOG_KEY_PERMISSION_ID = "permissionId";
  private static final String LOG_KEY_PERMISSION_NAME = "permissionName";
  private static final String LOG_KEY_ACTOR_USER_ID = "actorUserId";

  private static final String MESSAGE_NO_SUCH_ROLE = "No such role";
  private static final String CODE_ROLE_NOT_FOUND = "ROLE_NOT_FOUND";
  private static final String EVENT_SUBSET_DENIED = "RBAC_ROLE_SUBSET_DENIED";
  private static final String KEY_NON_ADMIN_ASSIGNED_COUNT = "nonAdminAssignedCount";
  private static final String KEY_HOLDER_COUNT = "holderCount";
  private static final String TAG_PERMISSION = "permission";
  private static final String TAG_REASON = "reason";
  private static final String OPERATION_DETACH = "detach";
  private static final String OPERATION_ATTACH = "attach";
  private static final String OPERATION_DELETE = "delete";
  private static final String OPERATION_UPDATE = "update";
  private static final String OPERATION_LIST = "list";
  private static final String OPERATION_GET = "get";
  private static final String OPERATION_REPLACE = "replace";
  private static final String AUDIT_OPERATION_REPLACE = "REPLACE";

  private static final String COUNTER_PERMISSION_DENIED = "nexus.rbac.permission_denied";
  private static final String REASON_ATTACH_PROVENANCE = "ATTACH_PROVENANCE";
  private static final String COUNTER_ATTACH_ESCALATES =
      "nexus.rbac.attach_escalates_non_admin_assigned";
  private static final String COUNTER_ROLE_BECAME_ADMIN_DEFINING =
      "nexus.rbac.role_became_admin_defining";
  private static final String TAG_HOLDERS = "holders";
  private static final String HOLDERS_UNKNOWN = "unknown";

  /** Shared with the controller, which counts the 428 before the service is reached (R1-5). */
  public static final String COUNTER_PERMISSION_REPLACE = "nexus.rbac.permission_replace";

  public static final String TAG_OUTCOME = "outcome";
  public static final String TAG_LOCK_PATH = "lockPath";
  public static final String LOCK_PATH_NONE = "none";
  public static final String OUTCOME_PRECONDITION_REQUIRED = "precondition_required";
  private static final String LOCK_PATH_ROLE_ROW = "role_row";
  private static final String LOCK_PATH_SET_LOCK = "set_lock";
  private static final String OUTCOME_REPLACED = "replaced";
  private static final String OUTCOME_NOOP = "noop";
  private static final String OUTCOME_PRECONDITION_FAILED = "precondition_failed";
  private static final String OUTCOME_DENIED = "denied";
  private static final String OUTCOME_CONFLICT = "conflict";
  private static final String OUTCOME_ERROR = "error";
  private static final String COUNTER_ROLE_CEASED_ADMIN_DEFINING =
      "nexus.rbac.role_ceased_admin_defining";
  // RC-56.2-3: 409 RBAC_012, tagged with the operation (assign, attach).
  private static final String COUNTER_ROLE_CLASSIFICATION_CHANGED =
      "nexus.rbac.role_classification_changed";
  // The set-lock hold timer of RoleAssignmentService; B8 adds operation="replace" (design §10.8).
  private static final String TIMER_LOCK_HOLD = "nexus.rbac.privileged_revoke_lock_hold";

  private final RoleManagementPort roleManagementPort;
  private final UserRoleAssignmentPort userRoleAssignmentPort;
  private final RbacAuditPort rbacAuditPort;
  private final PermissionFreshnessService permissionFreshnessService;
  private final PermissionCachePort permissionCachePort;
  private final TransactionTemplate holderReadTransaction;
  private final MeterRegistry meterRegistry;
  private final PiiPermissionGrantRule piiGrantRule;
  private final IdGenerator idGenerator;
  private final long maxRolesPerTenant;

  public RoleManagementService(
      RoleManagementPort roleManagementPort,
      UserRoleAssignmentPort userRoleAssignmentPort,
      RbacAuditPort rbacAuditPort,
      PermissionFreshnessService permissionFreshnessService,
      PermissionCachePort permissionCachePort,
      PlatformTransactionManager transactionManager,
      MeterRegistry meterRegistry,
      PiiPermissionGrantRule piiGrantRule,
      IdGenerator idGenerator,
      @Value("${nexus.rbac.max-roles-per-tenant:500}") long maxRolesPerTenant) {
    this.roleManagementPort = roleManagementPort;
    this.userRoleAssignmentPort = userRoleAssignmentPort;
    this.rbacAuditPort = rbacAuditPort;
    this.permissionFreshnessService = permissionFreshnessService;
    this.permissionCachePort = permissionCachePort;
    // afterCommit still has the committed transaction's resources bound; only a new transaction
    // is guaranteed a fresh read of the committed rows (TransactionSynchronization#afterCommit).
    this.holderReadTransaction = new TransactionTemplate(transactionManager);
    this.holderReadTransaction.setPropagationBehavior(
        TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    this.holderReadTransaction.setReadOnly(true);
    this.meterRegistry = meterRegistry;
    this.piiGrantRule = piiGrantRule;
    this.idGenerator = idGenerator;
    this.maxRolesPerTenant = maxRolesPerTenant;
  }

  /**
   * AC1, AC9, AC12. Returns the created role including its DB-generated {@code createdAt}.
   *
   * <p>Before insert: RC-1 rejects a name matching {@link RbacRoleNames#isReserved(String)}
   * ({@link ReservedRoleNameException} / RBAC_007) — checked first because it is a free,
   * in-memory comparison, cheaper than RC-4's {@code COUNT(*)}. Only then RC-4 rejects if the
   * tenant already holds {@code maxRolesPerTenant} roles ({@link RoleLimitExceededException} /
   * RBAC_008). Unlike {@code uq_roles_tenant_name}, the cap has no DB-level backstop: it is a
   * check-then-insert, so concurrent creates near the boundary can let a tenant exceed it by a
   * small margin. Accepted per 03-design.md §8.2 — role creation is a low-volume, one-request-
   * at-a-time admin action.
   */
  @Transactional
  public RoleView createRole(RoleChangeActor actor, String name, String description, RequestContext ctx) {
    if (RbacRoleNames.isReserved(name)) {
      throw new ReservedRoleNameException();
    }
    if (roleManagementPort.countRolesInTenant(actor.tenantId()) >= maxRolesPerTenant) {
      throw new RoleLimitExceededException();
    }

    UUID newRoleId = roleManagementPort.createRole(actor.tenantId(), name, description);
    // Re-read via the projection rather than any locally-built value: a projection reads
    // DB-generated values (createdAt) directly (same M4a rationale as RoleAssignmentService).
    RoleView view = roleManagementPort.findRole(newRoleId).orElseThrow();

    // US-018 A6 (design §6.2): the success-audit write moved INLINE, inside this transaction,
    // after the insert and before return -- no longer post-commit. RbacAuditPort's Group A
    // contract now REQUIRES the implementation to throw on failure (it no longer swallows), so a
    // lost audit write propagates from here, rolls back this transaction, and surfaces as a 500
    // rather than committing a role change with zero audit trail. The INFO log stays post-commit
    // below -- only the audit write itself moved.
    rbacAuditPort.recordRoleCreated(
        new RoleAuditEvent(
            actor.tenantId(), view.id(), view.name(), null, null, actor.userId(), ctx, null));

    registerPostCommitSideEffects(
        () -> {
          log.atInfo()
              .addKeyValue(LOG_KEY_EVENT, "ROLE_CREATED")
              .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
              .addKeyValue(LOG_KEY_ROLE_ID, view.id())
              .addKeyValue(LOG_KEY_ROLE_NAME, view.name())
              .addKeyValue("createdBy", actor.userId())
              .log("Role created");
        });

    return view;
  }

  /**
   * AC2, AC8, C2. One page of the live roles of the actor's tenant, tenant-scoped by predicate (the
   * tenant comes from the actor, i.e. the JWT), ordered by {@code (name, id)}.
   */
  @Transactional(readOnly = true)
  public PageResult<RoleView> listRoles(RoleChangeActor actor, int page, int size) {
    return roleManagementPort.findRolesInTenant(actor.tenantId(), page, size);
  }

  /** US-019 B3. One live role of the actor's tenant; missing, deleted and foreign ids are one 404. */
  @Transactional(readOnly = true)
  public RoleView getRole(RoleChangeActor actor, UUID roleId) {
    return resolveRoleInTenant(roleId, actor, ROLE_READ, OPERATION_GET);
  }

  /**
   * US-019 B6. The member and permission counts of the given roles of the actor's tenant, from two
   * grouped statements however many roles there are (none for an empty collection). Every id gets an
   * entry; a role with no holder or permission reports zero. Callers pass ids they have already
   * resolved in the actor's tenant, and both statements carry the tenant predicate regardless.
   */
  @Transactional(readOnly = true)
  public Map<UUID, RoleCounts> countsForRoles(RoleChangeActor actor, Collection<UUID> roleIds) {
    if (roleIds.isEmpty()) {
      return Map.of();
    }
    Map<UUID, Long> holders = roleManagementPort.countActiveHoldersByRole(actor.tenantId(), roleIds);
    Map<UUID, Long> permissions =
        roleManagementPort.countPermissionsByRole(actor.tenantId(), roleIds);
    Map<UUID, RoleCounts> counts = new HashMap<>();
    for (UUID roleId : roleIds) {
      counts.put(
          roleId,
          new RoleCounts(
              roleId,
              holders.getOrDefault(roleId, 0L),
              Math.toIntExact(permissions.getOrDefault(roleId, 0L))));
    }
    return counts;
  }

  /**
   * AC3, AC8. 404 then 403; empty list is a valid 200. US-019 B8: the result carries the set's
   * {@link RolePermissionSetVersion}, computed from the same read as the permissions, which the
   * controller serves as the {@code ETag} a replace sends back in {@code If-Match}.
   */
  @Transactional(readOnly = true)
  public RolePermissionSet listRolePermissions(RoleChangeActor actor, UUID roleId) {
    RoleView role = resolveRoleInTenant(roleId, actor, ROLE_READ, OPERATION_LIST);
    List<PermissionView> permissions = roleManagementPort.findPermissionsForRole(role.id());
    return new RolePermissionSet(
        role.id(),
        permissions,
        RolePermissionSetVersion.of(
            role.id(), permissions.stream().map(PermissionView::id).toList()));
  }

  /**
   * Attaches {@code permissionId} to a custom role. Order: tenant resolution (404/403), system-role
   * immutability (409), permission existence (404), A3 (403: the caller must hold the permission,
   * {@link #requireCallerHoldsPermission}), the PII grant rule (403, below), the narrow provenance
   * rule (409 {@code RBAC_010}, only when this attach would make the role admin-defining), the
   * duplicate pre-check (409 {@code
   * RBAC_005}), the role-row lock (404 if the role is gone), the insert, the post-insert current
   * read (409 {@code RBAC_012}). A3 sits before the duplicate check so a denied caller learns
   * nothing about attachment state.
   *
   * <p><b>Serialised on the role row (US-019 RC-64, RC-56.3).</b> Only after every authorization
   * check, attach X-locks R's row ({@code lockRoleRow}, the statement B8 uses) and then inserts, so
   * concurrent attaches on R queue on the row instead of deadlocking (T-D28). After the insert, a
   * {@code FOR SHARE} read of R's permissions re-classifies R; if it now covers the catalogue while
   * the snapshot said this attach would not complete it, a change committed while the attach waited
   * and the provenance rule never judged it, so the attach rolls back with the retryable 409 {@code
   * RBAC_012} and no audit row. Lock order is roles, then role_permissions (RC-46); a catalogue-completing
   * attach takes the set lock (user_roles) after the role row, as a promoting replace does.
   *
   * <p><b>Provenance rule (design §5.6, R1-1).</b> If the role is not admin-defining now and its
   * permissions plus the attached one cover the catalogue, the role would turn every holder into an
   * administrator. If any active holder was assigned by someone who is not currently an
   * administrator, the attach is refused: otherwise a second account could be promoted by an
   * unwitting administrator (RES-26). A role that is already admin-defining does not match, so its
   * duplicate attach still gets {@code RBAC_005}. Partial escalations stay detective, see the
   * signals below. The extra work is on the rare branch where the attach completes the catalogue:
   * a non-locking fast-fail before the role-row lock, then (R1-1) the same rule again after it,
   * from the set lock's rows and a current read, because a non-locking re-read would still see the
   * transaction's old snapshot and miss an assign that committed while the attach waited.
   *
   * <p><b>PII grant rule (US-019 §4.8, RC-60.3).</b> Right after A3 (RC-66.1) and before the
   * provenance rule and the duplicate check: attaching {@code user:directory:read} requires the
   * caller to be an administrator by A3's own M13 rows and the catalogue. A denial is 403 {@code
   * NOT_TENANT_ADMIN} with WARN {@code RBAC_PII_PERMISSION_GRANT_DENIED} and no audit row (Decision
   * 7). With the rule switched off, a non-administrator's attach is reported after commit (RC-60.2).
   *
   * <p><b>Signals (rows 13 and 14).</b> After commit, from one holder read, a WARN and a counter
   * report an attach that escalates holders assigned by non-administrators, and a second pair
   * reports that the role became admin-defining. See {@link #emitAttachSignals}. The same read
   * feeds the committed-state detector ({@link AdminDefiningRoleProvenanceDetector}, RC-56.4).
   */
  @Transactional
  public PermissionView attachPermission(
      RoleChangeActor actor, UUID roleId, UUID permissionId, RequestContext ctx) {
    RoleView role = resolveRoleInTenant(roleId, actor, ROLE_WRITE, OPERATION_ATTACH);
    requireMutableRole(role);

    PermissionView permission =
        roleManagementPort
            .findPermission(permissionId)
            .orElseThrow(
                () -> new ResourceNotFoundException("PERMISSION_NOT_FOUND", "No such permission"));

    List<RolePermissionRef> heldRolePermissions =
        requireCallerHoldsPermission(actor, role, permissionId);
    PiiPermissionGrantRule.Outcome piiGrant =
        piiGrantRule.evaluate(
            Set.of(permissionId),
            () ->
                RbacAdministrators.isAdministrator(
                    heldRolePermissions, userRoleAssignmentPort.findCatalogueIds()));
    if (piiGrant == PiiPermissionGrantRule.Outcome.DENIED) {
      piiGrantRule.warnDenied(actor.tenantId(), actor.userId(), role.id(), null, OPERATION_ATTACH);
      throw new InsufficientPermissionException(ROLE_WRITE, DenialReason.NOT_TENANT_ADMIN);
    }

    Set<UUID> catalogueIds = userRoleAssignmentPort.findCatalogueIds();
    boolean becameAdminDefining =
        attachWouldMakeRoleAdminDefining(actor, role, permissionId, catalogueIds);
    if (becameAdminDefining) {
      requireNoNonAdministratorAssignedHolder(actor, role, permissionId);
    }

    if (roleManagementPort.hasPermission(role.id(), permissionId)) {
      throw new DuplicateRolePermissionException();
    }
    // RC-64: R's row X lock before the insert, so concurrent attaches on R queue here instead of
    // deadlocking in the current read below (T-D28). Order: roles, then role_permissions (RC-46).
    if (!roleManagementPort.lockRoleRow(role.id(), actor.tenantId())) {
      throw new ResourceNotFoundException(CODE_ROLE_NOT_FOUND, MESSAGE_NO_SUCH_ROLE);
    }
    if (becameAdminDefining) {
      requireNoLockedNonAdministratorAssignedHolder(actor, role, catalogueIds);
    }
    roleManagementPort.attachPermission(role.id(), permissionId);
    requireAttachKeptItsClassification(
        actor, role, permissionId, becameAdminDefining, catalogueIds);

    // A6 (design §6.2): the success audit is written INLINE, inside this transaction. The port
    // contract requires it to throw on failure, so a lost audit write rolls the attach back.
    // holderCount is no longer carried on the audit row: the holder read is after commit (row 13).
    rbacAuditPort.recordRolePermissionGranted(
        new RoleAuditEvent(
            actor.tenantId(), role.id(), role.name(), permission.id(), permission.name(),
            actor.userId(), ctx, null));

    registerPostCommitSideEffects(
        () -> {
          log.atInfo()
              .addKeyValue(LOG_KEY_EVENT, "ROLE_PERMISSION_GRANTED")
              .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
              .addKeyValue(LOG_KEY_ROLE_ID, role.id())
              .addKeyValue(LOG_KEY_ROLE_NAME, role.name())
              .addKeyValue(LOG_KEY_PERMISSION_ID, permission.id())
              .addKeyValue(LOG_KEY_PERMISSION_NAME, permission.name())
              .addKeyValue("grantedBy", actor.userId())
              .log("Role permission granted");
          if (piiGrant == PiiPermissionGrantRule.Outcome.DELEGATED) {
            piiGrantRule.recordDelegated(actor.tenantId(), actor.userId(), role.id(), null);
          }

          Optional<AttachSnapshot> snapshot =
              readAfterCommit(
                  actor.tenantId(),
                  role.id(),
                  OPERATION_ATTACH,
                  false,
                  () -> readAttachSnapshot(actor.tenantId(), role.id()));
          emitAttachSignals(
              actor, role, List.of(permission.id()), becameAdminDefining, snapshot);
          detectNonAdministratorAssignedHolder(actor.tenantId(), role.id(), snapshot);
          // A10 (Decision 15): evict every holder's cached set so their next mint carries the new
          // permission; never bump, since a token lacking an added permission is fail-safe. A mint
          // that read the pre-attach set may still put it back after this eviction, so that holder
          // lacks the permission until the entry expires (L-4, accepted: Decision 15).
          snapshot.ifPresent(
              read ->
                  permissionCachePort.evict(
                      actor.tenantId(),
                      read.holders().stream().map(HolderProvenance::userId).toList()));
        });

    return permission;
  }

  /**
   * Detaches {@code permissionId} from a custom role. Order: tenant resolution (404/403),
   * system-role immutability (409), <b>role-subset</b> (403, {@link #requireRoleSubset}), the delete
   * (0 rows means 404). Role-subset replaces the former name-based dangerous-permission gate
   * (ADR-0021 D5). It runs before the delete, so a caller without the role's permissions gets 403
   * whether or not the permission is attached, which is no attachment-existence oracle.
   */
  @Transactional
  public void detachPermission(
      RoleChangeActor actor, UUID roleId, UUID permissionId, RequestContext ctx) {
    RoleView role = resolveRoleInTenant(roleId, actor, ROLE_WRITE, OPERATION_DETACH);
    requireMutableRole(role);

    requireRoleSubset(actor, role, OPERATION_DETACH);

    // One read serves the audit's permissionName.
    Optional<PermissionView> permission = roleManagementPort.findPermission(permissionId);

    int affectedRows = roleManagementPort.detachPermission(role.id(), permissionId);
    if (affectedRows == 0) {
      // Covers "permission does not exist", "never attached" and "already detached" identically
      // — the addressed resource is the pairing, which does not exist in any of the three cases.
      throw new ResourceNotFoundException(
          "ROLE_PERMISSION_NOT_FOUND", "This permission is not attached to this role");
    }

    String permissionName = permission.map(PermissionView::name).orElse(null);

    // A6 (design §6.2): the success audit is written INLINE, inside this transaction.
    rbacAuditPort.recordRolePermissionRevoked(
        new RoleAuditEvent(
            actor.tenantId(), role.id(), role.name(), permissionId, permissionName,
            actor.userId(), ctx, null));

    registerPostCommitSideEffects(
        () -> {
          log.atInfo()
              .addKeyValue(LOG_KEY_EVENT, "ROLE_PERMISSION_REVOKED")
              .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
              .addKeyValue(LOG_KEY_ROLE_ID, role.id())
              .addKeyValue(LOG_KEY_ROLE_NAME, role.name())
              .addKeyValue(LOG_KEY_PERMISSION_ID, permissionId)
              .addKeyValue(LOG_KEY_PERMISSION_NAME, permissionName)
              .addKeyValue("revokedBy", actor.userId())
              .log("Role permission revoked");
          // A10 (MC-7b): after commit only, so a mint in the gap cannot read the new epoch with the
          // pre-commit permission set. Holders are read after commit, so an assignment committed
          // before this read is included; one committed after it mints fresh, because its role set
          // changed.
          readAfterCommit(
                  actor.tenantId(),
                  role.id(),
                  OPERATION_DETACH,
                  true,
                  () -> userRoleAssignmentPort.findActiveUserIdsForRole(role.id()))
              .ifPresent(
                  holders ->
                      permissionFreshnessService.invalidateHolders(
                          actor.tenantId(), holders, OPERATION_DETACH));
        });
  }

  /**
   * US-019 B8: atomically replaces the permission set of a custom role with {@code targetIds}, if
   * {@code ifMatchTag} (the one strong entity-tag the controller accepted) is the version of the
   * set the server authorises against (design §10.3, §10.4). Steps:
   *
   * <ol>
   *   <li>1-3, snapshot reads: tenant resolution (404), system-role immutability (409 {@code
   *       RBAC_003}), every target id in the catalogue M15 (404 {@code PERMISSION_NOT_FOUND}).
   *   <li>4-5: the snapshot {@code S0} (M14) and its version {@code v0}; adds, removes, and whether
   *       the role is admin-defining before and after.
   *   <li>6, <b>always, before any state is revealed</b> (RC-58.1, T-I20): one M13 read; live
   *       {@code role:write} (L-1) and live {@code role:read} (RC-58.4); A3 on adds; the PII grant
   *       rule (§4.8); role-subset on removes, with the administrator-through-another-role rule
   *       on a demotion. Denials are 403 with WARN and no audit row (Decision 7).
   *   <li>7: {@code ifMatchTag} must equal {@code v0} (412, lock-free); an unchanged set is then
   *       the authorised no-op 200: no lock, no audit, no bump.
   *   <li>8, <b>locks only after authorization</b> (T-D27), in the order R's current class fixes
   *       (RC-46): an admin-defining R (a demotion) takes the set lock, then the role row {@code
   *       FOR UPDATE}; any other R takes the role row, then the set lock iff the PUT promotes it.
   *       A role row that is gone is 404.
   *   <li>9: the current read of R's {@code role_permissions} {@code FOR SHARE}; its version
   *       {@code v1} must equal {@code v0}, never merely something the client sent (RC-55.1,
   *       T-T22), or the PUT is 412. Equal versions mean the locked state is the one steps 5-7
   *       classified and authorised.
   *   <li>10, set lock held (RC-57.1): which locked roles are admin-defining <b>now</b>, from a
   *       {@code FOR SHARE} read of their {@code role_permissions}. A demotion needs a locked
   *       {@code user_roles} row of the caller on another role that is admin-defining in this
   *       read, else 403 {@code GRANT_EXCEEDS_CALLER}: one caller's two concurrent demotions can
   *       never both pass (RES-28).
   *   <li>11, promotion: 409 {@code RBAC_010} when a locked holder of R was assigned by a user who
   *       holds no locked row of a role admin-defining in step 10's read (RES-26).
   *   <li>12-13: one bulk delete of the removes (its row count must equal their number), the
   *       inserts, and one inline Group A audit row per change with {@code operation=REPLACE} and
   *       one server-generated {@code replaceId}.
   *   <li>14-15, after commit: removes bump every holder's epoch once, otherwise adds evict the
   *       holders' cache once; the attach signals for the added set; on a demotion, WARN {@code
   *       RBAC_ROLE_CEASED_ADMIN_DEFINING} and its counter (RC-63(f)); INFO {@code
   *       RBAC_PERMISSION_SET_REPLACED}. Returns the new set and its version.
   * </ol>
   */
  @Transactional
  public RolePermissionSet replaceRolePermissions(
      RoleChangeActor actor,
      UUID roleId,
      Collection<UUID> targetIds,
      String ifMatchTag,
      RequestContext ctx) {
    RoleView role = resolveRoleInTenant(roleId, actor, ROLE_WRITE, OPERATION_REPLACE);
    requireMutableRole(role);
    Set<UUID> catalogueIds = userRoleAssignmentPort.findCatalogueIds();
    Set<UUID> target = Set.copyOf(targetIds);
    if (!catalogueIds.containsAll(target)) {
      throw new ResourceNotFoundException("PERMISSION_NOT_FOUND", "No such permission");
    }

    Set<UUID> snapshot =
        userRoleAssignmentPort
            .findPermissionIdsForRole(role.id(), actor.tenantId())
            .orElseThrow(() -> new ResourceNotFoundException(CODE_ROLE_NOT_FOUND, MESSAGE_NO_SUCH_ROLE));
    String snapshotVersion = RolePermissionSetVersion.of(role.id(), snapshot);
    Set<UUID> adds = difference(target, snapshot);
    Set<UUID> removes = difference(snapshot, target);
    boolean before = RbacAdministrators.isAdminDefining(snapshot, catalogueIds);
    boolean after = RbacAdministrators.isAdminDefining(target, catalogueIds);

    PiiPermissionGrantRule.Outcome piiGrant =
        authorizeReplace(actor, role, snapshot, adds, removes, before, catalogueIds);

    if (!snapshotVersion.equals(ifMatchTag)) {
      countReplace(OUTCOME_PRECONDITION_FAILED, LOCK_PATH_NONE);
      throw new PreconditionFailedException();
    }
    if (adds.isEmpty() && removes.isEmpty()) {
      countReplace(OUTCOME_NOOP, LOCK_PATH_NONE);
      return new RolePermissionSet(
          role.id(), roleManagementPort.findPermissionsForRole(role.id()), snapshotVersion);
    }

    // Past the no-op an admin-defining R always loses a permission (adds are empty: R already
    // carries the whole catalogue), so "before" is exactly a demotion.
    ReplacePlan plan =
        new ReplacePlan(
            target, adds, removes, snapshotVersion, before, !before && after, catalogueIds,
            piiGrant);
    String lockPath = plan.needsSetLock() ? LOCK_PATH_SET_LOCK : LOCK_PATH_ROLE_ROW;
    SetLockRows setLockFirst = plan.demotion() ? acquireSetLock(actor, role, catalogueIds) : null;
    if (!roleManagementPort.lockRoleRow(role.id(), actor.tenantId())) {
      throw new ResourceNotFoundException(CODE_ROLE_NOT_FOUND, MESSAGE_NO_SUCH_ROLE);
    }
    Timer.Sample lockHold = Timer.start(meterRegistry);
    try {
      SetLockRows setLock =
          plan.promotion() ? acquireSetLock(actor, role, catalogueIds) : setLockFirst;
      return replaceUnderLocks(actor, role, plan, setLock, lockPath, lockHold, ctx);
    } catch (PreconditionFailedException e) {
      stopLockHoldTimer(lockHold, OUTCOME_PRECONDITION_FAILED);
      throw e;
    } catch (InsufficientPermissionException e) {
      stopLockHoldTimer(lockHold, OUTCOME_DENIED);
      throw e;
    } catch (AttachProvenanceConflictException e) {
      stopLockHoldTimer(lockHold, OUTCOME_CONFLICT);
      throw e;
    } catch (RuntimeException e) {
      stopLockHoldTimer(lockHold, OUTCOME_ERROR);
      throw e;
    }
  }

  /**
   * What steps 1-7 decided, carried into the locked steps: the target and its difference from the
   * snapshot, the snapshot version {@code v0}, the class change, the catalogue and the PII rule's
   * outcome.
   */
  private record ReplacePlan(
      Set<UUID> target,
      Set<UUID> adds,
      Set<UUID> removes,
      String snapshotVersion,
      boolean demotion,
      boolean promotion,
      Set<UUID> catalogueIds,
      PiiPermissionGrantRule.Outcome piiGrant) {

    boolean needsSetLock() {
      return demotion || promotion;
    }
  }

  /**
   * Steps 9 to 15 of {@link #replaceRolePermissions}, with the role row X-locked and, when {@code
   * setLock} is not {@code null}, the set lock held.
   */
  private RolePermissionSet replaceUnderLocks(
      RoleChangeActor actor,
      RoleView role,
      ReplacePlan plan,
      SetLockRows setLock,
      String lockPath,
      Timer.Sample lockHold,
      RequestContext ctx) {
    Set<UUID> adds = plan.adds();
    Set<UUID> removes = plan.removes();
    Set<UUID> current = roleManagementPort.lockPermissionIdsForRole(role.id());
    if (!RolePermissionSetVersion.of(role.id(), current).equals(plan.snapshotVersion())) {
      countReplace(OUTCOME_PRECONDITION_FAILED, lockPath);
      throw new PreconditionFailedException();
    }

    if (setLock != null) {
      requireSetLockInvariants(actor, role, plan, setLock);
    }

    Map<UUID, String> removedNames = Map.of();
    if (!removes.isEmpty()) {
      removedNames = namesById(roleManagementPort.findPermissionsForRole(role.id()));
      int detached = roleManagementPort.detachPermissions(role.id(), removes);
      if (detached != removes.size()) {
        throw new IllegalStateException(
            "Bulk detach removed " + detached + " rows, expected " + removes.size());
      }
    }
    if (!adds.isEmpty()) {
      roleManagementPort.attachPermissions(role.id(), adds);
    }
    List<PermissionView> permissions = roleManagementPort.findPermissionsForRole(role.id());
    Map<UUID, String> addedNames = namesById(permissions);

    UUID replaceId = idGenerator.newId();
    for (UUID added : sorted(adds)) {
      rbacAuditPort.recordRolePermissionGranted(
          replaceAuditEvent(actor, role, added, addedNames.get(added), replaceId, ctx));
    }
    for (UUID removed : sorted(removes)) {
      rbacAuditPort.recordRolePermissionRevoked(
          replaceAuditEvent(actor, role, removed, removedNames.get(removed), replaceId, ctx));
    }

    registerPostCommitSideEffects(
        () -> {
          stopLockHoldTimer(lockHold, OUTCOME_REPLACED);
          countReplace(OUTCOME_REPLACED, lockPath);
          log.atInfo()
              .addKeyValue(LOG_KEY_EVENT, "RBAC_PERMISSION_SET_REPLACED")
              .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
              .addKeyValue(LOG_KEY_ROLE_ID, role.id())
              .addKeyValue("replaceId", replaceId)
              .addKeyValue("addedCount", adds.size())
              .addKeyValue("removedCount", removes.size())
              .addKeyValue(TAG_LOCK_PATH, lockPath)
              .addKeyValue("replacedBy", actor.userId())
              .log("Role permission set replaced");
          if (plan.piiGrant() == PiiPermissionGrantRule.Outcome.DELEGATED) {
            piiGrantRule.recordDelegated(actor.tenantId(), actor.userId(), role.id(), null);
          }
          Optional<Integer> holderCount = applyReplaceFreshness(actor, role, adds, removes);
          if (plan.demotion()) {
            signalRoleCeasedAdminDefining(actor, role, holderCount);
          }
        });

    return new RolePermissionSet(
        role.id(), permissions, RolePermissionSetVersion.of(role.id(), plan.target()));
  }

  /** Steps 10 and 11 of {@link #replaceRolePermissions}: demotion and promotion checks. */
  private void requireSetLockInvariants(
      RoleChangeActor actor, RoleView role, ReplacePlan plan, SetLockRows setLock) {
    Set<UUID> adminDefiningNow = adminDefiningNow(actor, setLock, plan.catalogueIds());
    if (plan.demotion()) {
      requireAdministratorThroughAnotherLockedRole(
          actor, role, setLock, adminDefiningNow, OPERATION_REPLACE);
    }
    if (plan.promotion()) {
      requireNoLockedHolderAssignedByNonAdministrator(
          actor, role, setLock, adminDefiningNow, OPERATION_REPLACE);
    }
  }

  /**
   * RC-57.1 and RC-57.2 (T-E49): which of the set lock's roles are admin-defining <b>now</b>, from
   * a {@code FOR SHARE} read of their {@code role_permissions} taken under the set lock, never from
   * the pre-lock M10' read. An uncommitted detach or replace on one of them is waited for, then
   * seen.
   */
  private Set<UUID> adminDefiningNow(
      RoleChangeActor actor, SetLockRows setLock, Set<UUID> catalogueIds) {
    return RbacAdministrators.adminDefiningRoleIds(
        userRoleAssignmentPort.lockRolePermissionsForRoles(actor.tenantId(), setLock.roleIds()),
        catalogueIds);
  }

  /**
   * Step 10 on a demotion (RC-25.1, RC-57.1), and the locked half of role-subset on deleting an
   * admin-defining role (RC-57.2): the caller must hold a locked {@code user_roles} row of a role
   * other than R that is admin-defining in the current read. The snapshot said so at step 6 (or at
   * role-subset), but a concurrent demotion or revoke that committed while this request waited on
   * the set lock may have changed it; deciding from locked rows and the current read is what keeps
   * one caller's two demotions from removing the tenant's last administrator. 403 {@code
   * GRANT_EXCEEDS_CALLER}, WARN {@code RBAC_ROLE_SUBSET_DENIED} (ids only) and no audit row, as the
   * snapshot denial; a replace also counts the denial on its set-lock path.
   */
  private void requireAdministratorThroughAnotherLockedRole(
      RoleChangeActor actor,
      RoleView role,
      SetLockRows setLock,
      Set<UUID> adminDefiningNow,
      String operation) {
    boolean administratorElsewhere =
        setLock.holders().stream()
            .anyMatch(
                holder ->
                    holder.userId().equals(actor.userId())
                        && !holder.roleId().equals(role.id())
                        && adminDefiningNow.contains(holder.roleId()));
    if (administratorElsewhere) {
      return;
    }
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, EVENT_SUBSET_DENIED)
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_ROLE_ID, role.id())
        .addKeyValue("operation", operation)
        .addKeyValue("stage", "locked")
        .log("Blocked a change to an admin-defining role: under the set lock the caller is no"
            + " longer an administrator through another role");
    if (OPERATION_REPLACE.equals(operation)) {
      countReplace(OUTCOME_DENIED, LOCK_PATH_SET_LOCK);
    }
    throw new InsufficientPermissionException(ROLE_WRITE, DenialReason.GRANT_EXCEEDS_CALLER);
  }

  /**
   * Step 11 on a promotion (RES-26, as attach's narrow provenance rule, row 14): 409 {@code
   * RBAC_010} when an active holder of R was assigned by a user who is not currently an
   * administrator. Both sides come from the set lock's rows (R is in the lock set, so its holders
   * are locked and an assign cannot slip in), and "is an administrator" means holding a locked row
   * of a role admin-defining in step 10's current read. WARN {@code RBAC_ATTACH_PROVENANCE_REFUSED}
   * (ids and a count), {@code permission_denied{reason=ATTACH_PROVENANCE}}, no audit row.
   */
  private void requireNoLockedHolderAssignedByNonAdministrator(
      RoleChangeActor actor,
      RoleView role,
      SetLockRows setLock,
      Set<UUID> adminDefiningNow,
      String operation) {
    Set<UUID> administrators = new HashSet<>();
    setLock.holders().stream()
        .filter(holder -> adminDefiningNow.contains(holder.roleId()))
        .forEach(holder -> administrators.add(holder.userId()));
    long nonAdminAssignedCount =
        setLock.holders().stream()
            .filter(holder -> holder.roleId().equals(role.id()))
            .filter(holder -> !administrators.contains(holder.assignedBy()))
            .count();
    if (nonAdminAssignedCount == 0) {
      return;
    }
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_ATTACH_PROVENANCE_REFUSED")
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_ROLE_ID, role.id())
        .addKeyValue("operation", operation)
        .addKeyValue(KEY_NON_ADMIN_ASSIGNED_COUNT, nonAdminAssignedCount)
        .log("Refused a permission change that would make a role admin-defining while some of"
            + " its holders were assigned by a non-administrator");
    Counter.builder(COUNTER_PERMISSION_DENIED)
        .tag(TAG_PERMISSION, ROLE_WRITE)
        .tag(TAG_REASON, REASON_ATTACH_PROVENANCE)
        .register(meterRegistry)
        .increment();
    if (OPERATION_REPLACE.equals(operation)) {
      countReplace(OUTCOME_CONFLICT, LOCK_PATH_SET_LOCK);
    }
    throw new AttachProvenanceConflictException();
  }

  /**
   * RC-63(f), after a demotion commits: WARN {@code RBAC_ROLE_CEASED_ADMIN_DEFINING} (ids and the
   * holder count from the after-commit holder read, omitted if that read failed) and the untagged
   * counter {@code nexus.rbac.role_ceased_admin_defining} (a ticket). Its holders are no longer
   * administrators through R.
   */
  private void signalRoleCeasedAdminDefining(
      RoleChangeActor actor, RoleView role, Optional<Integer> holderCount) {
    var warn =
        log.atWarn()
            .addKeyValue(LOG_KEY_EVENT, "RBAC_ROLE_CEASED_ADMIN_DEFINING")
            .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
            .addKeyValue(LOG_KEY_ROLE_ID, role.id());
    if (holderCount.isPresent()) {
      warn = warn.addKeyValue(KEY_HOLDER_COUNT, holderCount.get());
    }
    warn.log("Role ceased to be admin-defining");
    Counter.builder(COUNTER_ROLE_CEASED_ADMIN_DEFINING).register(meterRegistry).increment();
  }

  /**
   * Step 6 of {@link #replaceRolePermissions}: the snapshot authorization, from one M13 read. Each
   * denial is a 403 {@code RBAC_001} with a WARN (ids only) and no audit row, as attach and detach
   * (Decision 7). Returns the PII rule's outcome for the after-commit delegation signal.
   */
  private PiiPermissionGrantRule.Outcome authorizeReplace(
      RoleChangeActor actor,
      RoleView role,
      Set<UUID> snapshot,
      Set<UUID> adds,
      Set<UUID> removes,
      boolean adminDefiningBefore,
      Set<UUID> catalogueIds) {
    List<RolePermissionRef> held =
        userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(
            actor.userId(), actor.tenantId());
    Set<UUID> heldPermissionIds = new HashSet<>();
    held.forEach(ref -> heldPermissionIds.add(ref.permissionId()));

    requireLiveEndpointPermission(
        actor, role, heldPermissionIds, RbacSeededPermissionIds.ROLE_WRITE, ROLE_WRITE);
    requireLiveEndpointPermission(
        actor, role, heldPermissionIds, RbacSeededPermissionIds.ROLE_READ, ROLE_READ);
    if (!heldPermissionIds.containsAll(adds)) {
      log.atWarn()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_REPLACE_EXCEEDS_CALLER")
          .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
          .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
          .addKeyValue(LOG_KEY_ROLE_ID, role.id())
          .log("Blocked a permission-set replace that adds a permission the caller does not hold");
      throw new InsufficientPermissionException(ROLE_WRITE, DenialReason.GRANT_EXCEEDS_CALLER);
    }

    PiiPermissionGrantRule.Outcome piiGrant =
        piiGrantRule.evaluate(
            adds, () -> RbacAdministrators.isAdministrator(held, catalogueIds));
    if (piiGrant == PiiPermissionGrantRule.Outcome.DENIED) {
      piiGrantRule.warnDenied(actor.tenantId(), actor.userId(), role.id(), null, OPERATION_REPLACE);
      throw new InsufficientPermissionException(ROLE_WRITE, DenialReason.NOT_TENANT_ADMIN);
    }

    if (!removes.isEmpty()) {
      boolean allowed = heldPermissionIds.containsAll(snapshot);
      if (allowed && adminDefiningBefore) {
        List<RolePermissionRef> heldThroughOtherRoles =
            held.stream().filter(ref -> !ref.roleId().equals(role.id())).toList();
        allowed = RbacAdministrators.isAdministrator(heldThroughOtherRoles, catalogueIds);
      }
      if (!allowed) {
        log.atWarn()
            .addKeyValue(LOG_KEY_EVENT, EVENT_SUBSET_DENIED)
            .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
            .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
            .addKeyValue(LOG_KEY_ROLE_ID, role.id())
            .addKeyValue("operation", OPERATION_REPLACE)
            .log("Blocked a role definition change by a caller who does not hold the role's"
                + " permissions");
        throw new InsufficientPermissionException(ROLE_WRITE, DenialReason.GRANT_EXCEEDS_CALLER);
      }
    }
    return piiGrant;
  }

  /**
   * L-1 and RC-58.4: {@code @RequiresPermission} read the endpoint permission from a JWT that may
   * predate a revoke, so the live M13 rows must still carry it (by seeded id). 403 {@code
   * PERMISSION_ABSENT} otherwise.
   */
  private void requireLiveEndpointPermission(
      RoleChangeActor actor,
      RoleView role,
      Set<UUID> heldPermissionIds,
      UUID permissionId,
      String permission) {
    if (heldPermissionIds.contains(permissionId)) {
      return;
    }
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_ENDPOINT_PERMISSION_NOT_HELD")
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_ROLE_ID, role.id())
        .addKeyValue("requiredPermission", permission)
        .addKeyValue("operation", OPERATION_REPLACE)
        .log("Blocked a permission-set replace by a caller whose live holdings lack an endpoint"
            + " permission");
    throw new InsufficientPermissionException(permission, DenialReason.PERMISSION_ABSENT);
  }

  /**
   * Step 14 of {@link #replaceRolePermissions}, after commit, from one holder read in its own
   * transaction. Removes revoke, so the holders' epochs are bumped once (which also leaves their
   * old-epoch cache entries unreachable) and a failed read is retried and queued as detach's is;
   * adds alone evict the holders' cache once. The attach signals are derived once for the added
   * set. Returns the number of holders read, empty if the read failed.
   */
  private Optional<Integer> applyReplaceFreshness(
      RoleChangeActor actor, RoleView role, Set<UUID> adds, Set<UUID> removes) {
    boolean revokes = !removes.isEmpty();
    if (adds.isEmpty()) {
      Optional<List<UUID>> holders =
          readAfterCommit(
              actor.tenantId(),
              role.id(),
              OPERATION_REPLACE,
              true,
              () -> userRoleAssignmentPort.findActiveUserIdsForRole(role.id()));
      holders.ifPresent(
          read ->
              permissionFreshnessService.invalidateHolders(
                  actor.tenantId(), read, OPERATION_REPLACE));
      return holders.map(List::size);
    }
    Optional<AttachSnapshot> snapshot =
        readAfterCommit(
            actor.tenantId(),
            role.id(),
            OPERATION_REPLACE,
            revokes,
            () -> readAttachSnapshot(actor.tenantId(), role.id()));
    emitAttachSignals(actor, role, sorted(adds), false, snapshot);
    detectNonAdministratorAssignedHolder(actor.tenantId(), role.id(), snapshot);
    snapshot.ifPresent(
        read -> {
          List<UUID> holders = read.holders().stream().map(HolderProvenance::userId).toList();
          if (revokes) {
            permissionFreshnessService.invalidateHolders(
                actor.tenantId(), holders, OPERATION_REPLACE);
          } else {
            permissionCachePort.evict(actor.tenantId(), holders);
          }
        });
    return snapshot.map(read -> read.holders().size());
  }

  private static RoleAuditEvent replaceAuditEvent(
      RoleChangeActor actor,
      RoleView role,
      UUID permissionId,
      String permissionName,
      UUID replaceId,
      RequestContext ctx) {
    return new RoleAuditEvent(
        actor.tenantId(),
        role.id(),
        role.name(),
        permissionId,
        permissionName,
        actor.userId(),
        ctx,
        null,
        AUDIT_OPERATION_REPLACE,
        replaceId);
  }

  private static Set<UUID> difference(Set<UUID> from, Set<UUID> minus) {
    Set<UUID> result = new HashSet<>(from);
    result.removeAll(minus);
    return result;
  }

  private static List<UUID> sorted(Set<UUID> ids) {
    return ids.stream().sorted().toList();
  }

  private static Map<UUID, String> namesById(List<PermissionView> permissions) {
    Map<UUID, String> names = new HashMap<>();
    permissions.forEach(view -> names.put(view.id(), view.name()));
    return names;
  }

  /** {@code nexus.rbac.permission_replace{outcome, lockPath}}: bounded tags, no tenant tag. */
  private void countReplace(String outcome, String lockPath) {
    Counter.builder(COUNTER_PERMISSION_REPLACE)
        .tag(TAG_OUTCOME, outcome)
        .tag(TAG_LOCK_PATH, lockPath)
        .register(meterRegistry)
        .increment();
  }

  /** Stops the shared lock-hold timer with {@code operation="replace"}. */
  private void stopLockHoldTimer(Timer.Sample sample, String outcome) {
    sample.stop(
        Timer.builder(TIMER_LOCK_HOLD)
            .tag("operation", OPERATION_REPLACE)
            .tag(TAG_OUTCOME, outcome)
            .register(meterRegistry));
  }

  /**
   * Renames a custom role and/or changes its description (US-018 C1, PATCH). A {@code null} argument
   * leaves that field unchanged; an empty {@code description} clears it. Order: tenant resolution
   * (404, a deleted role is a 404), <b>role-subset</b> (403, RC-35: otherwise a {@code role:write}
   * holder could rename an administrator role to look harmless), system-role immutability (409
   * {@code RBAC_003}), the reserved-name check (409 {@code RBAC_007}, in memory, as create does), the
   * two-column {@code UPDATE} (0 rows is a 404; a name already taken among live roles is 409 {@code
   * RBAC_006}) and the atomic {@code ROLE_UPDATED} audit row.
   *
   * <p>The design lists {@code RBAC_006} before {@code RBAC_007}; this order matches create, where
   * the free in-memory reserved check precedes the database's uniqueness check (see 09-technical.md
   * M9). A request that changes nothing is a successful no-op: no write, no audit row.
   *
   * <p>A rename does not bump the permission epoch: the name is cosmetic for authorization, and
   * {@code RoleResolutionService} already re-derives role names on the next mint. The description
   * text is never logged or audited; the audit row names the changed fields and the old and new
   * name only.
   */
  @Transactional
  public RoleView updateRole(
      RoleChangeActor actor, UUID roleId, String name, String description, RequestContext ctx) {
    RoleView role = resolveRoleInTenant(roleId, actor, ROLE_WRITE, OPERATION_UPDATE);
    requireRoleSubset(actor, role, OPERATION_UPDATE);
    requireMutableRole(role);
    if (name != null && RbacRoleNames.isReserved(name)) {
      throw new ReservedRoleNameException();
    }

    boolean nameChanged = name != null && !name.equals(role.name());
    String newDescription =
        description == null ? role.description() : (description.isEmpty() ? null : description);
    boolean descriptionChanged =
        description != null && !java.util.Objects.equals(newDescription, role.description());
    if (!nameChanged && !descriptionChanged) {
      return role;
    }
    String newName = nameChanged ? name : role.name();

    if (roleManagementPort.updateRole(role.id(), actor.tenantId(), newName, newDescription) == 0) {
      throw new ResourceNotFoundException(CODE_ROLE_NOT_FOUND, MESSAGE_NO_SUCH_ROLE);
    }

    List<String> changedFields = new java.util.ArrayList<>(2);
    if (nameChanged) {
      changedFields.add("name");
    }
    if (descriptionChanged) {
      changedFields.add("description");
    }
    rbacAuditPort.recordRoleUpdated(
        new RoleUpdateAuditEvent(
            actor.tenantId(),
            role.id(),
            newName,
            nameChanged ? role.name() : null,
            nameChanged ? newName : null,
            changedFields,
            actor.userId(),
            ctx));

    RoleView updated = roleManagementPort.findRole(role.id()).orElseThrow();
    registerPostCommitSideEffects(
        () ->
            log.atInfo()
                .addKeyValue(LOG_KEY_EVENT, "ROLE_UPDATED")
                .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
                .addKeyValue(LOG_KEY_ROLE_ID, role.id())
                .addKeyValue(LOG_KEY_ROLE_NAME, updated.name())
                .addKeyValue("changedFields", changedFields)
                .addKeyValue("updatedBy", actor.userId())
                .log("Role updated"));
    return updated;
  }

  /**
   * Soft-deletes a custom role that has no active holder (US-018 C1, design §11.1). Order: tenant
   * resolution (404, a deleted role is a 404 too), <b>role-subset</b> (403, as detach, RC-35),
   * system-role immutability (409 {@code RBAC_003}), then, when the role is admin-defining, the
   * <b>set lock first</b> (M10' then M11, as assign does: RC-46 option (a), so the two cannot
   * deadlock on the role row), the single-column {@code UPDATE} that sets {@code deleted_at} (0 rows
   * is a 404), on the set-lock path the administrator-through-another-role check again from the
   * locked rows and a current {@code FOR SHARE} read of the lock set's permissions (403, RC-57.2),
   * a {@code FOR UPDATE} read of the role's active assignments (any row is 409 {@code
   * RBAC_009} and rolls the {@code UPDATE} back), and the atomic {@code ROLE_DELETED} audit row.
   *
   * <p>Together with assign's conditional INSERT this keeps the invariant "a deleted role has no
   * active holders": a concurrent assign either committed before the holder read (409 here) or finds
   * the role deleted (404 there). Because the precondition is "no active holders", no holder's
   * token or cache entry can carry the role's permissions, so no epoch bump is needed (A-17: if the
   * precondition is ever relaxed, this must call {@link
   * PermissionFreshnessService#invalidateHolders} after commit, as detach does). Role-subset denials
   * use the detach posture: WARN, the central {@code permission_denied} metric, no audit row.
   */
  @Transactional
  public void softDeleteRole(RoleChangeActor actor, UUID roleId, RequestContext ctx) {
    RoleView role = resolveRoleInTenant(roleId, actor, ROLE_WRITE, OPERATION_DELETE);
    SubsetCheck subset = requireRoleSubset(actor, role, OPERATION_DELETE);
    requireMutableRole(role);

    SetLockRows setLock =
        subset.adminDefining() ? acquireSetLock(actor, role, subset.catalogueIds()) : null;

    if (roleManagementPort.softDeleteRole(role.id(), actor.tenantId(), Instant.now()) == 0) {
      throw new ResourceNotFoundException(CODE_ROLE_NOT_FOUND, MESSAGE_NO_SUCH_ROLE);
    }

    if (setLock != null) {
      // RC-57.2 (SD-17): role-subset's "administrator through another role" again, from the locked
      // rows and a current read, after the UPDATE's role-row lock, so the new FOR SHARE follows
      // both the user_roles and the roles locks this request takes. A 403 precedes the 409 below.
      requireAdministratorThroughAnotherLockedRole(
          actor,
          role,
          setLock,
          adminDefiningNow(actor, setLock, subset.catalogueIds()),
          OPERATION_DELETE);
    }

    List<ActiveAssignmentHolder> holders =
        userRoleAssignmentPort.lockActiveAssignmentHolders(actor.tenantId(), List.of(role.id()));
    if (!holders.isEmpty()) {
      log.atInfo()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_ROLE_DELETE_REFUSED_HAS_HOLDERS")
          .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
          .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
          .addKeyValue(LOG_KEY_ROLE_ID, role.id())
          .addKeyValue(KEY_HOLDER_COUNT, holders.size())
          .log("Refused to delete a role that still has active holders");
      throw new RoleHasHoldersException();
    }

    rbacAuditPort.recordRoleDeleted(
        new RoleAuditEvent(
            actor.tenantId(), role.id(), role.name(), null, null, actor.userId(), ctx, null));

    registerPostCommitSideEffects(
        () ->
            log.atInfo()
                .addKeyValue(LOG_KEY_EVENT, "ROLE_DELETED")
                .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
                .addKeyValue(LOG_KEY_ROLE_ID, role.id())
                .addKeyValue(LOG_KEY_ROLE_NAME, role.name())
                .addKeyValue("deletedBy", actor.userId())
                .log("Role deleted"));
  }

  /**
   * The tenant's set lock (RC-46): M10' for the tenant's roles, the admin-defining ones among them,
   * then ONE statement locking every active assignment of those roles plus this role, in the
   * ascending order {@link RoleAssignmentService} uses. The caller fixes where it falls relative to
   * the role row: before it for an admin-defining role (DELETE, a demoting replace, the order
   * assign takes on an admin-defining target), after it for a promoting replace. Returns the lock
   * set's role ids and the locked rows, current and X-locked, from which a replace decides its
   * steps 10 and 11 and DELETE its locked administrator check (RC-57.2); DELETE's holder check
   * still re-reads the role's own rows after the {@code UPDATE}.
   */
  private SetLockRows acquireSetLock(RoleChangeActor actor, RoleView role, Set<UUID> catalogueIds) {
    Set<UUID> adminDefiningRoleIds =
        RoleAssignmentService.resolveAdminDefiningRoleIds(
            userRoleAssignmentPort, actor.tenantId(), catalogueIds);
    List<UUID> lockSet =
        RoleAssignmentService.buildAscendingLockSet(adminDefiningRoleIds, role.id());
    return new SetLockRows(
        lockSet, userRoleAssignmentPort.lockActiveAssignmentHolders(actor.tenantId(), lockSet));
  }

  /** What the set lock locked: the lock set's role ids and their active assignment rows. */
  private record SetLockRows(List<UUID> roleIds, List<ActiveAssignmentHolder> holders) {}

  /** AC6. Global catalogue, no tenant scoping — {@code permissions} has no {@code tenant_id} column. */
  @Transactional(readOnly = true)
  public PageResult<PermissionView> listAllPermissions(int page, int size) {
    return roleManagementPort.findAllPermissions(page, size);
  }

  /**
   * AC8 tenant-isolation check: empty or another tenant's role ⇒ the same 404 {@code
   * ROLE_NOT_FOUND} (US-018 B1). A cross-tenant id also emits the WARN {@code
   * RBAC_CROSS_TENANT_TARGET} and the {@code permission_denied} counter, and writes no audit row.
   */
  private RoleView resolveRoleInTenant(
      UUID roleId, RoleChangeActor actor, String requiredPermission, String operation) {
    RoleView view =
        roleManagementPort
            .findRole(roleId)
            .orElseThrow(() -> new ResourceNotFoundException(CODE_ROLE_NOT_FOUND, MESSAGE_NO_SUCH_ROLE));
    if (!view.tenantId().equals(actor.tenantId())) {
      log.atWarn()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_CROSS_TENANT_TARGET")
          .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
          .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
          .addKeyValue("targetKind", "role")
          .addKeyValue("operation", operation)
          .log("Refused a role change: the target belongs to another tenant");
      Counter.builder(COUNTER_PERMISSION_DENIED)
          .tag(TAG_PERMISSION, requiredPermission)
          .tag(TAG_REASON, DenialReason.CROSS_TENANT_TARGET.name())
          .register(meterRegistry)
          .increment();
      throw new ResourceNotFoundException(CODE_ROLE_NOT_FOUND, MESSAGE_NO_SUCH_ROLE);
    }
    return view;
  }

  /** AC7: system roles (TENANT_ADMIN and MEMBER, RC-5b) are immutable through this API. */
  private void requireMutableRole(RoleView view) {
    if (view.systemRole()) {
      log.atWarn()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_SYSTEM_ROLE_MUTATION_BLOCKED")
          .addKeyValue(LOG_KEY_TENANT_ID, view.tenantId())
          .addKeyValue(LOG_KEY_ROLE_ID, view.id())
          .addKeyValue(LOG_KEY_ROLE_NAME, view.name())
          .log("Blocked write against a system role");
      throw new SystemRoleImmutableException();
    }
  }

  /**
   * US-018 A3 (FR-A3.a, ADR-0021 D2): the caller may attach {@code permissionId} only if they hold
   * it through an active assignment in their tenant. One M13 read — the grant-subset authorization
   * read, never a JWT claim or any other read; a read failure propagates and is never treated as "allow".
   * Denial is WARN {@code RBAC_ATTACH_EXCEEDS_CALLER} (ids only) plus a 403 whose {@code
   * nexus.rbac.permission_denied} series is incremented centrally by the exception handler. Like
   * the AC11 gate, it writes <b>no</b> audit row: {@code ROLE_ASSIGNMENT_DENIED}'s contracted scope
   * is role assignment, not attach (Decision 7).
   *
   * <p>07-security-review.md L-1: the same M13 rows must also still contain the endpoint
   * permission {@code role:write} (by its seeded id), since {@code @RequiresPermission} read it
   * from a JWT that may predate a revoke. Missing is a 403 {@code PERMISSION_ABSENT} with WARN
   * {@code RBAC_ENDPOINT_PERMISSION_NOT_HELD} (ids only), checked first, no extra read, and no
   * audit row for the same Decision 7 reason.
   */
  private List<RolePermissionRef> requireCallerHoldsPermission(
      RoleChangeActor actor, RoleView role, UUID permissionId) {
    List<RolePermissionRef> heldRolePermissions =
        userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(
            actor.userId(), actor.tenantId());
    boolean stillHoldsRoleWrite =
        heldRolePermissions.stream()
            .anyMatch(ref -> RbacSeededPermissionIds.ROLE_WRITE.equals(ref.permissionId()));
    if (!stillHoldsRoleWrite) {
      log.atWarn()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_ENDPOINT_PERMISSION_NOT_HELD")
          .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
          .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
          .addKeyValue(LOG_KEY_ROLE_ID, role.id())
          .addKeyValue(LOG_KEY_PERMISSION_ID, permissionId)
          .log("Blocked attach by a caller whose live holdings lack the endpoint permission");
      throw new InsufficientPermissionException(ROLE_WRITE, DenialReason.PERMISSION_ABSENT);
    }
    boolean held =
        heldRolePermissions.stream().anyMatch(ref -> ref.permissionId().equals(permissionId));
    if (!held) {
      log.atWarn()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_ATTACH_EXCEEDS_CALLER")
          .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
          .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
          .addKeyValue(LOG_KEY_ROLE_ID, role.id())
          .addKeyValue(LOG_KEY_PERMISSION_ID, permissionId)
          .log("Blocked attach of a permission the caller does not hold");
      throw new InsufficientPermissionException(ROLE_WRITE, DenialReason.GRANT_EXCEEDS_CALLER);
    }
    return heldRolePermissions;
  }

  /**
   * Role-subset (ADR-0021 D5, design §5.1 row 12): the caller must hold every permission of the
   * role (M13's union is a superset of M14), and when the role is admin-defining the caller must
   * also be an administrator through a role OTHER than this one (M13's per-role sets), so no single
   * detach removes the last administrator status the caller relies on. A union-holder therefore
   * cannot demote an administrator role. Fails closed: a read failure propagates, an empty M14
   * {@code Optional} (the role is not in the caller's tenant, unreachable after {@link
   * #resolveRoleInTenant}) denies.
   *
   * <p>Failure is 403 {@code RBAC_001} with {@code GRANT_EXCEEDS_CALLER} (the handler counts it as
   * {@code permission_denied{permission="role:write"}}), WARN {@code RBAC_ROLE_SUBSET_DENIED} (ids
   * only, A-14) and no audit row, matching A3's posture (Decision 7). The concurrent race, where two
   * detaches each see the other role in their snapshot, is RES-28 and is detected by the zero-admin
   * health indicator.
   */
  private SubsetCheck requireRoleSubset(RoleChangeActor actor, RoleView role, String operation) {
    List<RolePermissionRef> held =
        userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(
            actor.userId(), actor.tenantId());
    Set<UUID> rolePermissionIds =
        userRoleAssignmentPort
            .findPermissionIdsForRole(role.id(), actor.tenantId())
            .orElse(null);
    boolean allowed = false;
    boolean adminDefining = false;
    Set<UUID> catalogueIds = Set.of();
    if (rolePermissionIds != null) {
      Set<UUID> heldPermissionIds = new HashSet<>();
      held.forEach(ref -> heldPermissionIds.add(ref.permissionId()));
      catalogueIds = userRoleAssignmentPort.findCatalogueIds();
      allowed = heldPermissionIds.containsAll(rolePermissionIds);
      adminDefining = RbacAdministrators.isAdminDefining(rolePermissionIds, catalogueIds);
      if (allowed && adminDefining) {
        List<RolePermissionRef> heldThroughOtherRoles =
            held.stream().filter(ref -> !ref.roleId().equals(role.id())).toList();
        allowed = RbacAdministrators.isAdministrator(heldThroughOtherRoles, catalogueIds);
      }
    }
    if (allowed) {
      return new SubsetCheck(adminDefining, catalogueIds);
    }
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, EVENT_SUBSET_DENIED)
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_ROLE_ID, role.id())
        .addKeyValue("operation", operation)
        .log("Blocked a role definition change by a caller who does not hold the role's permissions");
    throw new InsufficientPermissionException(ROLE_WRITE, DenialReason.GRANT_EXCEEDS_CALLER);
  }

  /**
   * What a passed role-subset check learned about the role, so a caller that needs the
   * classification (DELETE, for the set lock) does not read M14 and M15 a second time.
   */
  private record SubsetCheck(boolean adminDefining, Set<UUID> catalogueIds) {}

  /**
   * Whether attaching {@code permissionId} would make {@code role} admin-defining: it is NOT
   * admin-defining now and its permission ids plus the attached one cover the catalogue (RC-50(a)).
   * M14 and M15, non-locking. Fails closed on an empty M14 {@code Optional} (the role is not in the
   * caller's tenant, unreachable after {@link #resolveRoleInTenant}).
   */
  private boolean attachWouldMakeRoleAdminDefining(
      RoleChangeActor actor, RoleView role, UUID permissionId, Set<UUID> catalogueIds) {
    Set<UUID> rolePermissionIds =
        userRoleAssignmentPort
            .findPermissionIdsForRole(role.id(), actor.tenantId())
            .orElseThrow(
                () -> new ResourceNotFoundException(CODE_ROLE_NOT_FOUND, MESSAGE_NO_SUCH_ROLE));
    if (RbacAdministrators.isAdminDefining(rolePermissionIds, catalogueIds)) {
      return false;
    }
    Set<UUID> afterAttach = new HashSet<>(rolePermissionIds);
    afterAttach.add(permissionId);
    return RbacAdministrators.isAdminDefining(afterAttach, catalogueIds);
  }

  /**
   * RC-56.3, after the insert and under R's row lock: the current {@code FOR SHARE} read of R's
   * permissions (the committed rows plus this insert). If they now cover the catalogue while the
   * snapshot said this attach would not complete it ({@code becameAdminDefining} false), another
   * change committed while this attach waited on the row and the provenance rule never ran: 409
   * {@code RBAC_012}, which rolls the insert back before the audit. The retry's snapshot sees the
   * completion, so {@code RBAC_010} applies to it.
   */
  private void requireAttachKeptItsClassification(
      RoleChangeActor actor,
      RoleView role,
      UUID permissionId,
      boolean becameAdminDefining,
      Set<UUID> catalogueIds) {
    Set<UUID> current = roleManagementPort.lockPermissionIdsForRole(role.id());
    if (becameAdminDefining || !RbacAdministrators.isAdminDefining(current, catalogueIds)) {
      return;
    }
    log.atInfo()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_ROLE_CLASSIFICATION_CHANGED")
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_ROLE_ID, role.id())
        .addKeyValue(LOG_KEY_PERMISSION_ID, permissionId)
        .addKeyValue("operation", OPERATION_ATTACH)
        .log("Rolled back an attach: the role became admin-defining while the attach waited");
    Counter.builder(COUNTER_ROLE_CLASSIFICATION_CHANGED)
        .tag("operation", OPERATION_ATTACH)
        .register(meterRegistry)
        .increment();
    throw new RoleClassificationChangedException();
  }

  /**
   * The narrow provenance rule's check (row 14, R1-1): 409 {@code RBAC_010} if the role has an
   * active holder whose {@code assigned_by} is not currently an administrator. Two non-locking
   * reads, only on the branch where the attach completes the catalogue. A break-glass grant
   * ({@code assigned_by} equals the target, who is an administrator) never trips it. WARN {@code
   * RBAC_ATTACH_PROVENANCE_REFUSED} (ids and a count) and {@code
   * permission_denied{permission="role:write", reason="ATTACH_PROVENANCE"}}; no audit row, matching
   * A3's posture. The exception's detail names no holder.
   */
  private void requireNoNonAdministratorAssignedHolder(
      RoleChangeActor actor, RoleView role, UUID permissionId) {
    List<HolderProvenance> holders =
        userRoleAssignmentPort.findActiveHoldersForRole(role.id(), actor.tenantId());
    int nonAdminAssignedCount = countAssignedByNonAdministrators(actor.tenantId(), holders);
    if (nonAdminAssignedCount == 0) {
      return;
    }
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_ATTACH_PROVENANCE_REFUSED")
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_ROLE_ID, role.id())
        .addKeyValue(LOG_KEY_PERMISSION_ID, permissionId)
        .addKeyValue(KEY_NON_ADMIN_ASSIGNED_COUNT, nonAdminAssignedCount)
        .log("Refused an attach that would make a role admin-defining while some of its holders "
            + "were assigned by a non-administrator");
    Counter.builder(COUNTER_PERMISSION_DENIED)
        .tag(TAG_PERMISSION, ROLE_WRITE)
        .tag(TAG_REASON, REASON_ATTACH_PROVENANCE)
        .register(meterRegistry)
        .increment();
    throw new AttachProvenanceConflictException();
  }

  /**
   * US-019 review R1-1: the provenance rule again, under locks, for an attach that completes the
   * catalogue. The pre-lock check reads the transaction's REPEATABLE READ snapshot, so an assign
   * by a non-administrator that committed while this attach waited for R's row is invisible to
   * it. After the role-row lock, this takes the set lock (RC-46 promotion order: roles, then
   * {@code user_roles}), classifies from the current {@code FOR SHARE} read and judges the locked
   * holders, exactly as a promoting replace does. R's row X lock keeps any assign (it needs S on
   * the row) from adding a holder after this point, so the locked read is final.
   */
  private void requireNoLockedNonAdministratorAssignedHolder(
      RoleChangeActor actor, RoleView role, Set<UUID> catalogueIds) {
    SetLockRows setLock = acquireSetLock(actor, role, catalogueIds);
    requireNoLockedHolderAssignedByNonAdministrator(
        actor, role, setLock, adminDefiningNow(actor, setLock, catalogueIds), OPERATION_ATTACH);
  }

  /**
   * How many of {@code holders} were assigned by a user who is not currently an administrator of
   * the tenant: one read of the administrator user set (the holders of the tenant's admin-defining
   * roles, from M10' and the catalogue). With no holders there is nothing to compare and nothing
   * is read.
   */
  private int countAssignedByNonAdministrators(UUID tenantId, List<HolderProvenance> holders) {
    if (holders.isEmpty()) {
      return 0;
    }
    return countAssignedByNonAdministrators(
        tenantId, holders, tenantAdminDefiningRoleIds(tenantId));
  }

  private int countAssignedByNonAdministrators(
      UUID tenantId, List<HolderProvenance> holders, Set<UUID> adminDefiningRoleIds) {
    Set<UUID> administratorUserIds =
        userRoleAssignmentPort.findActiveHolderUserIdsForRoles(tenantId, adminDefiningRoleIds);
    return (int)
        holders.stream().filter(h -> !administratorUserIds.contains(h.assignedBy())).count();
  }

  /** The tenant's admin-defining role ids, from M10' and the catalogue (both non-locking). */
  private Set<UUID> tenantAdminDefiningRoleIds(UUID tenantId) {
    return RbacAdministrators.adminDefiningRoleIds(
        userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId),
        userRoleAssignmentPort.findCatalogueIds());
  }

  /**
   * What the after-commit attach read saw: the role's holders, how many of them were assigned by a
   * non-administrator, and whether the role itself is admin-defining (from the same M10' read; only
   * known, and only needed, when there are holders).
   */
  private record AttachSnapshot(
      List<HolderProvenance> holders, int nonAdminAssignedCount, boolean roleAdminDefining) {}

  /**
   * The after-commit read of an attach, in a read-only transaction of its own: the role's active
   * holders with their assigners (the A10 holder read, extended) and the count of those assigned by
   * a non-administrator (one more read of the administrator user set, skipped when there are no
   * holders). The committed-state detector (RC-56.4) reuses it and adds no statement.
   */
  private AttachSnapshot readAttachSnapshot(UUID tenantId, UUID roleId) {
    List<HolderProvenance> holders =
        userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId);
    if (holders.isEmpty()) {
      return new AttachSnapshot(holders, 0, false);
    }
    Set<UUID> adminDefiningRoleIds = tenantAdminDefiningRoleIds(tenantId);
    return new AttachSnapshot(
        holders,
        countAssignedByNonAdministrators(tenantId, holders, adminDefiningRoleIds),
        adminDefiningRoleIds.contains(roleId));
  }

  /** RC-56.4 after an attach or a replace that added permissions, from the attach read. */
  private void detectNonAdministratorAssignedHolder(
      UUID tenantId, UUID roleId, Optional<AttachSnapshot> snapshot) {
    snapshot.ifPresent(
        read ->
            AdminDefiningRoleProvenanceDetector.check(
                meterRegistry,
                tenantId,
                roleId,
                read.roleAdminDefining(),
                read.holders().size(),
                read.nonAdminAssignedCount()));
  }

  /**
   * Rows 13 and 14, after commit, for the permission ids an attach (one) or a replace (its adds)
   * added. <b>Row 13:</b> when at least one active holder of the role was
   * assigned by a non-administrator, WARN {@code RBAC_ATTACH_ESCALATES_NON_ADMIN_ASSIGNED_HOLDERS}
   * and {@code nexus.rbac.attach_escalates_non_admin_assigned{holders, page}} ({@code holders}
   * bucketed, no tenant tag). It is a ticket; {@code page} is {@code true} when an added
   * permission is {@code user:role:assign} or {@code role:write}, or the change made the role
   * admin-defining (A-15). One added id is logged as {@code permissionId}, several as {@code
   * permissionIds}. <b>Row 14:</b> when the attach made the role admin-defining, WARN {@code
   * RBAC_ROLE_BECAME_ADMIN_DEFINING} and {@code nexus.rbac.role_became_admin_defining{holders}},
   * paged when {@code holders} is not {@code "0"}. If the read failed, row 14 still fires with
   * {@code holders="unknown"}, which pages: the failure mode of the signal is to alert.
   */
  private void emitAttachSignals(
      RoleChangeActor actor,
      RoleView role,
      List<UUID> addedPermissionIds,
      boolean becameAdminDefining,
      Optional<AttachSnapshot> snapshot) {
    snapshot.ifPresent(
        read -> {
          int holderCount = read.holders().size();
          if (read.nonAdminAssignedCount() > 0) {
            boolean page =
                becameAdminDefining
                    || addedPermissionIds.contains(RbacSeededPermissionIds.USER_ROLE_ASSIGN)
                    || addedPermissionIds.contains(RbacSeededPermissionIds.ROLE_WRITE);
            log.atWarn()
                .addKeyValue(
                    LOG_KEY_EVENT, "RBAC_ATTACH_ESCALATES_NON_ADMIN_ASSIGNED_HOLDERS")
                .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
                .addKeyValue(LOG_KEY_ROLE_ID, role.id())
                .addKeyValue(
                    addedPermissionIds.size() == 1 ? LOG_KEY_PERMISSION_ID : "permissionIds",
                    addedPermissionIds.size() == 1 ? addedPermissionIds.get(0) : addedPermissionIds)
                .addKeyValue(KEY_HOLDER_COUNT, holderCount)
                .addKeyValue(KEY_NON_ADMIN_ASSIGNED_COUNT, read.nonAdminAssignedCount())
                .log("Permission attached to a role with holders assigned by a non-administrator");
            Counter.builder(COUNTER_ATTACH_ESCALATES)
                .tag(TAG_HOLDERS, holderCountBucket(holderCount))
                .tag("page", Boolean.toString(page))
                .register(meterRegistry)
                .increment();
          }
        });
    if (!becameAdminDefining) {
      return;
    }
    String bucket = snapshot.map(read -> holderCountBucket(read.holders().size())).orElse(HOLDERS_UNKNOWN);
    var warn =
        log.atWarn()
            .addKeyValue(LOG_KEY_EVENT, "RBAC_ROLE_BECAME_ADMIN_DEFINING")
            .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
            .addKeyValue(LOG_KEY_ROLE_ID, role.id())
            .addKeyValue("grantedBy", actor.userId());
    if (snapshot.isPresent()) {
      warn = warn.addKeyValue(KEY_HOLDER_COUNT, snapshot.get().holders().size());
    }
    warn.log("Role became admin-defining");
    Counter.builder(COUNTER_ROLE_BECAME_ADMIN_DEFINING)
        .tag(TAG_HOLDERS, bucket)
        .register(meterRegistry)
        .increment();
  }

  /**
   * Bucket for the {@code holders} tag of the attach signals: bounded cardinality (four values),
   * never the raw count, which is unbounded (03-design.md §9.4).
   */
  private static String holderCountBucket(int holderCount) {
    if (holderCount == 0) {
      return "0";
    }
    if (holderCount == 1) {
      return "1";
    }
    if (holderCount <= 10) {
      return "2-10";
    }
    return ">10";
  }

  /**
   * Runs a holder read from an afterCommit callback, in a new read-only transaction that ends
   * before the caller touches Redis. While it runs the request briefly holds two pooled
   * connections: the committed transaction's, still bound until afterCompletion, and this one's.
   *
   * <p>A read for a change that revokes ({@code revocation}: a detach, or a replace that removes)
   * is retried once, because a failure there loses a revocation (M-2): the likeliest
   * cause is a pool timeout that has cleared a moment later. If the retry fails too, {@link
   * PermissionFreshnessService#holderReadFailed} pages ({@code
   * nexus.rbac.epoch.bump_failed{operation=detach, reason=holder_read}}) and queues the role: the
   * scheduler tick reads the holders again and bumps them (M7 part 2 review M-2). An attach read is
   * not retried and not queued: a missed eviction is fail-safe, and the escalation signals fail
   * toward alerting (see {@link #emitAttachSignals}).
   */
  private <T> Optional<T> readAfterCommit(
      UUID tenantId, UUID roleId, String operation, boolean revocation, Supplier<T> read) {
    RuntimeException failure = null;
    for (int attempt = 0; attempt < (revocation ? 2 : 1); attempt++) {
      try {
        return Optional.ofNullable(holderReadTransaction.execute(status -> read.get()));
      } catch (RuntimeException e) {
        failure = e;
      }
    }
    // The change has committed: rethrowing from afterCommit would turn the administrator's
    // success into a 500 and still leave every holder's token and cache entry in place.
    log.atError()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_HOLDER_READ_FAILED")
        .addKeyValue("operation", operation)
        .addKeyValue(LOG_KEY_TENANT_ID, tenantId)
        .addKeyValue(LOG_KEY_ROLE_ID, roleId)
        .addKeyValue("exception", failure.getClass().getSimpleName())
        .log("Reading role holders after commit failed; permission freshness not applied");
    if (revocation) {
      permissionFreshnessService.holderReadFailed(tenantId, roleId, operation);
    }
    return Optional.empty();
  }

  /**
   * Runs {@code sideEffects} (audit + log) after the enclosing transaction commits. Identical
   * fallback to {@link RoleAssignmentService#registerPostCommitSideEffects}: if no transaction
   * synchronization is active, {@code sideEffects} runs inline instead of being silently dropped
   * — the only way a plain unit test can observe these side effects firing.
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
