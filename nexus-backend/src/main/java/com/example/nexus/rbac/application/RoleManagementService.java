package com.example.nexus.rbac.application;

import static com.example.nexus.common.security.Permissions.ROLE_READ;
import static com.example.nexus.common.security.Permissions.ROLE_WRITE;

import com.example.nexus.common.domain.ConflictException;
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

  private static final String COUNTER_PERMISSION_REPLACE = "nexus.rbac.permission_replace";
  private static final String TAG_OUTCOME = "outcome";
  private static final String TAG_LOCK_PATH = "lockPath";
  private static final String LOCK_PATH_NONE = "none";
  private static final String LOCK_PATH_ROLE_ROW = "role_row";
  private static final String OUTCOME_REPLACED = "replaced";
  private static final String OUTCOME_NOOP = "noop";
  private static final String OUTCOME_PRECONDITION_FAILED = "precondition_failed";
  private static final String OUTCOME_ERROR = "error";
  // The set-lock hold timer of RoleAssignmentService; B8 adds operation="replace" (design §10.8).
  private static final String TIMER_LOCK_HOLD = "nexus.rbac.privileged_revoke_lock_hold";

  /**
   * US-019 T-018 interim guard, removed by T-019 (which ships in the same PR, A-7, O-3): a replace
   * whose before or after state is admin-defining needs the set-lock path, which T-019 adds. Until
   * then such a change is refused with this code, after authorization and before any lock.
   */
  static final String INTERIM_SET_LOCK_PATH_GUARD_CODE = "RBAC_REPLACE_SET_LOCK_PATH_PENDING";

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
   * RBAC_005}), the insert. A3 sits before the duplicate check so a denied caller learns nothing
   * about attachment state.
   *
   * <p><b>Provenance rule (design §5.6, R1-1).</b> If the role is not admin-defining now and its
   * permissions plus the attached one cover the catalogue, the role would turn every holder into an
   * administrator. If any active holder was assigned by someone who is not currently an
   * administrator, the attach is refused: otherwise a second account could be promoted by an
   * unwitting administrator (RES-26). A role that is already admin-defining does not match, so its
   * duplicate attach still gets {@code RBAC_005}. Partial escalations stay detective, see the
   * signals below. The only extra reads are on the rare branch where the attach completes the
   * catalogue, and they are non-locking.
   *
   * <p><b>PII grant rule (US-019 §4.8, RC-60.3).</b> Right after A3 (RC-66.1) and before the
   * provenance rule and the duplicate check: attaching {@code user:directory:read} requires the
   * caller to be an administrator by A3's own M13 rows and the catalogue. A denial is 403 {@code
   * NOT_TENANT_ADMIN} with WARN {@code RBAC_PII_PERMISSION_GRANT_DENIED} and no audit row (Decision
   * 7). With the rule switched off, a non-administrator's attach is reported after commit (RC-60.2).
   *
   * <p><b>Signals (rows 13 and 14).</b> After commit, from one holder read, a WARN and a counter
   * report an attach that escalates holders assigned by non-administrators, and a second pair
   * reports that the role became admin-defining. See {@link #emitAttachSignals}.
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

    boolean becameAdminDefining = attachWouldMakeRoleAdminDefining(actor, role, permissionId);
    if (becameAdminDefining) {
      requireNoNonAdministratorAssignedHolder(actor, role, permissionId);
    }

    if (roleManagementPort.hasPermission(role.id(), permissionId)) {
      throw new DuplicateRolePermissionException();
    }
    roleManagementPort.attachPermission(role.id(), permissionId);

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
   * set the server authorises against (design §10.3, role-row path). Steps:
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
   *   <li>8-9, <b>locks only after authorization</b> (T-D27): the role row {@code FOR UPDATE}
   *       (404 if it is gone), then the current read of the role's {@code role_permissions}
   *       {@code FOR SHARE}; its version {@code v1} must equal {@code v0}, never merely something
   *       the client sent (RC-55.1, T-T22), or the PUT is 412. Equal versions mean the locked
   *       state is the one steps 5-7 classified and authorised.
   *   <li>12-13: one bulk delete of the removes (its row count must equal their number), the
   *       inserts, and one inline Group A audit row per change with {@code operation=REPLACE} and
   *       one server-generated {@code replaceId}.
   *   <li>14-15, after commit: removes bump every holder's epoch once, otherwise adds evict the
   *       holders' cache once; the attach signals for the added set; INFO {@code
   *       RBAC_PERMISSION_SET_REPLACED}. Returns the new set and its version.
   * </ol>
   *
   * <p>Interim (T-018): a change whose before or after state is admin-defining is refused after
   * step 7 by {@link #INTERIM_SET_LOCK_PATH_GUARD_CODE}; T-019 replaces the guard with the set-lock
   * path.
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
            .orElseThrow(() -> new ResourceNotFoundException("ROLE_NOT_FOUND", "No such role"));
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
    refuseSetLockPathUntilSupported(actor, role, before, after);

    if (!roleManagementPort.lockRoleRow(role.id(), actor.tenantId())) {
      throw new ResourceNotFoundException("ROLE_NOT_FOUND", "No such role");
    }
    Timer.Sample lockHold = Timer.start(meterRegistry);
    try {
      return replaceUnderRoleRowLock(
          actor, role, target, adds, removes, snapshotVersion, piiGrant, lockHold, ctx);
    } catch (PreconditionFailedException e) {
      stopLockHoldTimer(lockHold, OUTCOME_PRECONDITION_FAILED);
      throw e;
    } catch (RuntimeException e) {
      stopLockHoldTimer(lockHold, OUTCOME_ERROR);
      throw e;
    }
  }

  /** Steps 9 to 15 of {@link #replaceRolePermissions}, with the role row already X-locked. */
  private RolePermissionSet replaceUnderRoleRowLock(
      RoleChangeActor actor,
      RoleView role,
      Set<UUID> target,
      Set<UUID> adds,
      Set<UUID> removes,
      String snapshotVersion,
      PiiPermissionGrantRule.Outcome piiGrant,
      Timer.Sample lockHold,
      RequestContext ctx) {
    Set<UUID> current = roleManagementPort.lockPermissionIdsForRole(role.id());
    if (!RolePermissionSetVersion.of(role.id(), current).equals(snapshotVersion)) {
      countReplace(OUTCOME_PRECONDITION_FAILED, LOCK_PATH_ROLE_ROW);
      throw new PreconditionFailedException();
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
          countReplace(OUTCOME_REPLACED, LOCK_PATH_ROLE_ROW);
          log.atInfo()
              .addKeyValue(LOG_KEY_EVENT, "RBAC_PERMISSION_SET_REPLACED")
              .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
              .addKeyValue(LOG_KEY_ROLE_ID, role.id())
              .addKeyValue("replaceId", replaceId)
              .addKeyValue("addedCount", adds.size())
              .addKeyValue("removedCount", removes.size())
              .addKeyValue("lockPath", LOCK_PATH_ROLE_ROW)
              .addKeyValue("replacedBy", actor.userId())
              .log("Role permission set replaced");
          if (piiGrant == PiiPermissionGrantRule.Outcome.DELEGATED) {
            piiGrantRule.recordDelegated(actor.tenantId(), actor.userId(), role.id(), null);
          }
          applyReplaceFreshness(actor, role, adds, removes);
        });

    return new RolePermissionSet(
        role.id(), permissions, RolePermissionSetVersion.of(role.id(), target));
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
            .addKeyValue(LOG_KEY_EVENT, "RBAC_ROLE_SUBSET_DENIED")
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

  /** The interim T-018 guard (see {@link #INTERIM_SET_LOCK_PATH_GUARD_CODE}). */
  private void refuseSetLockPathUntilSupported(
      RoleChangeActor actor,
      RoleView role,
      boolean adminDefiningBefore,
      boolean adminDefiningAfter) {
    if (!adminDefiningBefore && !adminDefiningAfter) {
      return;
    }
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_REPLACE_ADMIN_DEFINING_REFUSED")
        .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
        .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
        .addKeyValue(LOG_KEY_ROLE_ID, role.id())
        .log("Refused a permission-set replace that needs the set-lock path");
    throw new ConflictException(
        INTERIM_SET_LOCK_PATH_GUARD_CODE,
        "Replacing the permissions of an administrator role is not available yet.");
  }

  /**
   * Step 14 of {@link #replaceRolePermissions}, after commit, from one holder read in its own
   * transaction. Removes revoke, so the holders' epochs are bumped once (which also leaves their
   * old-epoch cache entries unreachable) and a failed read is retried and queued as detach's is;
   * adds alone evict the holders' cache once. The attach signals are derived once for the added
   * set.
   */
  private void applyReplaceFreshness(
      RoleChangeActor actor, RoleView role, Set<UUID> adds, Set<UUID> removes) {
    boolean revokes = !removes.isEmpty();
    if (adds.isEmpty()) {
      readAfterCommit(
              actor.tenantId(),
              role.id(),
              OPERATION_REPLACE,
              true,
              () -> userRoleAssignmentPort.findActiveUserIdsForRole(role.id()))
          .ifPresent(
              holders ->
                  permissionFreshnessService.invalidateHolders(
                      actor.tenantId(), holders, OPERATION_REPLACE));
      return;
    }
    Optional<AttachSnapshot> snapshot =
        readAfterCommit(
            actor.tenantId(),
            role.id(),
            OPERATION_REPLACE,
            revokes,
            () -> readAttachSnapshot(actor.tenantId(), role.id()));
    emitAttachSignals(actor, role, sorted(adds), false, snapshot);
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
      throw new ResourceNotFoundException("ROLE_NOT_FOUND", "No such role");
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
   * is a 404), a {@code FOR UPDATE} read of the role's active assignments (any row is 409 {@code
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

    if (subset.adminDefining()) {
      acquireSetLockBeforeRoleRow(actor, role, subset.catalogueIds());
    }

    if (roleManagementPort.softDeleteRole(role.id(), actor.tenantId(), Instant.now()) == 0) {
      throw new ResourceNotFoundException("ROLE_NOT_FOUND", "No such role");
    }

    List<ActiveAssignmentHolder> holders =
        userRoleAssignmentPort.lockActiveAssignmentHolders(actor.tenantId(), List.of(role.id()));
    if (!holders.isEmpty()) {
      log.atInfo()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_ROLE_DELETE_REFUSED_HAS_HOLDERS")
          .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
          .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
          .addKeyValue(LOG_KEY_ROLE_ID, role.id())
          .addKeyValue("holderCount", holders.size())
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
   * The set lock for DELETE of an admin-defining role (RC-46 option (a)): M10' for the tenant's
   * roles, the admin-defining ones among them, then ONE statement locking every active assignment
   * of those roles plus this role, in the ascending order {@link RoleAssignmentService} uses. It
   * runs before the role row is touched, the order assign takes on an admin-defining target. The
   * rows it returns are not used: the holder check re-reads the role's own rows after the {@code
   * UPDATE}.
   */
  private void acquireSetLockBeforeRoleRow(
      RoleChangeActor actor, RoleView role, Set<UUID> catalogueIds) {
    Set<UUID> adminDefiningRoleIds =
        RoleAssignmentService.resolveAdminDefiningRoleIds(
            userRoleAssignmentPort, actor.tenantId(), catalogueIds);
    userRoleAssignmentPort.lockActiveAssignmentHolders(
        actor.tenantId(), RoleAssignmentService.buildAscendingLockSet(adminDefiningRoleIds, role.id()));
  }

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
            .orElseThrow(() -> new ResourceNotFoundException("ROLE_NOT_FOUND", "No such role"));
    if (!view.tenantId().equals(actor.tenantId())) {
      log.atWarn()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_CROSS_TENANT_TARGET")
          .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
          .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
          .addKeyValue("targetKind", "role")
          .addKeyValue("operation", operation)
          .log("Refused a role change: the target belongs to another tenant");
      Counter.builder(COUNTER_PERMISSION_DENIED)
          .tag("permission", requiredPermission)
          .tag("reason", DenialReason.CROSS_TENANT_TARGET.name())
          .register(meterRegistry)
          .increment();
      throw new ResourceNotFoundException("ROLE_NOT_FOUND", "No such role");
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
        .addKeyValue(LOG_KEY_EVENT, "RBAC_ROLE_SUBSET_DENIED")
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
      RoleChangeActor actor, RoleView role, UUID permissionId) {
    Set<UUID> rolePermissionIds =
        userRoleAssignmentPort
            .findPermissionIdsForRole(role.id(), actor.tenantId())
            .orElseThrow(
                () -> new ResourceNotFoundException("ROLE_NOT_FOUND", "No such role"));
    Set<UUID> catalogueIds = userRoleAssignmentPort.findCatalogueIds();
    if (RbacAdministrators.isAdminDefining(rolePermissionIds, catalogueIds)) {
      return false;
    }
    Set<UUID> afterAttach = new HashSet<>(rolePermissionIds);
    afterAttach.add(permissionId);
    return RbacAdministrators.isAdminDefining(afterAttach, catalogueIds);
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
        .addKeyValue("nonAdminAssignedCount", nonAdminAssignedCount)
        .log("Refused an attach that would make a role admin-defining while some of its holders "
            + "were assigned by a non-administrator");
    Counter.builder(COUNTER_PERMISSION_DENIED)
        .tag("permission", ROLE_WRITE)
        .tag("reason", REASON_ATTACH_PROVENANCE)
        .register(meterRegistry)
        .increment();
    throw new AttachProvenanceConflictException();
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
    Set<UUID> adminDefiningRoleIds =
        RbacAdministrators.adminDefiningRoleIds(
            userRoleAssignmentPort.findRolePermissionIdsForTenantRoles(tenantId),
            userRoleAssignmentPort.findCatalogueIds());
    Set<UUID> administratorUserIds =
        userRoleAssignmentPort.findActiveHolderUserIdsForRoles(tenantId, adminDefiningRoleIds);
    return (int)
        holders.stream().filter(h -> !administratorUserIds.contains(h.assignedBy())).count();
  }

  /** What the after-commit attach read saw: the role's holders and the tenant's administrators. */
  private record AttachSnapshot(List<HolderProvenance> holders, int nonAdminAssignedCount) {}

  /**
   * The after-commit read of an attach, in a read-only transaction of its own: the role's active
   * holders with their assigners (the A10 holder read, extended) and the count of those assigned by
   * a non-administrator (one more read of the administrator user set, skipped when there are no
   * holders).
   */
  private AttachSnapshot readAttachSnapshot(UUID tenantId, UUID roleId) {
    List<HolderProvenance> holders =
        userRoleAssignmentPort.findActiveHoldersForRole(roleId, tenantId);
    return new AttachSnapshot(holders, countAssignedByNonAdministrators(tenantId, holders));
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
                .addKeyValue("holderCount", holderCount)
                .addKeyValue("nonAdminAssignedCount", read.nonAdminAssignedCount())
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
      warn = warn.addKeyValue("holderCount", snapshot.get().holders().size());
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
