package com.example.nexus.rbac.application;

import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlertPort;
import com.example.nexus.rbac.application.port.out.BreakGlassAuditEvent;
import com.example.nexus.rbac.application.port.out.BreakGlassGrantLookupPort;
import com.example.nexus.rbac.application.port.out.DirectoryUser;
import com.example.nexus.rbac.application.port.out.DirectoryUserStatus;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.RbacAdministrators;
import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.domain.Role;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * US-018 A7 (03-design.md §7.1, §7.2): grants the first administrator of a tenant that has none.
 * Reachable only from {@code rbac.interfaces.cli} (ArchUnit-enforced, EC2) and never through
 * {@link RoleAssignmentService#assign}: break-glass has no caller to authorize.
 *
 * <p><b>Order.</b> {@link #grantFirstAdmin} is a non-transactional orchestrator: the replay lookup
 * (exit 6) and the target lookup (exit 3) run first, outside any transaction; then one grant
 * transaction ({@link TransactionTemplate}, {@code REQUIRED}) resolves the role (exit 4), takes
 * the set lock, reads the statuses under it, re-checks that the target is ACTIVE (exit 3, L-2),
 * checks for an administrator (exit 5), inserts and writes SUCCESS (exit 0). The non-locking
 * ACTIVE check before the transaction is only a pre-filter; the one under the lock decides. The
 * transaction callback has no other side effect: it returns its decision, and every page and
 * every FAILURE row is written only after the transaction has ended (T-008 review Low 1).
 *
 * <p><b>Locking.</b> The zero-admin check runs under the SAME single-statement ascending set lock
 * that {@code assign()}/{@code revoke()} take, built from the same M10' + catalogue resolution
 * ({@link RoleAssignmentService#resolveAdminDefiningRoleIds} and {@link
 * RoleAssignmentService#buildAscendingLockSet}), and decides "zero administrators" with the revoke
 * guard's own predicate ({@link RoleAssignmentService#wouldLeaveTenantWithoutAdministrator}).
 * Right after the set lock, a {@code FOR SHARE} read of the lock set's {@code role_permissions}
 * ({@link UserRoleAssignmentPort#lockRolePermissionsForRoles}) decides which locked roles are
 * admin-defining now, as revoke and role deletion do (US-019 RC-57.2), so a demotion that
 * committed while this grant waited is seen. Then one statement takes shared ({@code FOR SHARE})
 * locks on the {@code users} rows of the target and of every administrator holder, in ascending
 * id order ({@link UserDirectoryPort#lockUserStatuses}), so the statuses the decision uses are
 * current, not a snapshot, and cannot change before the commit. The status lock is added only on
 * this path: the insert's foreign-key check already takes a shared lock on the target's {@code
 * users} row after the set lock, in the same order. Nothing is retried (ADR-0018 D6).
 *
 * <p><b>Who counts as an administrator (A-6, O-7, [OR-2.2-01]).</b> A holder of an admin-defining role
 * (the one definition, ADR-0021 D3: a role carrying every permission of the catalogue), whatever its
 * name. For break-glass only, such a holder whose user is DISABLED or LOCKED is not an administrator,
 * so a tenant whose only administrators are DISABLED or LOCKED is recoverable. Every other status
 * (ACTIVE, PENDING), and a holder whose status is not returned, still counts. The
 * last-admin lockout, the assign and revoke guards and the zero-admin health indicator are
 * unchanged.
 *
 * <p><b>Audit.</b> A grant writes {@code ROLE_BREAK_GLASS_GRANT} SUCCESS inside the grant's
 * transaction (Group A), so a lost audit row rolls the grant back. A refusal writes FAILURE in its
 * own transaction (Group B) so the row survives, then pages; that write is never buffered for
 * retry, and a failed one is logged as {@code RBAC_AUDIT_WRITE_LOST}. A refusal decided inside
 * the grant transaction (exit 4 or 5) is written only after that transaction has ended, so no
 * {@code REQUIRES_NEW} write ever runs while the set lock is held. An invocation commits at most
 * one row, SUCCESS or FAILURE, never both: a FAILURE row is attempted only when {@code execute()}
 * threw (nothing committed) or its callback returned a refusal (nothing inserted).
 *
 * <p><b>Pages.</b> One page per invocation. The grant's page is sent after {@code execute()}
 * returned, so after the commit by construction. Every page is best effort: if it fails the
 * failure is logged as {@code RBAC_BREAK_GLASS_ALERT_FAILED} (ERROR, no argument value) and the
 * outcome is unchanged: a grant stays exit 0, a refusal keeps its own exit code (L-1).
 *
 * <p><b>Failed grant transaction (T-008).</b> Any {@link RuntimeException} out of the grant
 * transaction (a deadlock on the insert, a failed SUCCESS write, a lost connection, a failed
 * commit) is mapped, after the rollback, to an audited and paged refusal: {@code
 * CONCURRENT_INVOCATION} (exit 7) for a {@link PessimisticLockingFailureException} (MySQL 1213
 * and 1205), {@code UNEXPECTED_ERROR} (exit 1) for anything else. This replaces any refusal the
 * failed transaction had decided. An {@link Error} propagates.
 */
@Service
public class BootstrapAdminService {

  private static final Logger log = LoggerFactory.getLogger(BootstrapAdminService.class);

  private static final String LOG_KEY_EVENT = "event";
  private static final String LOG_KEY_TENANT_ID = "tenantId";

  private final UserDirectoryPort userDirectoryPort;
  private final UserRoleAssignmentPort userRoleAssignmentPort;
  private final RbacAuditPort rbacAuditPort;
  private final BreakGlassAlertPort breakGlassAlertPort;
  private final BreakGlassGrantLookupPort breakGlassGrantLookupPort;
  private final TransactionTemplate grantTransaction;

  public BootstrapAdminService(
      UserDirectoryPort userDirectoryPort,
      UserRoleAssignmentPort userRoleAssignmentPort,
      RbacAuditPort rbacAuditPort,
      BreakGlassAlertPort breakGlassAlertPort,
      BreakGlassGrantLookupPort breakGlassGrantLookupPort,
      PlatformTransactionManager transactionManager) {
    this.userDirectoryPort = userDirectoryPort;
    this.userRoleAssignmentPort = userRoleAssignmentPort;
    this.rbacAuditPort = rbacAuditPort;
    this.breakGlassAlertPort = breakGlassAlertPort;
    this.breakGlassGrantLookupPort = breakGlassGrantLookupPort;
    // Default definition: PROPAGATION_REQUIRED, read-write.
    this.grantTransaction = new TransactionTemplate(transactionManager);
  }

  /**
   * Grants the target user its tenant's system {@code TENANT_ADMIN} role iff the change reference
   * was never used on a successful grant, the target is ACTIVE under the lock, and the tenant has
   * zero administrators (holders of admin-defining roles, A-6, minus holders whose user is DISABLED,
   * O-7) under the set lock. {@code assigned_by} is the target
   * itself (Decision 10). Refusals, including a failed grant transaction, are returned, not
   * thrown. A failure of the replay or target lookup propagates (fail closed, no row, no page).
   *
   * @param targetUserId the user to grant; must not be {@code null}
   * @param changeRef the validated change reference (RC-47); must not be {@code null}
   * @throws NullPointerException if either argument is {@code null}, before anything is read or
   *     written
   */
  public BreakGlassOutcome grantFirstAdmin(UUID targetUserId, ChangeRef changeRef) {
    Objects.requireNonNull(targetUserId, "targetUserId must not be null");
    Objects.requireNonNull(changeRef, "changeRef must not be null");
    if (breakGlassGrantLookupPort.existsSuccessfulGrantWithChangeRef(changeRef.value())) {
      return refuse(null, targetUserId, changeRef, BreakGlassRefusalReason.CHANGE_REF_REUSED);
    }
    Optional<DirectoryUser> target = userDirectoryPort.findUser(targetUserId);
    if (target.isEmpty()) {
      return refuse(null, targetUserId, changeRef, BreakGlassRefusalReason.TARGET_USER_NOT_FOUND);
    }
    UUID tenantId = target.get().tenantId();
    if (!target.get().active()) {
      return refuse(
          tenantId, targetUserId, changeRef, BreakGlassRefusalReason.TARGET_USER_NOT_ACTIVE);
    }

    // The callback has no side effect beyond its own transaction: every page and every FAILURE row
    // is written after execute() returns, so it can be neither duplicated nor contradicted by a
    // failure of the commit (T-008 review Low 1).
    BreakGlassOutcome decided;
    try {
      decided =
          grantTransaction.execute(status -> grantUnderLock(tenantId, targetUserId, changeRef));
    } catch (PessimisticLockingFailureException e) {
      // The grant has rolled back. No retry and no extra lock (ADR-0018); the runbook allows one
      // invocation per tenant at a time.
      log.atWarn()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_BREAK_GLASS_CONFLICT")
          .addKeyValue(LOG_KEY_TENANT_ID, tenantId)
          .log("Break-glass grant lost a lock race and rolled back: tenantId={}", tenantId);
      return refuse(
          tenantId, targetUserId, changeRef, BreakGlassRefusalReason.CONCURRENT_INVOCATION);
    } catch (RuntimeException e) {
      log.atWarn()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_BREAK_GLASS_GRANT_FAILED")
          .addKeyValue(LOG_KEY_TENANT_ID, tenantId)
          .setCause(e)
          .log("Break-glass grant failed and rolled back: tenantId={}", tenantId);
      return refuse(tenantId, targetUserId, changeRef, BreakGlassRefusalReason.UNEXPECTED_ERROR);
    }
    return switch (Objects.requireNonNull(decided, "grant transaction returned no outcome")) {
      case BreakGlassOutcome.Granted granted -> alertGranted(granted, changeRef);
      case BreakGlassOutcome.Refused(BreakGlassRefusalReason reason) ->
          refuse(tenantId, targetUserId, changeRef, reason);
    };
  }

  /**
   * Records an argument-validation refusal (RC-54(a), L-6): one FAILURE row with reason {@code
   * INVALID_ARGUMENT}, no tenant, no user and no change reference, and a page with the same
   * fields omitted. Takes no parameter, so no rejected argument value can reach either.
   *
   * @return the {@code INVALID_ARGUMENT} refusal, exit 2
   */
  public BreakGlassOutcome recordInvalidArgument() {
    return refuse(null, null, null, BreakGlassRefusalReason.INVALID_ARGUMENT);
  }

  /**
   * The body of the grant transaction: role, set lock, locking status read, target ACTIVE check,
   * zero-admin check, insert, SUCCESS row. Writes
   * nothing outside that transaction and pages nothing: a {@code Refused} returned from here is
   * not yet audited or paged, and a {@code Granted} not yet paged; the caller does both once the
   * transaction has ended.
   */
  private BreakGlassOutcome grantUnderLock(UUID tenantId, UUID targetUserId, ChangeRef changeRef) {
    Optional<UUID> tenantAdminRoleId =
        userRoleAssignmentPort
            .findRoleIdByName(tenantId, RbacRoleNames.TENANT_ADMIN)
            .filter(
                roleId ->
                    userRoleAssignmentPort.findRole(roleId).map(Role::isSystemRole).orElse(false));
    if (tenantAdminRoleId.isEmpty()) {
      return new BreakGlassOutcome.Refused(BreakGlassRefusalReason.NO_SYSTEM_ADMIN_ROLE);
    }

    Set<UUID> catalogueIds = userRoleAssignmentPort.findCatalogueIds();
    List<UUID> lockSet =
        RoleAssignmentService.buildAscendingLockSet(
            RoleAssignmentService.resolveAdminDefiningRoleIds(
                userRoleAssignmentPort, tenantId, catalogueIds),
            tenantAdminRoleId.get());
    List<ActiveAssignmentHolder> lockedHolders =
        userRoleAssignmentPort.lockActiveAssignmentHolders(tenantId, lockSet);
    // RC-57.2 (ADR-0021 Revision 3 follow-on rule): which locked roles are admin-defining comes
    // from a current FOR SHARE read under the set lock, as for revoke, deletion and a replace,
    // never from the pre-lock M10' read. After the set lock, before the status lock.
    Set<UUID> adminDefiningRoleIds =
        RbacAdministrators.adminDefiningRoleIds(
            userRoleAssignmentPort.lockRolePermissionsForRoles(tenantId, lockSet), catalogueIds);

    // O-7 and L-2: one locking read of the target's and every administrator holder's status, after
    // the set lock, so neither can be a stale snapshot.
    Set<UUID> statusUserIds = new HashSet<>();
    statusUserIds.add(targetUserId);
    lockedHolders.stream()
        .filter(holder -> adminDefiningRoleIds.contains(holder.roleId()))
        .forEach(holder -> statusUserIds.add(holder.userId()));
    Map<UUID, DirectoryUserStatus> statuses =
        userDirectoryPort.lockUserStatuses(tenantId, statusUserIds);

    if (statuses.get(targetUserId) != DirectoryUserStatus.ACTIVE) {
      return new BreakGlassOutcome.Refused(BreakGlassRefusalReason.TARGET_USER_NOT_ACTIVE);
    }
    // O-7, [OR-2.2-01], for A7 only: a DISABLED or LOCKED holder is not an administrator. A
    // holder of any other status, or whose status was not returned, still counts (fail closed).
    List<ActiveAssignmentHolder> administratorCandidates =
        lockedHolders.stream()
            .filter(holder -> {
              DirectoryUserStatus status = statuses.get(holder.userId());
              return status != DirectoryUserStatus.DISABLED && status != DirectoryUserStatus.LOCKED;
            })
            .toList();
    if (!RoleAssignmentService.wouldLeaveTenantWithoutAdministrator(
        administratorCandidates, null, adminDefiningRoleIds)) {
      return new BreakGlassOutcome.Refused(BreakGlassRefusalReason.TENANT_HAS_ADMIN);
    }

    userRoleAssignmentPort.assign(targetUserId, tenantAdminRoleId.get(), tenantId, targetUserId);
    rbacAuditPort.recordBreakGlassGrant(
        new BreakGlassAuditEvent(tenantId, targetUserId, changeRef.value()));
    return new BreakGlassOutcome.Granted(tenantId, targetUserId, tenantAdminRoleId.get());
  }

  /**
   * Pages a committed grant. Best effort: the grant and its SUCCESS row are already committed, so
   * a failed page is logged and the outcome stays a grant (exit 0); the daily reconciliation on
   * SUCCESS rows (03-design.md §7.2) is the backstop. Never turns into a FAILURE row.
   */
  private BreakGlassOutcome alertGranted(BreakGlassOutcome.Granted granted, ChangeRef changeRef) {
    try {
      breakGlassAlertPort.alert(
          new BreakGlassAlert(
              granted.tenantId(),
              granted.targetUserId(),
              BreakGlassAlert.Outcome.GRANTED,
              null,
              changeRef.value()));
    } catch (RuntimeException e) {
      log.atError()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_BREAK_GLASS_ALERT_FAILED")
          .addKeyValue(LOG_KEY_TENANT_ID, granted.tenantId())
          .setCause(e)
          .log(
              "Break-glass grant committed but its page failed: tenantId={}", granted.tenantId());
    }
    return granted;
  }

  /**
   * Writes the FAILURE row (own {@code REQUIRES_NEW} transaction, never buffered, never throws)
   * and pages right after it, even when the row was lost; a failed page is logged and never
   * changes the refusal (L-1). Nothing is committed to {@code
   * user_roles} on any path that reaches here. {@code null} values are omitted from the row and
   * the page.
   */
  private BreakGlassOutcome refuse(
      UUID tenantId, UUID targetUserId, ChangeRef changeRef, BreakGlassRefusalReason reason) {
    String changeRefValue = changeRef == null ? null : changeRef.value();
    rbacAuditPort.recordBreakGlassRefusal(
        new BreakGlassAuditEvent(tenantId, targetUserId, changeRefValue), reason.name());
    try {
      breakGlassAlertPort.alert(
          new BreakGlassAlert(
              tenantId,
              targetUserId,
              BreakGlassAlert.Outcome.REFUSED,
              reason.name(),
              changeRefValue));
    } catch (RuntimeException e) {
      // L-1: best effort, like the GRANTED page. The FAILURE row is already written; the refusal
      // keeps its own exit code. No argument value (target, change reference) is logged.
      log.atError()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_BREAK_GLASS_ALERT_FAILED")
          .addKeyValue(LOG_KEY_TENANT_ID, tenantId)
          .addKeyValue("reason", reason.name())
          .setCause(e)
          .log("Break-glass refusal recorded but its page failed: reason={}", reason.name());
    }
    return new BreakGlassOutcome.Refused(reason);
  }
}
