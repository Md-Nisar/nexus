package com.example.nexus.rbac.application;

import com.example.nexus.rbac.application.RoleAssignmentService.AdminEquivalentRoles;
import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlertPort;
import com.example.nexus.rbac.application.port.out.BreakGlassAuditEvent;
import com.example.nexus.rbac.application.port.out.BreakGlassGrantLookupPort;
import com.example.nexus.rbac.application.port.out.DirectoryUser;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.domain.Role;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * US-018 A7 (03-design.md §7.1, §7.2): grants the first administrator of a tenant that has none.
 * Reachable only from {@code rbac.interfaces.cli} (ArchUnit-enforced, EC2) and never through
 * {@link RoleAssignmentService#assign}: break-glass has no caller to authorize.
 *
 * <p><b>Order.</b> {@link #grantFirstAdmin} is a non-transactional orchestrator: the replay lookup
 * (exit 6) and the target lookup (exit 3) run first, outside any transaction; then one grant
 * transaction ({@link TransactionTemplate}, {@code REQUIRED}) resolves the role (exit 4), takes
 * the lock, checks for an administrator (exit 5), inserts and writes SUCCESS (exit 0).
 *
 * <p><b>Locking.</b> The zero-admin check runs under the SAME single-statement ascending M11 set
 * lock that {@code assign()}/{@code revoke()} take, built from the same M10 + M8 resolution
 * ({@link RoleAssignmentService#resolveAdminEquivalentRolesFor(UserRoleAssignmentPort, UUID)}
 * and {@link RoleAssignmentService#buildAscendingAdminEquivalentLockSet}), and decides "zero
 * administrators" with the revoke guard's own predicate ({@link
 * RoleAssignmentService#wouldLeaveTenantWithoutCallerQualifyingHolder}). No other lock is taken
 * and nothing is retried (ADR-0018 D6).
 *
 * <p><b>Audit.</b> A grant writes {@code ROLE_BREAK_GLASS_GRANT} SUCCESS inside the grant's
 * transaction (Group A), so a lost audit row rolls the grant back. A refusal writes FAILURE in its
 * own transaction (Group B) so the row survives, then pages; that write is never buffered for
 * retry, and a failed one is logged as {@code RBAC_AUDIT_WRITE_LOST}. A refusal never follows a
 * committed SUCCESS write. The grant's page is sent after commit only.
 *
 * <p><b>Failed grant transaction (T-008).</b> Any {@link RuntimeException} out of the grant
 * transaction (a deadlock on the insert, a failed SUCCESS write, a lost connection, a failed
 * commit) is mapped, after the rollback, to an audited and paged refusal: {@code
 * CONCURRENT_INVOCATION} (exit 7) for a {@link PessimisticLockingFailureException} (MySQL 1213
 * and 1205), {@code UNEXPECTED_ERROR} (exit 1) for anything else. An {@link Error} propagates.
 */
@Service
public class BootstrapAdminService {

  private static final Logger log = LoggerFactory.getLogger(BootstrapAdminService.class);

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
   * was never used on a successful grant and the tenant has zero administrators (the ADR-0018
   * caller-qualifying population, A-6) under the set lock. {@code assigned_by} is the target
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

    try {
      return grantTransaction.execute(status -> grantUnderLock(tenantId, targetUserId, changeRef));
    } catch (PessimisticLockingFailureException e) {
      // The grant has rolled back. No retry and no extra lock (ADR-0018); the runbook allows one
      // invocation per tenant at a time.
      log.atWarn()
          .addKeyValue("event", "RBAC_BREAK_GLASS_CONFLICT")
          .addKeyValue("tenantId", tenantId)
          .log("Break-glass grant lost a lock race and rolled back: tenantId={}", tenantId);
      return refuse(
          tenantId, targetUserId, changeRef, BreakGlassRefusalReason.CONCURRENT_INVOCATION);
    } catch (RuntimeException e) {
      log.atWarn()
          .addKeyValue("event", "RBAC_BREAK_GLASS_GRANT_FAILED")
          .addKeyValue("tenantId", tenantId)
          .setCause(e)
          .log("Break-glass grant failed and rolled back: tenantId={}", tenantId);
      return refuse(tenantId, targetUserId, changeRef, BreakGlassRefusalReason.UNEXPECTED_ERROR);
    }
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

  /** The body of the grant transaction: role, lock, zero-admin check, insert, SUCCESS row. */
  private BreakGlassOutcome grantUnderLock(UUID tenantId, UUID targetUserId, ChangeRef changeRef) {
    Optional<UUID> tenantAdminRoleId =
        userRoleAssignmentPort
            .findRoleIdByName(tenantId, RbacRoleNames.TENANT_ADMIN)
            .filter(
                roleId ->
                    userRoleAssignmentPort.findRole(roleId).map(Role::isSystemRole).orElse(false));
    if (tenantAdminRoleId.isEmpty()) {
      return refuse(
          tenantId, targetUserId, changeRef, BreakGlassRefusalReason.NO_SYSTEM_ADMIN_ROLE);
    }

    AdminEquivalentRoles roles =
        RoleAssignmentService.resolveAdminEquivalentRolesFor(userRoleAssignmentPort, tenantId);
    List<UUID> lockSet =
        RoleAssignmentService.buildAscendingAdminEquivalentLockSet(roles, tenantAdminRoleId.get());
    List<ActiveAssignmentHolder> lockedHolders =
        userRoleAssignmentPort.lockActiveAssignmentHolders(tenantId, lockSet);

    if (!RoleAssignmentService.wouldLeaveTenantWithoutCallerQualifyingHolder(
        lockedHolders, null, roles.callerQualifyingIds())) {
      return refuse(tenantId, targetUserId, changeRef, BreakGlassRefusalReason.TENANT_HAS_ADMIN);
    }

    userRoleAssignmentPort.assign(targetUserId, tenantAdminRoleId.get(), tenantId, targetUserId);
    rbacAuditPort.recordBreakGlassGrant(
        new BreakGlassAuditEvent(tenantId, targetUserId, changeRef.value()));

    BreakGlassAlert alert =
        new BreakGlassAlert(
            tenantId, targetUserId, BreakGlassAlert.Outcome.GRANTED, null, changeRef.value());
    runAfterCommit(() -> breakGlassAlertPort.alert(alert));
    return new BreakGlassOutcome.Granted(tenantId, targetUserId, tenantAdminRoleId.get());
  }

  /**
   * Writes the FAILURE row (own {@code REQUIRES_NEW} transaction, never buffered, never throws)
   * and pages right after it, even when the row was lost. Nothing is committed to {@code
   * user_roles} on any path that reaches here. {@code null} values are omitted from the row and
   * the page.
   */
  private BreakGlassOutcome refuse(
      UUID tenantId, UUID targetUserId, ChangeRef changeRef, BreakGlassRefusalReason reason) {
    String changeRefValue = changeRef == null ? null : changeRef.value();
    rbacAuditPort.recordBreakGlassRefusal(
        new BreakGlassAuditEvent(tenantId, targetUserId, changeRefValue), reason.name());
    breakGlassAlertPort.alert(
        new BreakGlassAlert(
            tenantId,
            targetUserId,
            BreakGlassAlert.Outcome.REFUSED,
            reason.name(),
            changeRefValue));
    return new BreakGlassOutcome.Refused(reason);
  }

  /**
   * Runs {@code action} after the enclosing transaction commits; inline when no synchronization
   * is active (a plain unit test), the same fallback as {@code
   * RoleAssignmentService#registerPostCommitSideEffects}.
   */
  private static void runAfterCommit(Runnable action) {
    if (TransactionSynchronizationManager.isSynchronizationActive()) {
      TransactionSynchronizationManager.registerSynchronization(
          new TransactionSynchronization() {
            @Override
            public void afterCommit() {
              action.run();
            }
          });
    } else {
      action.run();
    }
  }
}
