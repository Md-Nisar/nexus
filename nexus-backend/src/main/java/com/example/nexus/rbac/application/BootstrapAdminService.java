package com.example.nexus.rbac.application;

import com.example.nexus.rbac.application.RoleAssignmentService.AdminEquivalentRoles;
import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlertPort;
import com.example.nexus.rbac.application.port.out.BreakGlassAuditEvent;
import com.example.nexus.rbac.application.port.out.DirectoryUser;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.domain.Role;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * US-018 A7 (03-design.md §7.1, §7.2): grants the first administrator of a tenant that has none.
 * Reachable only from {@code rbac.interfaces.cli} (ArchUnit-enforced, EC2) and never through
 * {@link RoleAssignmentService#assign}: break-glass has no caller to authorize.
 *
 * <p><b>Locking.</b> The zero-admin check runs under the SAME single-statement ascending M11 set
 * lock that {@code assign()}/{@code revoke()} take, built from the same M10 + M8 resolution
 * ({@link RoleAssignmentService#resolveAdminEquivalentRoles(UserRoleAssignmentPort, UUID)} and
 * {@link RoleAssignmentService#buildAscendingAdminEquivalentLockSet}). No other lock is taken
 * (ADR-0018 D6).
 *
 * <p><b>Audit.</b> A grant writes {@code ROLE_BREAK_GLASS_GRANT} SUCCESS inside the grant's
 * transaction (Group A), so a lost audit row rolls the grant back. A refusal writes FAILURE in its
 * own transaction (Group B) so the row survives, then pages. A refusal never follows a SUCCESS
 * write. The grant's page is sent after commit.
 */
@Service
public class BootstrapAdminService {

  private static final String OUTCOME_GRANTED = "GRANTED";
  private static final String OUTCOME_REFUSED = "REFUSED";

  private final UserDirectoryPort userDirectoryPort;
  private final UserRoleAssignmentPort userRoleAssignmentPort;
  private final RbacAuditPort rbacAuditPort;
  private final BreakGlassAlertPort breakGlassAlertPort;

  public BootstrapAdminService(
      UserDirectoryPort userDirectoryPort,
      UserRoleAssignmentPort userRoleAssignmentPort,
      RbacAuditPort rbacAuditPort,
      BreakGlassAlertPort breakGlassAlertPort) {
    this.userDirectoryPort = userDirectoryPort;
    this.userRoleAssignmentPort = userRoleAssignmentPort;
    this.rbacAuditPort = rbacAuditPort;
    this.breakGlassAlertPort = breakGlassAlertPort;
  }

  /**
   * Grants the target user its tenant's system {@code TENANT_ADMIN} role iff the tenant has zero
   * administrators (the ADR-0018 caller-qualifying population, A-6) under the set lock. {@code
   * assigned_by} is the target itself (Decision 10). Refusals are returned, not thrown; an
   * unexpected failure (including a failed SUCCESS audit write) propagates and rolls back.
   */
  @Transactional
  public BreakGlassOutcome grantFirstAdmin(UUID targetUserId, String changeRef) {
    Optional<DirectoryUser> target = userDirectoryPort.findUser(targetUserId);
    if (target.isEmpty()) {
      return refuse(null, targetUserId, changeRef, BreakGlassRefusalReason.TARGET_USER_NOT_FOUND);
    }
    UUID tenantId = target.get().tenantId();
    if (!target.get().active()) {
      return refuse(
          tenantId, targetUserId, changeRef, BreakGlassRefusalReason.TARGET_USER_NOT_ACTIVE);
    }

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
        RoleAssignmentService.resolveAdminEquivalentRoles(userRoleAssignmentPort, tenantId);
    List<UUID> lockSet =
        RoleAssignmentService.buildAscendingAdminEquivalentLockSet(roles, tenantAdminRoleId.get());
    List<ActiveAssignmentHolder> lockedHolders =
        userRoleAssignmentPort.lockActiveAssignmentHolders(tenantId, lockSet);

    Set<UUID> callerQualifyingIds = roles.callerQualifyingIds();
    if (lockedHolders.stream().anyMatch(holder -> callerQualifyingIds.contains(holder.roleId()))) {
      return refuse(tenantId, targetUserId, changeRef, BreakGlassRefusalReason.TENANT_HAS_ADMIN);
    }

    userRoleAssignmentPort.assign(targetUserId, tenantAdminRoleId.get(), tenantId, targetUserId);
    rbacAuditPort.recordBreakGlassGrant(
        new BreakGlassAuditEvent(tenantId, targetUserId, changeRef));

    BreakGlassAlert alert =
        new BreakGlassAlert(tenantId, targetUserId, OUTCOME_GRANTED, null, changeRef);
    runAfterCommit(() -> breakGlassAlertPort.alert(alert));
    return new BreakGlassOutcome.Granted(tenantId, targetUserId, tenantAdminRoleId.get());
  }

  /**
   * Writes the FAILURE row (own {@code REQUIRES_NEW} transaction, never throws) and pages right
   * after it. Nothing has been written to {@code user_roles} on any path that reaches here.
   */
  private BreakGlassOutcome refuse(
      UUID tenantId, UUID targetUserId, String changeRef, BreakGlassRefusalReason reason) {
    rbacAuditPort.recordBreakGlassRefusal(
        new BreakGlassAuditEvent(tenantId, targetUserId, changeRef), reason.name());
    breakGlassAlertPort.alert(
        new BreakGlassAlert(tenantId, targetUserId, OUTCOME_REFUSED, reason.name(), changeRef));
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
