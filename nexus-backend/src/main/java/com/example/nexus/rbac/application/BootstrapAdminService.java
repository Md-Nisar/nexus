package com.example.nexus.rbac.application;

import com.example.nexus.common.Profiles;
import com.example.nexus.rbac.application.RoleAssignmentService.AdminEquivalentRoles;
import com.example.nexus.rbac.application.port.out.BreakGlassAlert;
import com.example.nexus.rbac.application.port.out.BreakGlassAlertPort;
import com.example.nexus.rbac.application.port.out.BreakGlassAuditEvent;
import com.example.nexus.rbac.application.port.out.BreakGlassGrantLookupPort;
import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort.DirectoryUser;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.domain.Role;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * The break-glass first-administrator grant (US-018 A7, ADR-0025, 03-design.md §7). The platform's
 * one privileged entry point that is not HTTP: it grants the tenant's system {@code TENANT_ADMIN}
 * to a target user, and only when the tenant has <b>zero</b> administrators.
 *
 * <p><b>Containment.</b> Callable only from {@code rbac.interfaces.cli} (ArchUnit), so REST can
 * never reach it. The bean itself exists only under the {@code break-glass} profile (ArchUnit), so
 * a serving JVM does not even hold the admin-granting service (US-018 M5 M-1). It never calls {@link RoleAssignmentService#assign}, so the no-self-assignment
 * rule (A4) needs no exemption.
 *
 * <p><b>Locking.</b> The zero-administrator check runs under the same single-statement, ascending
 * M11 set lock that assign and revoke take, over the same population (M10), so it cannot race a
 * concurrent change. No other lock is taken (ADR-0018 D6).
 *
 * <p><b>Audit.</b> A grant writes its {@code ROLE_BREAK_GLASS_GRANT} SUCCESS row inside the grant's
 * transaction (a lost row rolls the grant back). A refusal writes a FAILURE row in its own
 * transaction, which survives, and every invocation pages through {@link BreakGlassAlertPort}; a
 * grant pages after commit. A refusal returns an outcome instead of throwing, so nothing rolls
 * back that the refusal row depends on.
 *
 * <p>Before US-018 M3 "administrator" is the shipped ADR-0018 caller-qualifying population (A-6).
 */
@Service
@Profile(Profiles.BREAK_GLASS)
public class BootstrapAdminService {

  private final UserRoleAssignmentPort userRoleAssignmentPort;
  private final UserDirectoryPort userDirectoryPort;
  private final RbacAuditPort rbacAuditPort;
  private final BreakGlassAlertPort alertPort;
  private final BreakGlassGrantLookupPort grantLookupPort;
  private final PermissionCachePort permissionCachePort;

  public BootstrapAdminService(
      UserRoleAssignmentPort userRoleAssignmentPort,
      UserDirectoryPort userDirectoryPort,
      RbacAuditPort rbacAuditPort,
      BreakGlassAlertPort alertPort,
      BreakGlassGrantLookupPort grantLookupPort,
      PermissionCachePort permissionCachePort) {
    this.userRoleAssignmentPort = userRoleAssignmentPort;
    this.userDirectoryPort = userDirectoryPort;
    this.rbacAuditPort = rbacAuditPort;
    this.alertPort = alertPort;
    this.grantLookupPort = grantLookupPort;
    this.permissionCachePort = permissionCachePort;
  }

  /**
   * Grants the target's tenant's system {@code TENANT_ADMIN} to {@code targetUserId} when the
   * tenant has no administrator. {@code changeRef} must already have passed the runner's
   * canonical-pattern check; it is the operator's only attribution (it joins the infra audit log).
   *
   * <p>Order (design §7.1): change reference already used on a SUCCESS grant in any tenant (exit
   * 6, RC-37.2; before any user lookup) → target user (missing or not ACTIVE, exit 3) → system {@code
   * TENANT_ADMIN} (absent, exit 4) → M10 prime and M11 set lock → zero-administrator check (an
   * administrator exists, exit 5) → insert with {@code assigned_by = target} (Decision 10) → atomic
   * audit → page, then permission-cache eviction, after commit.
   */
  @Transactional
  public BreakGlassOutcome grantFirstAdmin(UUID targetUserId, String changeRef) {
    if (grantLookupPort.existsSuccessfulGrantWithChangeRef(changeRef)) {
      return refuse(BreakGlassOutcome.CHANGE_REF_REUSED, null, targetUserId, changeRef);
    }

    Optional<DirectoryUser> user = userDirectoryPort.findDirectoryUser(targetUserId);
    if (user.isEmpty()) {
      return refuse(BreakGlassOutcome.USER_NOT_FOUND, null, targetUserId, changeRef);
    }
    UUID tenantId = user.get().tenantId();
    if (!user.get().active()) {
      return refuse(BreakGlassOutcome.USER_NOT_ACTIVE, tenantId, targetUserId, changeRef);
    }

    Optional<UUID> adminRoleId = findSystemTenantAdminRoleId(tenantId);
    if (adminRoleId.isEmpty()) {
      return refuse(BreakGlassOutcome.NO_SYSTEM_ADMIN_ROLE, tenantId, targetUserId, changeRef);
    }

    // M10 prime, then the M11 set lock: the SAME population and acquisition order as assign and
    // revoke (ADR-0018 D6). The TENANT_ADMIN id is always in the lock set, so the INSERT below is
    // inside the locked range.
    AdminEquivalentRoles roles = AdminEquivalentRoles.resolve(userRoleAssignmentPort, tenantId);
    List<UUID> lockSet =
        RoleAssignmentService.buildAscendingAdminEquivalentLockSet(roles, adminRoleId.get());
    List<ActiveAssignmentHolder> holders =
        userRoleAssignmentPort.lockActiveAssignmentHolders(tenantId, lockSet);

    Set<UUID> administratorRoleIds = roles.callerQualifyingIds();
    if (holders.stream().anyMatch(holder -> administratorRoleIds.contains(holder.roleId()))) {
      return refuse(BreakGlassOutcome.TENANT_HAS_ADMIN, tenantId, targetUserId, changeRef);
    }

    // assigned_by = the target (Decision 10): no migration, no synthetic principal, and no
    // operator identity in tenant data. Forensics join this row to ROLE_BREAK_GLASS_GRANT.
    userRoleAssignmentPort.assign(targetUserId, adminRoleId.get(), tenantId, targetUserId);

    rbacAuditPort.recordBreakGlassGranted(
        new BreakGlassAuditEvent(tenantId, targetUserId, changeRef, null));

    // Page first, then evict the new administrator's cached permission set (it may hold the
    // pre-grant, empty set for up to its TTL), as assign() does. Eviction never throws.
    afterCommit(
        () -> {
          alertPort.raise(
              new BreakGlassAlert(
                  tenantId, targetUserId, BreakGlassAlert.OUTCOME_GRANTED, null, changeRef));
          permissionCachePort.evict(tenantId, targetUserId);
        });
    return BreakGlassOutcome.GRANTED;
  }

  /**
   * The refusal path for an invalid or missing argument (exit 2, RC-54(a)). It takes <b>no
   * argument</b> on purpose: the rejected values never reach the audit row (null {@code tenant_id},
   * metadata {@code {actorType, reason}} only) or the page (no {@code targetUserId}, no {@code
   * changeRef}), so free text cannot be smuggled into either through a refusal (L-6).
   */
  public BreakGlassOutcome refuseInvalidArgument() {
    return refuse(BreakGlassOutcome.INVALID_ARGUMENT, null, null, null);
  }

  /**
   * The tenant's seeded system {@code TENANT_ADMIN}, or empty. A role merely named {@code
   * TENANT_ADMIN} that is not a system role does not count (Decision 11: the CLI never provisions
   * roles).
   */
  private Optional<UUID> findSystemTenantAdminRoleId(UUID tenantId) {
    return userRoleAssignmentPort
        .findRoleIdByName(tenantId, RbacRoleNames.TENANT_ADMIN)
        .filter(
            roleId ->
                userRoleAssignmentPort
                    .findRole(roleId)
                    .filter(role -> role.getTenantId().equals(tenantId))
                    .map(Role::isSystemRole)
                    .orElse(false));
  }

  /**
   * A refusal: its audit row is written in its own transaction (Group B), then the page is raised
   * immediately. Returns the outcome so the caller's transaction commits empty instead of rolling
   * back.
   */
  private BreakGlassOutcome refuse(
      BreakGlassOutcome outcome, UUID tenantId, UUID targetUserId, String changeRef) {
    rbacAuditPort.recordBreakGlassRefused(
        new BreakGlassAuditEvent(tenantId, targetUserId, changeRef, outcome.reason()));
    alertPort.raise(
        new BreakGlassAlert(
            tenantId, targetUserId, BreakGlassAlert.OUTCOME_REFUSED, outcome.reason(), changeRef));
    return outcome;
  }

  private static void afterCommit(Runnable sideEffect) {
    if (TransactionSynchronizationManager.isSynchronizationActive()) {
      TransactionSynchronizationManager.registerSynchronization(
          new TransactionSynchronization() {
            @Override
            public void afterCommit() {
              sideEffect.run();
            }
          });
    } else {
      sideEffect.run();
    }
  }
}
