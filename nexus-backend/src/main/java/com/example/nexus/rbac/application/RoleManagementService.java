package com.example.nexus.rbac.application;

import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.RoleAuditEvent;
import com.example.nexus.rbac.application.port.out.RoleManagementPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.DuplicateRolePermissionException;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.RbacDangerousPermissions;
import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.domain.ReservedRoleNameException;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleLimitExceededException;
import com.example.nexus.rbac.domain.RoleView;
import com.example.nexus.rbac.domain.SystemRoleImmutableException;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
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
 * Creates and manages tenant-scoped custom roles and their attached permissions (03-design.md
 * §4.2, §3.1-§3.3). This is the <b>only</b> place AC7 (system-role immutability), AC8 (tenant
 * isolation) and AC11 (the dangerous-permission admin gate — the mint side of the M-3 escalation
 * chain, threat model T-E14/T-E16) are enforced — {@code @RequiresPermission}/{@code
 * TenantAwarePermissionEvaluator} check nothing but flat JWT {@code permissions[]} membership and
 * cannot express any of them.
 *
 * <p><b>Design invariant, self-policed (not compiler-enforced), mirroring {@link
 * RoleAssignmentService}'s:</b> every public method on this class accepts only {@link
 * RoleChangeActor}, {@link UUID}, {@link String} and {@link RequestContext} — never {@code
 * org.springframework.security.core.Authentication}, never {@code java.security.Principal}, never
 * {@code java.util.Map}.
 *
 * <p><b>Single shared guards, not per-endpoint copies</b> (story risk R9's own mitigation): {@link
 * #resolveRoleInTenant} produces the 404/403/{@link RoleView}, and {@link #requireMutableRole}
 * produces the 409. Both write endpoints call both — there is no path to a {@code
 * role_permissions} write that bypasses either.
 */
@Service
public class RoleManagementService {

  private static final Logger log = LoggerFactory.getLogger(RoleManagementService.class);

  private static final String ROLE_WRITE = "role:write";
  private static final String ROLE_READ = "role:read";

  private static final String LOG_KEY_EVENT = "event";
  private static final String LOG_KEY_TENANT_ID = "tenantId";
  private static final String LOG_KEY_ROLE_ID = "roleId";
  private static final String LOG_KEY_ROLE_NAME = "roleName";
  private static final String LOG_KEY_PERMISSION_ID = "permissionId";
  private static final String LOG_KEY_PERMISSION_NAME = "permissionName";
  private static final String LOG_KEY_ACTOR_USER_ID = "actorUserId";

  private final RoleManagementPort roleManagementPort;
  private final UserRoleAssignmentPort userRoleAssignmentPort;
  private final RbacAuditPort rbacAuditPort;
  private final MeterRegistry meterRegistry;
  private final long maxRolesPerTenant;

  public RoleManagementService(
      RoleManagementPort roleManagementPort,
      UserRoleAssignmentPort userRoleAssignmentPort,
      RbacAuditPort rbacAuditPort,
      MeterRegistry meterRegistry,
      @Value("${nexus.rbac.max-roles-per-tenant:500}") long maxRolesPerTenant) {
    this.roleManagementPort = roleManagementPort;
    this.userRoleAssignmentPort = userRoleAssignmentPort;
    this.rbacAuditPort = rbacAuditPort;
    this.meterRegistry = meterRegistry;
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

    registerPostCommitSideEffects(
        () -> {
          rbacAuditPort.recordRoleCreated(
              new RoleAuditEvent(
                  actor.tenantId(),
                  view.id(),
                  view.name(),
                  null,
                  null,
                  actor.userId(),
                  ctx,
                  null));
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

  /** AC2, AC8. Tenant-scoped by predicate, ordered by name (D11). */
  @Transactional(readOnly = true)
  public List<RoleView> listRoles(RoleChangeActor actor) {
    return roleManagementPort.findRolesInTenant(actor.tenantId());
  }

  /** AC3, AC8. 404 then 403; empty list is a valid 200. */
  @Transactional(readOnly = true)
  public List<PermissionView> listRolePermissions(RoleChangeActor actor, UUID roleId) {
    RoleView role = resolveRoleInTenant(roleId, actor, ROLE_READ);
    return roleManagementPort.findPermissionsForRole(role.id());
  }

  /**
   * AC4, AC7, AC8, AC11, AC12. The story's security-critical path, in the §8.6-pinned order:
   * tenant resolution (404/403) &rarr; AC7 (409) &rarr; permission existence (404) &rarr; AC11
   * (403, dangerous permissions only) &rarr; AC4's duplicate pre-check (409) &rarr; insert.
   *
   * <p><b>D13 / RC-8 (T-E21, US-016):</b> on the dangerous-permission path only, after the insert
   * this method counts how many users actively hold {@code roleId} at that moment via {@link
   * UserRoleAssignmentPort#findActiveUserIdsForRole} and carries the count on the {@code
   * ROLE_PERMISSION_GRANTED} audit event, a WARN marker, and a bounded metric bucket. This is a
   * <b>signal, not a gate</b> — attaching a dangerous permission to a role with existing holders
   * is a legitimate administrative action and is never blocked here. Removing this signal
   * silently reopens T-E21's mass-escalation blind spot (03-design.md §4.7, D13); do not delete
   * it without re-opening that note.
   */
  @Transactional
  public PermissionView attachPermission(
      RoleChangeActor actor, UUID roleId, UUID permissionId, RequestContext ctx) {
    RoleView role = resolveRoleInTenant(roleId, actor, ROLE_WRITE);
    requireMutableRole(role);

    PermissionView permission =
        roleManagementPort
            .findPermission(permissionId)
            .orElseThrow(
                () -> new ResourceNotFoundException("PERMISSION_NOT_FOUND", "No such permission"));

    boolean dangerous = RbacDangerousPermissions.contains(permission.name());
    if (dangerous) {
      verifyCallerIsActiveTenantAdmin(actor, role, permission);
    }

    if (roleManagementPort.hasPermission(role.id(), permissionId)) {
      throw new DuplicateRolePermissionException();
    }
    roleManagementPort.attachPermission(role.id(), permissionId);

    // D13 / RC-8 (T-E21): count the users this attach silently escalates. Dangerous path only —
    // no cost on the ordinary attach. M9 is UserRoleAssignmentPort.findActiveUserIdsForRole,
    // shipped by US-015 RC-6 for the remediation runbook; this is its first runtime caller. Signal,
    // not a gate — removing it silently reopens T-E21's mass-escalation blind spot.
    Integer holderCount =
        dangerous ? userRoleAssignmentPort.findActiveUserIdsForRole(role.id()).size() : null;

    registerPostCommitSideEffects(
        () -> {
          rbacAuditPort.recordRolePermissionGranted(
              new RoleAuditEvent(
                  actor.tenantId(),
                  role.id(),
                  role.name(),
                  permission.id(),
                  permission.name(),
                  actor.userId(),
                  ctx,
                  holderCount));
          var infoBuilder =
              log.atInfo()
                  .addKeyValue(LOG_KEY_EVENT, "ROLE_PERMISSION_GRANTED")
                  .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
                  .addKeyValue(LOG_KEY_ROLE_ID, role.id())
                  .addKeyValue(LOG_KEY_ROLE_NAME, role.name())
                  .addKeyValue(LOG_KEY_PERMISSION_ID, permission.id())
                  .addKeyValue(LOG_KEY_PERMISSION_NAME, permission.name())
                  .addKeyValue("dangerous", dangerous)
                  .addKeyValue("grantedBy", actor.userId());
          if (holderCount != null) {
            infoBuilder = infoBuilder.addKeyValue("holderCount", holderCount);
          }
          infoBuilder.log("Role permission granted");

          if (dangerous && holderCount > 0) {
            log.atWarn()
                .addKeyValue(LOG_KEY_EVENT, "RBAC_DANGEROUS_PERMISSION_GRANTED_TO_EXISTING_HOLDERS")
                .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
                .addKeyValue(LOG_KEY_ROLE_ID, role.id())
                .addKeyValue(LOG_KEY_ROLE_NAME, role.name())
                .addKeyValue(LOG_KEY_PERMISSION_ID, permission.id())
                .addKeyValue(LOG_KEY_PERMISSION_NAME, permission.name())
                .addKeyValue("grantedBy", actor.userId())
                .addKeyValue("holderCount", holderCount)
                .log("Dangerous permission granted to a role with existing active holders");
          }
          if (dangerous) {
            Counter.builder("nexus.rbac.dangerous_permission_granted")
                .tag("permission", permission.name())
                .tag("tenantId", actor.tenantId().toString())
                .tag("holders", holderCountBucket(holderCount))
                .register(meterRegistry)
                .increment();
          }
        });

    return permission;
  }

  /**
   * AC5, AC7, AC8, AC12. No AC11 gate — detaching a permission reduces privilege, a deliberate
   * asymmetry with {@link #attachPermission}.
   */
  @Transactional
  public void detachPermission(
      RoleChangeActor actor, UUID roleId, UUID permissionId, RequestContext ctx) {
    RoleView role = resolveRoleInTenant(roleId, actor, ROLE_WRITE);
    requireMutableRole(role);

    int affectedRows = roleManagementPort.detachPermission(role.id(), permissionId);
    if (affectedRows == 0) {
      // Covers "permission does not exist", "never attached" and "already detached" identically
      // — the addressed resource is the pairing, which does not exist in any of the three cases.
      throw new ResourceNotFoundException(
          "ROLE_PERMISSION_NOT_FOUND", "This permission is not attached to this role");
    }

    // Enrichment only, not a gate: Q9's affected-row count above IS the existence gate (§8.6).
    // This read exists solely so the audit event and log carry permissionName, per AC12.
    String permissionName =
        roleManagementPort.findPermission(permissionId).map(PermissionView::name).orElse(null);

    registerPostCommitSideEffects(
        () -> {
          rbacAuditPort.recordRolePermissionRevoked(
              new RoleAuditEvent(
                  actor.tenantId(),
                  role.id(),
                  role.name(),
                  permissionId,
                  permissionName,
                  actor.userId(),
                  ctx,
                  null));
          log.atInfo()
              .addKeyValue(LOG_KEY_EVENT, "ROLE_PERMISSION_REVOKED")
              .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
              .addKeyValue(LOG_KEY_ROLE_ID, role.id())
              .addKeyValue(LOG_KEY_ROLE_NAME, role.name())
              .addKeyValue(LOG_KEY_PERMISSION_ID, permissionId)
              .addKeyValue(LOG_KEY_PERMISSION_NAME, permissionName)
              .addKeyValue("revokedBy", actor.userId())
              .log("Role permission revoked");
        });
  }

  /** AC6. Global catalogue, no tenant scoping — {@code permissions} has no {@code tenant_id} column. */
  @Transactional(readOnly = true)
  public List<PermissionView> listAllPermissions() {
    return roleManagementPort.findAllPermissions();
  }

  /** AC8 tenant-isolation check: empty ⇒ 404 {@code ROLE_NOT_FOUND}; foreign tenant ⇒ 403 {@code CROSS_TENANT_TARGET}. */
  private RoleView resolveRoleInTenant(UUID roleId, RoleChangeActor actor, String requiredPermission) {
    RoleView view =
        roleManagementPort
            .findRole(roleId)
            .orElseThrow(() -> new ResourceNotFoundException("ROLE_NOT_FOUND", "No such role"));
    if (!view.tenantId().equals(actor.tenantId())) {
      throw new InsufficientPermissionException(requiredPermission, DenialReason.CROSS_TENANT_TARGET);
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
   * AC11's dangerous-permission admin gate (F1/T-E14, RC-5a) — {@code Q3 -> Q11}, both fresh
   * reads inside this write transaction. MUST NOT be replaced by {@code
   * RoleAssignmentService.callerHoldsActiveTenantAdmin}'s shape (that helper is deliberately
   * non-locking — it only decides whether to redact one response field, not whether to authorize
   * a mutation) and MUST NOT call {@link UserRoleAssignmentPort#findActiveAssignmentViews} (this
   * service has no target user; that method exists for a different caller's field-redaction
   * decision and its use here would silently convert an assignment check into a role-name check).
   * {@code void}, not {@code boolean}, by design: a caller cannot ignore a thrown exception the
   * way it could ignore an unchecked boolean return value.
   */
  private void verifyCallerIsActiveTenantAdmin(RoleChangeActor actor, RoleView role, PermissionView permission) {
    Optional<UUID> adminRoleId =
        roleManagementPort.findRoleIdByName(actor.tenantId(), RbacRoleNames.TENANT_ADMIN);
    // Empty ⇒ fail closed (R-10): a tenant with no seeded TENANT_ADMIN role cannot attach a
    // dangerous permission at all. Short-circuits before hasActiveAdminAssignment is ever called.
    boolean isActiveAdmin =
        adminRoleId.isPresent()
            && userRoleAssignmentPort.hasActiveAdminAssignment(
                actor.userId(), adminRoleId.get(), actor.tenantId());
    if (!isActiveAdmin) {
      log.atWarn()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_DANGEROUS_PERMISSION_ATTACH_BLOCKED")
          .addKeyValue(LOG_KEY_TENANT_ID, actor.tenantId())
          .addKeyValue(LOG_KEY_ROLE_ID, role.id())
          .addKeyValue(LOG_KEY_ROLE_NAME, role.name())
          .addKeyValue(LOG_KEY_PERMISSION_ID, permission.id())
          .addKeyValue(LOG_KEY_PERMISSION_NAME, permission.name())
          .addKeyValue(LOG_KEY_ACTOR_USER_ID, actor.userId())
          .log("Blocked dangerous-permission attach by a non-admin caller");
      throw new InsufficientPermissionException(ROLE_WRITE, DenialReason.NOT_TENANT_ADMIN);
    }
  }

  /**
   * D13 bucket for {@code nexus.rbac.dangerous_permission_granted}'s {@code holders} tag —
   * bounded cardinality (four values), never the raw count, which is unbounded (03-design.md
   * §4.7).
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
