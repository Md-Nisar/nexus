package com.example.nexus.rbac.infrastructure.health;

import com.example.nexus.rbac.infrastructure.persistence.ZeroAdminTenantReader;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Component;

/**
 * US-012 T-015 / US-017 FR-2, re-scoped by US-018 row 15 (ADR-0021 D3) — a runtime self-check
 * alerting when any tenant has at least one <b>admin-defining</b> role (a role carrying every
 * permission of the catalogue, compared by {@code COUNT(DISTINCT permission)} against the catalogue
 * count) with zero active holders of any admin-defining role, mirroring {@link
 * RbacDbPrivilegeHealthIndicator}'s UP/DOWN/UNKNOWN shape. No role or permission names are passed
 * to the queries: the one definition of "administrator" is the catalogue, so the indicator tracks
 * the same population the last-admin lockout, A4, the break-glass precondition and {@code
 * listActive}'s redaction use.
 *
 * <p>This is the only control that catches an administrator lockout from <b>any</b> cause — a bug,
 * a catalogue change, a concurrent pair of detaches (RES-28), or a raw-SQL path — not just the
 * concurrent-revocation race the set lock already closes. It is a detection control, not a
 * prevention control: by the time this reports DOWN, the tenant has no administrator and needs
 * break-glass (where a system {@code TENANT_ADMIN} is seeded) or DBA-level remediation.
 *
 * <p><b>Constructor injects {@link ZeroAdminTenantReader} (US-017 D25), not {@code
 * JpaUserRoleRepository} directly</b> — this indicator has no business holding {@code
 * save}/{@code delete} capability over {@code user_roles} merely to run two read-only queries
 * (T-T14/RES-22). It does not go through the port.
 *
 * <p><b>Two queries, not one — a stated, deliberate fail-closed exception.</b> Every other guard
 * fails closed; this control fails <b>open</b> to {@code UNKNOWN} on a query error: it is a
 * detection control, not a gate, and reporting DOWN on a transient query timeout would page on an
 * infrastructure blip and train operators to ignore the one signal that means a tenant has no
 * administrator.
 *
 * <p><b>US-018 T-026 (RC-36.4).</b> The same indicator carries the soft-delete invariant detector,
 * the count-only detail {@code deletedRoleActiveAssignments} ("active {@code user_roles} rows
 * referencing a soft-deleted role"). It is 0 by construction; greater than 0 reports DOWN, which
 * pages through the same alert path as the zero-admin detail. No ids are published. It runs under
 * the same 30 s cache and probe exclusion.
 *
 * <p>Read-only; issues no writes. Registered as a named {@link HealthIndicator} bean ({@code
 * rbacZeroActiveAdmins}), left visible on the aggregate {@code /actuator/health}, and deliberately
 * excluded from the liveness/readiness probe groups (MC-J) — a DOWN here must stay a page, never a
 * container-eviction outage. The 30 s actuator cache and that exclusion are protected properties
 * (US-017 RES-21, RC-22).
 */
@Component("rbacZeroActiveAdmins")
public class RbacZeroActiveAdminsHealthIndicator implements HealthIndicator {

  private static final String KEY_ISSUE = "issue";
  private static final Logger log =
      LoggerFactory.getLogger(RbacZeroActiveAdminsHealthIndicator.class);

  private final ZeroAdminTenantReader zeroAdminTenantReader;

  public RbacZeroActiveAdminsHealthIndicator(ZeroAdminTenantReader zeroAdminTenantReader) {
    this.zeroAdminTenantReader = zeroAdminTenantReader;
  }

  @Override
  public Health health() {
    try {
      Set<UUID> tenantsWithAnAdminDefiningRole =
          new LinkedHashSet<>(zeroAdminTenantReader.findTenantsWithAnAdminDefiningRole());
      List<UUID> tenantsWithAnActiveAdminDefiningHolder =
          zeroAdminTenantReader.findTenantsWithActiveAdminDefiningHolders();
      tenantsWithAnAdminDefiningRole.removeAll(tenantsWithAnActiveAdminDefiningHolder);
      List<UUID> affectedTenantIds = List.copyOf(tenantsWithAnAdminDefiningRole);
      long deletedRoleActiveAssignments =
          zeroAdminTenantReader.countActiveAssignmentsOnDeletedRolesInAnyTenant();

      if (deletedRoleActiveAssignments > 0) {
        // RC-36.4: a count only, never ids. The delete protocol makes this 0 by construction, so a
        // positive value is an invariant break that pages through the same alert path.
        log.warn(
            "RBAC_DELETED_ROLE_ACTIVE_ASSIGNMENTS activeAssignmentsOnDeletedRoles={}",
            deletedRoleActiveAssignments);
      }
      if (!affectedTenantIds.isEmpty()) {
        log.warn(
            "tenant(s) with zero active administrators detected: tenantIds={}", affectedTenantIds);
      }
      if (!affectedTenantIds.isEmpty() || deletedRoleActiveAssignments > 0) {
        // 07-security-review.md M-1: the affected tenant ids themselves are NOT published in
        // the actuator detail — /actuator/health's WHEN_AUTHORIZED show-details treats any
        // authenticated principal as authorized (management.endpoint.health.roles is unset),
        // and /actuator/health/** is permitAll, so every self-registered MEMBER of every
        // tenant could otherwise read other tenants' UUIDs here. A count preserves the runbook's
        // alerting signal without the cross-tenant disclosure; the full id list remains
        // available to operators via the WARN log line above.
        Health.Builder down =
            Health.down()
                .withDetail("affectedTenantCount", affectedTenantIds.size())
                .withDetail("deletedRoleActiveAssignments", deletedRoleActiveAssignments);
        if (!affectedTenantIds.isEmpty()) {
          down.withDetail(
              KEY_ISSUE,
              "one or more tenants have at least one admin-defining role (a role carrying every"
                  + " permission of the catalogue) but zero active holders of any of them —"
                  + " privileged actions in these tenants have no reachable administrator;"
                  + " recover with break-glass or manual remediation; see application logs for"
                  + " affected tenant ids");
        } else {
          down.withDetail(
              KEY_ISSUE,
              "one or more active role assignments reference a soft-deleted role — the delete"
                  + " invariant (a deleted role has no active holders) is broken; see the runbook");
        }
        return down.build();
      }
      return Health.up().withDetail("deletedRoleActiveAssignments", 0L).build();
    } catch (DataAccessException e) {
      // The self-check itself must never fail the app or throw — an inconclusive check is
      // reported as UNKNOWN, not treated as either a pass or a lockout finding.
      log.warn("zero-active-admins self-check failed to execute: {}", e.getMessage());
      return Health.unknown()
          .withDetail(KEY_ISSUE, "zero-active-admins self-check could not run: " + e.getMessage())
          .build();
    }
  }
}
