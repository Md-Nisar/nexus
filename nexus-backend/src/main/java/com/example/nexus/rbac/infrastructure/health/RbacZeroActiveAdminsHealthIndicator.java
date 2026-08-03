package com.example.nexus.rbac.infrastructure.health;

import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Component;

/**
 * US-012 T-015 (design §9.2 item 5 / {@code 03b-threat-model.md} T-D4, "adopt unconditionally") —
 * a runtime self-check alerting when any tenant has a seeded {@code TENANT_ADMIN}-named role with
 * zero active assignments, mirroring {@link RbacDbPrivilegeHealthIndicator}'s UP/DOWN/UNKNOWN
 * shape.
 *
 * <p>This is the only control that catches an AC5 (last-admin lockout) bypass from <b>any</b>
 * cause — a bug, a future grant change, a {@code roles.name} casing mismatch, or a raw-SQL path —
 * not just the specific concurrent-revocation race {@code RoleAssignmentService}'s M1 locking
 * guard already closes. It is a detection control, not a prevention control: by the time this
 * reports DOWN, the tenant is already locked out and needs manual (DBA-level) remediation, since
 * {@code nexus_app} cannot re-{@code INSERT} an admin without one.
 *
 * <p>Read-only; issues no writes. Registered as a named {@link HealthIndicator} bean ({@code
 * rbacZeroActiveAdmins}), left visible on the aggregate {@code /actuator/health} for the same
 * reason {@link RbacDbPrivilegeHealthIndicator} is: a tenant zeroing out its admins is rare, not a
 * routine condition to exclude from the aggregate.
 */
@Component("rbacZeroActiveAdmins")
public class RbacZeroActiveAdminsHealthIndicator implements HealthIndicator {

  private static final Logger log =
      LoggerFactory.getLogger(RbacZeroActiveAdminsHealthIndicator.class);

  private final JpaUserRoleRepository userRoleRepository;

  public RbacZeroActiveAdminsHealthIndicator(JpaUserRoleRepository userRoleRepository) {
    this.userRoleRepository = userRoleRepository;
  }

  @Override
  public Health health() {
    try {
      List<UUID> affectedTenantIds =
          userRoleRepository.findTenantsWithZeroActiveAssignmentsForRole(
              RbacRoleNames.TENANT_ADMIN);

      if (!affectedTenantIds.isEmpty()) {
        log.warn(
            "tenant(s) with zero active {} assignments detected: tenantIds={}",
            RbacRoleNames.TENANT_ADMIN,
            affectedTenantIds);
        // 07-security-review.md M-1: the affected tenant ids themselves are NOT published in
        // the actuator detail — /actuator/health's WHEN_AUTHORIZED show-details treats any
        // authenticated principal as authorized (management.endpoint.health.roles is unset),
        // and /actuator/health/** is permitAll, so every self-registered MEMBER of every
        // tenant could otherwise read other tenants' UUIDs here. A count preserves the runbook's
        // alerting signal without the cross-tenant disclosure; the full id list remains
        // available to operators via the WARN log line above.
        return Health.down()
            .withDetail("affectedTenantCount", affectedTenantIds.size())
            .withDetail(
                "issue",
                "one or more tenants have a seeded TENANT_ADMIN role with zero active"
                    + " assignments — user:write actions in these tenants have no reachable admin"
                    + " (AC5 bypass or lockout); manual remediation required, nexus_app cannot"
                    + " re-INSERT an admin without one; see application logs for affected tenant"
                    + " ids")
            .build();
      }
      return Health.up().build();
    } catch (DataAccessException e) {
      // The self-check itself must never fail the app or throw — an inconclusive check is
      // reported as UNKNOWN, not treated as either a pass or a lockout finding.
      log.warn("zero-active-admins self-check failed to execute: {}", e.getMessage());
      return Health.unknown()
          .withDetail("issue", "zero-active-admins self-check could not run: " + e.getMessage())
          .build();
    }
  }
}
