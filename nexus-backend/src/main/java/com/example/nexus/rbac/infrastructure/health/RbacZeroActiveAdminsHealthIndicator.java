package com.example.nexus.rbac.infrastructure.health;

import com.example.nexus.rbac.domain.RbacDangerousPermissions;
import com.example.nexus.rbac.domain.RbacRoleNames;
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
 * US-012 T-015 / US-017 FR-2 (design §9.2 item 5 / {@code 03b-threat-model.md} T-D4, "adopt
 * unconditionally"; widened by US-017 D10-D12; re-scoped by {@code 06-code-review.md} H-1,
 * 2026-09-24) — a runtime self-check alerting when any tenant has at least one
 * <b>caller-qualifying</b> role (literal {@code TENANT_ADMIN}, or a custom role carrying ALL THREE
 * of {@link RbacDangerousPermissions#NAMES}) with zero active holders of any of them, mirroring
 * {@link RbacDbPrivilegeHealthIndicator}'s UP/DOWN/UNKNOWN shape.
 *
 * <p><b>Re-scoped from the broader ANY-admin-equivalent population (H-1):</b> checking for zero
 * holders of ANY dangerous-permission-carrying role does not guarantee the tenant retains anyone
 * who can actually pass {@code RoleAssignmentService}'s caller gate ({@code
 * RbacAdminEquivalence#isFullyAdminEquivalent}, literal name OR ALL THREE permissions) — a tenant
 * could keep an ANY-holder (e.g. a role with only {@code tenant:write}) while losing its last
 * caller-qualifying holder, silently bricking its ability to ever administer itself again while
 * this indicator kept reporting UP. This indicator now tracks the SAME population the caller gate
 * and the widened lockout guard (§7.2) both protect.
 *
 * <p>This is the only control that catches a caller-qualifying lockout from <b>any</b> cause — a
 * bug, a future grant change, a {@code roles.name} casing mismatch, or a raw-SQL path — not just
 * the specific concurrent-revocation race {@code RoleAssignmentService}'s M11 locking guard
 * already closes. It is a detection control, not a prevention control: by the time this reports
 * DOWN, the tenant is already locked out and needs manual (DBA-level) remediation, since {@code
 * nexus_app} cannot re-{@code INSERT} an admin without one.
 *
 * <p><b>Constructor injects {@link ZeroAdminTenantReader} (US-017 D25), not {@code
 * JpaUserRoleRepository} directly</b> — this indicator has no business holding {@code
 * save}/{@code delete} capability over {@code user_roles} merely to run two read-only queries
 * (T-T14/RES-22). Still does not go through the port (D12, unaffected by D25): {@code
 * RbacRoleNames.TENANT_ADMIN}/{@code RbacDangerousPermissions.NAMES} are passed directly into the
 * two queries below, never hardcoded in the infrastructure layer.
 *
 * <p><b>Two queries, not one — a stated, deliberate fail-closed exception (D10, D11, §8.2).</b>
 * Every other guard in this story fails closed; this control fails <b>open</b> to {@code UNKNOWN}
 * on a query error, and that remains correct here even though it now spans two queries over four
 * tables: this is a detection control, not a gate, and reporting DOWN on a transient query timeout
 * would page on an infrastructure blip and train operators to ignore the one signal that means a
 * tenant is genuinely locked out.
 *
 * <p>Read-only; issues no writes. Registered as a named {@link HealthIndicator} bean ({@code
 * rbacZeroActiveAdmins}), left visible on the aggregate {@code /actuator/health} for the same
 * reason {@link RbacDbPrivilegeHealthIndicator} is: a tenant zeroing out its admins is rare, not a
 * routine condition to exclude from the aggregate. It is, however, deliberately excluded from the
 * liveness/readiness probe groups (MC-J) — a widened DOWN population here must stay a page, never
 * a container-eviction outage.
 */
@Component("rbacZeroActiveAdmins")
public class RbacZeroActiveAdminsHealthIndicator implements HealthIndicator {

  private static final Logger log =
      LoggerFactory.getLogger(RbacZeroActiveAdminsHealthIndicator.class);

  private final ZeroAdminTenantReader zeroAdminTenantReader;

  public RbacZeroActiveAdminsHealthIndicator(ZeroAdminTenantReader zeroAdminTenantReader) {
    this.zeroAdminTenantReader = zeroAdminTenantReader;
  }

  @Override
  public Health health() {
    try {
      long dangerousNamesCount = RbacDangerousPermissions.NAMES.size();
      Set<UUID> tenantsWithAFullyAdminEquivalentRole =
          new LinkedHashSet<>(
              zeroAdminTenantReader.findTenantsWithAFullyAdminEquivalentRole(
                  RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, dangerousNamesCount));
      List<UUID> tenantsWithAnActiveFullyAdminEquivalentHolder =
          zeroAdminTenantReader.findTenantsWithActiveFullyAdminEquivalentHolders(
              RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, dangerousNamesCount);
      tenantsWithAFullyAdminEquivalentRole.removeAll(tenantsWithAnActiveFullyAdminEquivalentHolder);
      List<UUID> affectedTenantIds = List.copyOf(tenantsWithAFullyAdminEquivalentRole);

      if (!affectedTenantIds.isEmpty()) {
        log.warn(
            "tenant(s) with zero active caller-qualifying holders detected: tenantIds={}",
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
                "one or more tenants have at least one caller-qualifying role (TENANT_ADMIN, or a"
                    + " custom role carrying ALL of role:write / user:write / tenant:write) but"
                    + " zero active holders of any of them — privileged actions in these tenants"
                    + " have no reachable administrator; manual remediation required, nexus_app"
                    + " cannot re-INSERT an admin without one; see application logs for affected"
                    + " tenant ids")
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
