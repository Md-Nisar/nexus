package com.example.nexus.rbac.application;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The committed-state detector (US-019 RC-56.4, design §10.9), shared by attach, the permission-set
 * replace (B8) and assign. Each caller evaluates it after commit, from the read-only holder read it
 * already makes: if role R is admin-defining <b>now</b> and has an active holder whose {@code
 * assigned_by} is not currently an administrator, the provenance rule ({@code RBAC_010}, ADR-0021
 * D8) was bypassed on some path the preventive checks missed. That emits WARN {@code
 * RBAC_ADMIN_DEFINING_ROLE_HAS_NON_ADMIN_ASSIGNED_HOLDER} (ids and counts only, retained at least a
 * year, RES-6) and increments {@code nexus.rbac.admin_defining_role_non_admin_assigned_holder},
 * which has no tags (no tenant tag) and pages.
 */
final class AdminDefiningRoleProvenanceDetector {

  private static final Logger log =
      LoggerFactory.getLogger(AdminDefiningRoleProvenanceDetector.class);

  private static final String COUNTER = "nexus.rbac.admin_defining_role_non_admin_assigned_holder";

  private AdminDefiningRoleProvenanceDetector() {}

  /**
   * Emits the signal iff {@code roleAdminDefining} and {@code nonAdminAssignedCount > 0}; otherwise
   * does nothing.
   */
  static void check(
      MeterRegistry meterRegistry,
      UUID tenantId,
      UUID roleId,
      boolean roleAdminDefining,
      int holderCount,
      int nonAdminAssignedCount) {
    if (!roleAdminDefining || nonAdminAssignedCount == 0) {
      return;
    }
    log.atWarn()
        .addKeyValue("event", "RBAC_ADMIN_DEFINING_ROLE_HAS_NON_ADMIN_ASSIGNED_HOLDER")
        .addKeyValue("tenantId", tenantId)
        .addKeyValue("roleId", roleId)
        .addKeyValue("holderCount", holderCount)
        .addKeyValue("nonAdminAssignedCount", nonAdminAssignedCount)
        .log("An admin-defining role has a holder assigned by someone who is not an administrator");
    Counter.builder(COUNTER).register(meterRegistry).increment();
  }
}
