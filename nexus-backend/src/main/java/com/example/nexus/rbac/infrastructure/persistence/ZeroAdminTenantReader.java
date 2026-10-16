package com.example.nexus.rbac.infrastructure.persistence;

import java.util.List;
import java.util.UUID;

/**
 * Narrow, read-only view over {@link JpaUserRoleRepository} for the zero-admin detection queries
 * (US-017 D25) — it exists solely so {@code RbacZeroActiveAdminsHealthIndicator} can depend on two
 * read-only methods instead of the full {@code JpaRepository<UserRole, UUID>} surface ({@code
 * save}/{@code delete}/{@code deleteAll}), closing T-T14/RES-22 rather than accepting it.
 *
 * <p>US-018 row 15 (ADR-0021 D3): both methods use the one definition of an administrator. A role
 * is admin-defining iff its {@code COUNT(DISTINCT permission)} equals the catalogue count; no
 * permission or role names are passed. A tenant is reported when it has at least one admin-defining
 * role and no active holder of any of them. The same indicator carries the count-only soft-delete
 * invariant detector.
 */
public interface ZeroAdminTenantReader {

  List<UUID> findTenantsWithAnAdminDefiningRole();

  List<UUID> findTenantsWithActiveAdminDefiningHolders();

  /**
   * US-018 T-026 (RC-36.4): active {@code user_roles} rows that reference a soft-deleted role.
   * Expected 0 always; greater than 0 is an invariant break and pages. A count, never ids.
   */
  long countActiveAssignmentsOnDeletedRolesInAnyTenant();
}
