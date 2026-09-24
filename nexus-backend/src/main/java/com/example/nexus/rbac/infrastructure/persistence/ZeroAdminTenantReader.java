package com.example.nexus.rbac.infrastructure.persistence;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Narrow, read-only view over {@link JpaUserRoleRepository} for FR-2's zero-admin detection query
 * (US-017 D25) — it exists solely so {@code RbacZeroActiveAdminsHealthIndicator} can depend on two
 * read-only methods instead of the full {@code JpaRepository<UserRole, UUID>} surface ({@code
 * save}/{@code delete}/{@code deleteAll}), closing T-T14/RES-22 rather than accepting it.
 *
 * <p><b>Re-scoped post-06-code-review.md H-1</b> (2026-09-24): these two methods used to drive off
 * the ANY-admin-equivalent predicate ({@code isAdminEquivalent} / {@code carriesAny}) — the same
 * broad population the target-side gate uses. That let a tenant retain an ANY-holder (e.g. a role
 * with only {@code tenant:write}) while losing its last <em>caller-qualifying</em> holder (literal
 * {@code TENANT_ADMIN} or ALL THREE dangerous permissions), silently bricking the tenant's ability
 * to ever pass the caller gate again while this detector kept reporting UP. Re-scoped to the SAME
 * caller-qualifying predicate the gate itself uses ({@code isFullyAdminEquivalent} / {@code
 * carriesAll}) so the detective control matches what actually determines whether the tenant can
 * still administer itself — not merely whether it still has some dangerous-permission holder.
 */
public interface ZeroAdminTenantReader {

  List<UUID> findTenantsWithAFullyAdminEquivalentRole(
      String adminRoleName, Collection<String> dangerousNames, long dangerousNamesCount);

  List<UUID> findTenantsWithActiveFullyAdminEquivalentHolders(
      String adminRoleName, Collection<String> dangerousNames, long dangerousNamesCount);
}
