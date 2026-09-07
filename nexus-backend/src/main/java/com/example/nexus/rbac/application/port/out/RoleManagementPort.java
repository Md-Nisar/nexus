package com.example.nexus.rbac.application.port.out;

import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.RoleView;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Port over role, permission, and role-permission persistence for US-015 (03-design.md §4.3, D1).
 *
 * <p>One port, not a split, and not a widening of {@link UserRoleAssignmentPort} — that port is
 * scoped to the assignment aggregate and three existing test classes depend on its current
 * surface. There is exactly one consumer ({@code RoleManagementService}) and one implementor
 * ({@code JpaRoleManagementAdapter}), so splitting into role/role-permission/permission-catalogue
 * ports would be machinery with no user. The read-only-ness of {@code permissions} (ADR-0013 D1)
 * is expressed by this port simply having no write method for it.
 *
 * <p><b>Every method returns a {@link RoleView}/{@link PermissionView} projection or an id, never
 * a managed {@code Role} entity (R-6).</b> {@code nexus_app} holds {@code SELECT, INSERT} on
 * {@code roles} and no {@code UPDATE} at all; an accidental dirty-flush on a loaded entity would
 * fail in production only, since every {@code *IT} connects as the Testcontainers superuser.
 */
public interface RoleManagementPort {

  // --- roles ---------------------------------------------------------------

  /**
   * AC1. Inserts a role with {@code is_system_role = FALSE} and an {@code IdGenerator}-supplied
   * UUIDv7; returns its id. Implementations translate the {@code uq_roles_tenant_name} violation
   * into {@code DuplicateRoleNameException} (RBAC_006) so a concurrent duplicate yields 409, not
   * 500.
   */
  UUID createRole(UUID tenantId, String name, String description);

  /**
   * Q2 — role by id as a projection, never a managed entity. One read serves the 404, the 403,
   * and the AC7 {@code is_system_role} boolean.
   */
  Optional<RoleView> findRole(UUID roleId);

  /**
   * Q1 — AC2. All roles in a tenant, {@code ORDER BY name} for a stable unpaginated contract
   * (D11). Served by {@code uq_roles_tenant_name}'s leftmost {@code tenant_id} prefix — no new
   * index.
   */
  List<RoleView> findRolesInTenant(UUID tenantId);

  /**
   * Q3 — AC11. Resolves the tenant's admin role id by {@code (tenantId, name)}. MUST use a plain
   * {@code r.name = :name} predicate and rely on {@code utf8mb4_0900_ai_ci} for
   * case-insensitivity, so {@code uq_roles_tenant_name} is used as an index. MUST NOT wrap the
   * column in {@code UPPER()} — that de-sargonises AC11's write hot path. Returns the id only,
   * never the entity. Empty ⇒ the caller MUST fail closed (R-10).
   */
  Optional<UUID> findRoleIdByName(UUID tenantId, String name);

  /**
   * Q12 — RC-4's per-tenant cap check. Count of roles in the tenant, served by {@code
   * uq_roles_tenant_name}'s leftmost prefix — same index as Q1, no new cost.
   */
  long countRolesInTenant(UUID tenantId);

  // --- permissions (read-only, ADR-0013 D1) --------------------------------

  /** Q4 — AC4's 404 and AC11's name lookup, served by one PK read. */
  Optional<PermissionView> findPermission(UUID permissionId);

  /** Q5 — AC6. All seeded permissions, {@code ORDER BY name}. Deliberately NOT cached (§5.6). */
  List<PermissionView> findAllPermissions();

  // --- role_permissions ------------------------------------------------------

  /**
   * Q7 — AC3. A single projection join {@code RolePermission -> Permission}. Bounded at
   * {@code |permissions| = 7}.
   */
  List<PermissionView> findPermissionsForRole(UUID roleId);

  /**
   * Q8 — AC4's common-path 409. Kept alongside the adapter's constraint translation: the
   * pre-check gives the clean 409, the translation covers the concurrent-attach race.
   */
  boolean hasPermission(UUID roleId, UUID permissionId);

  /**
   * Q10 — AC4. Inserts the join row. Implementations translate the {@code pk_role_permissions}
   * violation into {@code DuplicateRolePermissionException} (RBAC_005).
   */
  void attachPermission(UUID roleId, UUID permissionId);

  /**
   * Q9 — AC5. MUST be a {@code @Modifying} bulk {@code DELETE} returning an affected-row count:
   * {@code deleteById} returns void and cannot distinguish "was attached" from "never attached",
   * which is exactly the distinction the 404-not-204 resolution requires. {@code RolePermission}
   * has no {@code @Version}, so this int count IS the concurrency guard.
   */
  int detachPermission(UUID roleId, UUID permissionId);
}
