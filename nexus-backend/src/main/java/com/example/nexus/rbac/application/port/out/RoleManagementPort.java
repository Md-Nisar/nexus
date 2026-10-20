package com.example.nexus.rbac.application.port.out;

import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.RoleView;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
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
   * Q1 — AC2, paginated by US-018 C2. One page of the LIVE roles in a tenant, {@code ORDER BY name,
   * id}: a total order, so pages neither overlap nor skip rows under concurrent writes. Served by
   * {@code uq_roles_tenant_name}'s leftmost {@code tenant_id} prefix — no new index. Non-locking.
   *
   * @param page 0-based, {@code >= 0}
   * @param size {@code >= 1}
   */
  PageResult<RoleView> findRolesInTenant(UUID tenantId, int page, int size);

  /**
   * C1 — soft-deletes a role: a targeted single-column {@code UPDATE roles SET deleted_at = ? WHERE
   * id = ? AND tenant_id = ? AND deleted_at IS NULL}, never a load-mutate-save (the {@code nexus_app}
   * grant is column-scoped). Returns the affected-row count: {@code 1} = deleted, {@code 0} = already
   * deleted, missing or in another tenant (the caller maps 0 to 404). The statement takes an X lock
   * on the role row, which is what a concurrent assign's conditional INSERT queues behind.
   */
  int softDeleteRole(UUID roleId, UUID tenantId, Instant deletedAt);

  /**
   * C1 PATCH — rewrites a live role's {@code name} and {@code description}: a targeted two-column
   * {@code UPDATE ... WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL}, never a
   * load-mutate-save (the {@code nexus_app} grant is column-scoped to exactly these columns and
   * {@code deleted_at}). The caller passes the values to store (current values for an unchanged
   * field). Returns the affected-row count: {@code 0} means the role is deleted, missing or in
   * another tenant (the caller maps it to 404). Implementations translate the {@code
   * uq_roles_tenant_active_name} / {@code uq_roles_tenant_name} violation into {@code
   * DuplicateRoleNameException} (RBAC_006), never exposing the driver's message.
   */
  int updateRole(UUID roleId, UUID tenantId, String name, String description);

  /**
   * Q12 — RC-4's per-tenant cap check. Count of LIVE (not soft-deleted) roles in the tenant, served
   * by {@code uq_roles_tenant_name}'s leftmost prefix — same index as Q1, no new cost.
   */
  long countRolesInTenant(UUID tenantId);

  /**
   * US-019 B6 — active (non-revoked) assignments per LIVE role of {@code tenantId}, one {@code
   * GROUP BY role_id} statement for the whole {@code roleIds} page. The user's status is ignored.
   * Roles with no holder are absent from the map. An empty {@code roleIds} issues no statement.
   */
  Map<UUID, Long> countActiveHoldersByRole(UUID tenantId, Collection<UUID> roleIds);

  /**
   * US-019 B6 — attached permissions per LIVE role of {@code tenantId}, one {@code GROUP BY
   * role_id} statement for the whole {@code roleIds} page. {@code role_permissions} has no tenant
   * column, so the statement joins {@code roles} for the tenant predicate. Roles with no permission
   * are absent from the map. An empty {@code roleIds} issues no statement.
   */
  Map<UUID, Long> countPermissionsByRole(UUID tenantId, Collection<UUID> roleIds);

  // --- permissions (read-only, ADR-0013 D1) --------------------------------

  /** Q4 — AC4's 404 and AC11's name lookup, served by one PK read. */
  Optional<PermissionView> findPermission(UUID permissionId);

  /**
   * Q5 — AC6, paginated by US-018 C2. One page of the seeded permissions, {@code ORDER BY name}
   * ({@code name} is unique). Deliberately NOT cached (§5.6). Non-locking.
   */
  PageResult<PermissionView> findAllPermissions(int page, int size);

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
