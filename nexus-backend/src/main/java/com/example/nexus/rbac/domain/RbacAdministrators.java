package com.example.nexus.rbac.domain;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * The single definition of "administrator" (US-018 03-design.md §2.1, ADR-0021): a role is
 * <b>admin-defining</b> iff it carries every permission in the {@code permissions} catalogue, and a
 * user is an administrator in a tenant iff they hold an active assignment of an admin-defining role
 * there.
 *
 * <p>Evaluated <b>per role</b>, never over the union of a user's roles: a user holding the whole
 * catalogue only through two partial roles is not an administrator (fails closed). Compared over
 * ids, never names, so there is no case-sensitivity trap.
 */
public final class RbacAdministrators {

  private RbacAdministrators() {}

  /**
   * Whether one role's permission ids cover the whole catalogue. An empty catalogue returns {@code
   * false} (MC-1): if {@code permissions} reads back empty, nobody is an administrator.
   */
  public static boolean isAdminDefining(Set<UUID> rolePermissionIds, Set<UUID> catalogueIds) {
    return !catalogueIds.isEmpty() && rolePermissionIds.containsAll(catalogueIds);
  }

  /**
   * The ids of the roles, among the {@code (roleId, permissionId)} rows given, that are
   * admin-defining. Evaluated per role over ids (M10', M13). A role with no row is never
   * admin-defining here, which is correct: it carries nothing, and an empty catalogue yields an
   * empty set.
   */
  public static Set<UUID> adminDefiningRoleIds(
      Collection<RolePermissionRef> rolePermissions, Set<UUID> catalogueIds) {
    Set<UUID> adminDefining = new HashSet<>();
    permissionIdsByRole(rolePermissions)
        .forEach(
            (roleId, permissionIds) -> {
              if (isAdminDefining(permissionIds, catalogueIds)) {
                adminDefining.add(roleId);
              }
            });
    return Set.copyOf(adminDefining);
  }

  /**
   * Whether the holder of {@code heldRolePermissions} (M13: one row per permission of each role the
   * user actively holds) is an administrator: some single role among them is admin-defining. Never
   * the union across roles (03-design.md §2.1): the whole catalogue held across two partial roles
   * does not qualify.
   */
  public static boolean isAdministrator(
      Collection<RolePermissionRef> heldRolePermissions, Set<UUID> catalogueIds) {
    return !adminDefiningRoleIds(heldRolePermissions, catalogueIds).isEmpty();
  }

  private static Map<UUID, Set<UUID>> permissionIdsByRole(Collection<RolePermissionRef> rows) {
    Map<UUID, Set<UUID>> byRole = new HashMap<>();
    for (RolePermissionRef row : rows) {
      byRole.computeIfAbsent(row.roleId(), id -> new HashSet<>()).add(row.permissionId());
    }
    return byRole;
  }
}
