package com.example.nexus.rbac.domain;

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
}
