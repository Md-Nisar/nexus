package com.example.nexus.rbac.domain;

import java.util.Set;

/**
 * AC11's fixed set of permissions that, if attached to a role, let the role's holder escalate
 * further (grant roles, assign users, or mutate tenants). Single-sourced here rather than as a
 * private field on {@code RoleManagementService} so the set is directly unit-testable under the
 * {@code *.domain.*} coverage gate (03-design.md §4.4).
 */
public final class RbacDangerousPermissions {

  public static final Set<String> NAMES = Set.of("role:write", "user:write", "tenant:write");

  /**
   * Case-insensitive, null-safe membership check. {@code permissions.name}'s collation is {@code
   * utf8mb4_0900_ai_ci}, so this mirrors the DB's own comparison semantics.
   */
  public static boolean contains(String permissionName) {
    if (permissionName == null) {
      return false;
    }
    return NAMES.stream().anyMatch(name -> name.equalsIgnoreCase(permissionName));
  }

  private RbacDangerousPermissions() {}
}
