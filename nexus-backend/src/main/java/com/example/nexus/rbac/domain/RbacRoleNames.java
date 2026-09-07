package com.example.nexus.rbac.domain;

import java.util.Set;

/**
 * Single-sourced role name(s) with built-in authorization semantics. Callers must compare against
 * {@code role.getName()} case-insensitively — {@code roles.name}'s collation makes
 * {@code uq_roles_tenant_name} case-insensitive, so a case-sensitive Java compare could silently
 * disable the guards that depend on this constant (03-design.md §5.2, R-9).
 */
public final class RbacRoleNames {

  public static final String TENANT_ADMIN = "TENANT_ADMIN";
  public static final String MEMBER = "MEMBER";

  /**
   * The two seeded system role names, reserved against reuse by custom role creation
   * (threat-model.md RC-1) — a name collision with either, once created, would be a permanent,
   * application-unremediable denial of service, since {@code nexus_app} has neither {@code
   * UPDATE} nor {@code DELETE} on {@code roles}.
   */
  public static final Set<String> RESERVED = Set.of(TENANT_ADMIN, MEMBER);

  /** Case-insensitive, null-safe check against {@link #RESERVED}, mirroring {@link
   * RbacDangerousPermissions#contains(String)}'s shape. */
  public static boolean isReserved(String name) {
    if (name == null) {
      return false;
    }
    return RESERVED.stream().anyMatch(reserved -> reserved.equalsIgnoreCase(name));
  }

  private RbacRoleNames() {}
}
