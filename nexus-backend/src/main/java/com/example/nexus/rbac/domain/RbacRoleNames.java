package com.example.nexus.rbac.domain;

/**
 * Single-sourced role name(s) with built-in authorization semantics. Callers must compare against
 * {@code role.getName()} case-insensitively — {@code roles.name}'s collation makes
 * {@code uq_roles_tenant_name} case-insensitive, so a case-sensitive Java compare could silently
 * disable the guards that depend on this constant (03-design.md §5.2, R-9).
 */
public final class RbacRoleNames {

  public static final String TENANT_ADMIN = "TENANT_ADMIN";

  private RbacRoleNames() {}
}
