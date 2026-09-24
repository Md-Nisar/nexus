package com.example.nexus.rbac.domain;

import java.util.Collection;

/**
 * Two deliberately different admin-equivalence tests. See ADR-0018 D1/D2 for why they differ
 * (03-design.md §4.1, D1). Built only on {@link RbacRoleNames#TENANT_ADMIN} and {@link
 * RbacDangerousPermissions}'s combinators — never redefining the permission set.
 */
public final class RbacAdminEquivalence {

  /**
   * TARGET side (FR-1, FR-2, and US-016's gate condition): name OR ANY dangerous permission.
   * Identical in effect to the shipped US-016 gate condition (ADR-0017 D1).
   */
  public static boolean isAdminEquivalent(String roleName, Collection<String> permissionNames) {
    return RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(roleName)
        || RbacDangerousPermissions.carriesAny(permissionNames);
  }

  /**
   * CALLER side (FR-3): name OR ALL THREE dangerous permissions. <b>STRICTLY NARROWER — never
   * substitute one for the other; an ANY caller test is vacuous</b> (ADR-0018 D2).
   */
  public static boolean isFullyAdminEquivalent(String roleName, Collection<String> permissionNames) {
    return RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(roleName)
        || RbacDangerousPermissions.carriesAll(permissionNames);
  }

  private RbacAdminEquivalence() {}
}
