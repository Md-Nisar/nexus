package com.example.nexus.rbac.domain;

import java.util.Collection;
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

  /**
   * {@code true} iff at least one element of {@code permissionNames} case-insensitively matches a
   * member of {@link #NAMES} (US-017 D1, RC-18.1). {@code null}/empty ⇒ {@code false}.
   */
  public static boolean carriesAny(Collection<String> permissionNames) {
    if (permissionNames == null || permissionNames.isEmpty()) {
      return false;
    }
    return permissionNames.stream().anyMatch(RbacDangerousPermissions::contains);
  }

  /**
   * {@code true} iff {@code permissionNames} case-insensitively covers ALL THREE of {@link
   * #NAMES} (US-017 D1, RC-18.1). {@code null}/empty ⇒ {@code false}.
   *
   * <p><b>MUST be a per-name, case-insensitive {@code anyMatch}</b> — for each of the three names
   * independently, does the collection contain a case-insensitive match? <b>Never a count</b>
   * (e.g. {@code filter(...).count() >= 3}), which returns {@code true} for {@code
   * ["user:write","user:write","user:write"]} — it fails open on the caller-side predicate, which
   * is the one direction that must never fail open (03-design.md §4.1). <b>Never {@code
   * containsAll}</b> — that is case-sensitive: it fails closed, but silently, and would deny a
   * legitimate case-variant like {@code "Role:Write"}. Null-tolerant, mirroring the shipped
   * null-safe {@link #contains(String)}: a {@code null} element in {@code permissionNames} is
   * simply never a case-insensitive match for any of the three names.
   */
  public static boolean carriesAll(Collection<String> permissionNames) {
    if (permissionNames == null || permissionNames.isEmpty()) {
      return false;
    }
    return NAMES.stream()
        .allMatch(
            name -> permissionNames.stream().anyMatch(name::equalsIgnoreCase));
  }

  private RbacDangerousPermissions() {}
}
