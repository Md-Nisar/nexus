package com.example.nexus.rbac.domain;

import java.util.List;

/**
 * The deduplicated, tenant-scoped result of resolving a user's active role and permission names
 * (US-010) — {@code roles} feeds the JWT/{@code /users/me} {@code roles[]} claim, {@code
 * permissions} feeds {@code permissions[]}. Both lists are sorted for deterministic output.
 */
public record ResolvedPermissions(List<String> roles, List<String> permissions) {

  public ResolvedPermissions {
    roles = List.copyOf(roles.stream().sorted().distinct().toList());
    permissions = List.copyOf(permissions.stream().sorted().distinct().toList());
  }

  public static ResolvedPermissions empty() {
    return new ResolvedPermissions(List.of(), List.of());
  }
}
