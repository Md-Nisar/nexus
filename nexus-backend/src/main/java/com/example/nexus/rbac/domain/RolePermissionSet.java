package com.example.nexus.rbac.domain;

import java.util.List;
import java.util.UUID;

/**
 * A role's permission set as served by {@code GET} and {@code PUT /roles/{roleId}/permissions}
 * (US-019 design §10.5): the permissions, and the {@link RolePermissionSetVersion} of exactly that
 * set, which the controller sends as the {@code ETag}.
 */
public record RolePermissionSet(UUID roleId, List<PermissionView> permissions, String version) {

  public RolePermissionSet {
    permissions = List.copyOf(permissions);
  }
}
