package com.example.nexus.rbac.domain;

import java.util.List;
import java.util.UUID;

/**
 * One user holding a permission in the caller's tenant, with the live roles that grant it (US-018
 * C3). A user who holds the permission through several roles appears once, with every role id.
 * Ids only.
 */
public record PermissionHolder(UUID userId, List<UUID> viaRoleIds) {

  public PermissionHolder {
    viaRoleIds = List.copyOf(viaRoleIds);
  }
}
