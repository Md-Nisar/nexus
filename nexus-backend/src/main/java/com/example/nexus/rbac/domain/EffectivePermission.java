package com.example.nexus.rbac.domain;

import java.util.List;
import java.util.UUID;

/** One permission a user holds, with the live roles that grant it (US-018 C3). */
public record EffectivePermission(String name, List<UUID> viaRoleIds) {

  public EffectivePermission {
    viaRoleIds = List.copyOf(viaRoleIds);
  }
}
