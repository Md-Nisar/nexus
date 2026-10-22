package com.example.nexus.rbac.interfaces.rest.dto;

import java.util.List;

/** One user holding a permission, with the role ids that grant it (US-018 C3). Ids only. */
public record PermissionHolderResponse(String userId, List<String> viaRoleIds) {
  public PermissionHolderResponse {
    viaRoleIds = List.copyOf(viaRoleIds);
  }
}
