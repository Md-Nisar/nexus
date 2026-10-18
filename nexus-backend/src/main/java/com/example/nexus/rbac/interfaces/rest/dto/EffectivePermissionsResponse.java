package com.example.nexus.rbac.interfaces.rest.dto;

import java.util.List;

/**
 * Response of {@code GET /api/v1/users/{userId}/effective-permissions} (US-018 C3): every permission
 * the user holds in the caller's tenant with the role ids that grant it. Not paginated: a single
 * resource bounded by the catalogue. Ids and permission names only.
 */
public record EffectivePermissionsResponse(
    String userId, List<EffectivePermissionEntry> permissions) {

  public EffectivePermissionsResponse {
    permissions = List.copyOf(permissions);
  }

  /** One permission and the roles that grant it. */
  public record EffectivePermissionEntry(String name, List<String> viaRoleIds) {
    public EffectivePermissionEntry {
      viaRoleIds = List.copyOf(viaRoleIds);
    }
  }
}
