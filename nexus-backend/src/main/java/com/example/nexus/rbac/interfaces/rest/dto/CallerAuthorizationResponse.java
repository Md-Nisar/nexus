package com.example.nexus.rbac.interfaces.rest.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * US-019 B4 (03-design.md §6.1): the signed-in caller's own live roles, the distinct permission
 * names they grant, and whether the caller is an administrator. Nothing else: no role composition,
 * no {@code assignedBy}, no tenant id, no catalogue size.
 */
public record CallerAuthorizationResponse(
    @Schema(example = "0190a000-0000-7000-8000-000000000001") String userId,
    List<RoleEntry> roles,
    @Schema(example = "[\"audit:read\", \"role:read\"]") List<String> permissions,
    @Schema(description = "True when one held role carries the whole permission catalogue")
        boolean isAdministrator) {

  public CallerAuthorizationResponse {
    roles = List.copyOf(roles);
    permissions = List.copyOf(permissions);
  }

  /** One live role the caller actively holds. */
  public record RoleEntry(
      @Schema(example = "0190a000-0000-7000-8000-00000000000a") String roleId, String name) {}
}
