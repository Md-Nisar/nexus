package com.example.nexus.rbac.interfaces.rest.dto;

import java.util.List;

/**
 * Envelope for {@code GET /api/v1/permissions} (AC6; paginated by US-018 C2). Distinct from {@link
 * PermissionListResponse}, which stays the unpaginated envelope of {@code GET
 * /api/v1/roles/{roleId}/permissions} (a role carries at most the catalogue's few permissions).
 * Ordered by {@code name}, which is unique.
 */
public record PermissionPageResponse(
    List<PermissionResponse> data, PageMetadata page, PageLinks links) {
  public PermissionPageResponse {
    data = List.copyOf(data);
  }
}
