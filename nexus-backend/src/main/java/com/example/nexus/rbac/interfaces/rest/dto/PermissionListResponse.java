package com.example.nexus.rbac.interfaces.rest.dto;

import java.util.List;

/**
 * Envelope shared by {@code GET /api/v1/roles/{roleId}/permissions} (AC3) and {@code GET
 * /api/v1/permissions} (AC6) — the field set and shape are identical for both endpoints
 * (03-design.md §8.3/§8.4, D5).
 */
public record PermissionListResponse(List<PermissionResponse> data) {
  public PermissionListResponse {
    data = List.copyOf(data);
  }
}
