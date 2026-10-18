package com.example.nexus.rbac.interfaces.rest.dto;

import java.util.List;

/** Envelope for {@code GET /api/v1/permissions/{permissionId}/holders} (US-018 C3). */
public record PermissionHolderListResponse(
    List<PermissionHolderResponse> data, PageMetadata page, PageLinks links) {
  public PermissionHolderListResponse {
    data = List.copyOf(data);
  }
}
