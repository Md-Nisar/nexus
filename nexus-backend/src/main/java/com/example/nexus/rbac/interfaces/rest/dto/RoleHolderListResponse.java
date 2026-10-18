package com.example.nexus.rbac.interfaces.rest.dto;

import java.util.List;

/** Envelope for {@code GET /api/v1/roles/{roleId}/holders} (US-018 C3): data, page, links. */
public record RoleHolderListResponse(
    List<RoleHolderResponse> data, PageMetadata page, PageLinks links) {
  public RoleHolderListResponse {
    data = List.copyOf(data);
  }
}
