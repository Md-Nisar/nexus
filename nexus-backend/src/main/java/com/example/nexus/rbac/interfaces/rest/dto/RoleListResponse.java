package com.example.nexus.rbac.interfaces.rest.dto;

import java.util.List;

/**
 * Envelope for {@code GET /api/v1/roles} (03-design.md §8.2, D11). Unbounded and unpaginated by
 * design — {@code page}/{@code links} can be added additively later precisely because of this
 * {@code {"data": […]}} envelope; a bare top-level array could only gain them via a breaking
 * change.
 */
public record RoleListResponse(List<RoleResponse> data) {
  public RoleListResponse {
    data = List.copyOf(data);
  }
}
