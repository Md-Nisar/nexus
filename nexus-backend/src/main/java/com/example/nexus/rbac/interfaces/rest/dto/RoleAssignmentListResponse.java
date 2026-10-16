package com.example.nexus.rbac.interfaces.rest.dto;

import java.util.List;

/**
 * Envelope for {@code GET /api/v1/users/{userId}/roles} (03-design.md §8.3/D7; paginated by
 * US-018 C2): {@code data}, {@link PageMetadata} and {@link PageLinks}. Ordered by {@code
 * (assignedAt, id)}, a total order.
 */
public record RoleAssignmentListResponse(
    List<RoleAssignmentResponse> data, PageMetadata page, PageLinks links) {
  public RoleAssignmentListResponse {
    data = List.copyOf(data);
  }
}
