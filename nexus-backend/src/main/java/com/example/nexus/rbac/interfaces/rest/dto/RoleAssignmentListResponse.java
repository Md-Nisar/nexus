package com.example.nexus.rbac.interfaces.rest.dto;

import java.util.List;

/**
 * Envelope for {@code GET /api/v1/users/{userId}/roles} (03-design.md §8.3/D7). No pagination —
 * the result set is provably bounded (at most one active assignment per role, per tenant).
 */
public record RoleAssignmentListResponse(List<RoleAssignmentResponse> data) {
  public RoleAssignmentListResponse {
    data = List.copyOf(data);
  }
}
