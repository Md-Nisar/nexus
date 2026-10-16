package com.example.nexus.rbac.interfaces.rest.dto;

import java.util.List;

/**
 * Envelope for {@code GET /api/v1/roles} (03-design.md §8.2, D11; paginated by US-018 C2): {@code
 * data}, {@link PageMetadata} and {@link PageLinks}, per the api-design skill's Collections shape.
 * Ordered by {@code (name, id)}, a total order, so pages neither overlap nor skip rows under
 * concurrent writes.
 */
public record RoleListResponse(List<RoleResponse> data, PageMetadata page, PageLinks links) {
  public RoleListResponse {
    data = List.copyOf(data);
  }
}
