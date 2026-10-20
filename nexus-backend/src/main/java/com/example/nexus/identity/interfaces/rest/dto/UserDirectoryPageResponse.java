package com.example.nexus.identity.interfaces.rest.dto;

import java.util.List;

/**
 * Envelope of {@code GET /api/v1/users} in list and {@code ids} mode (US-019 B1, B2): the same
 * shape as the RBAC page envelopes ({@code PagingEnvelopeShapeTest}).
 */
public record UserDirectoryPageResponse(
    List<UserDirectoryEntryResponse> data, DirectoryPageMetadata page, DirectoryPageLinks links) {

  public UserDirectoryPageResponse {
    data = List.copyOf(data);
  }
}
