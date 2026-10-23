package com.example.nexus.identity.interfaces.rest.dto;

import java.util.List;

/**
 * Response of {@code POST /api/v1/users/lookup} (US-019 B1, design §4.2): {@code data} holds the
 * one matching user of the caller's tenant, or is empty. A miss and another tenant's user are the
 * same empty body.
 */
public record UserLookupResponse(List<UserDirectoryEntryResponse> data) {

  public UserLookupResponse {
    data = List.copyOf(data);
  }
}
