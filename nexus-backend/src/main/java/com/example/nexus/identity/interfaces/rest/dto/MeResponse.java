package com.example.nexus.identity.interfaces.rest.dto;

import java.util.List;

public record MeResponse(
    String userId,
    boolean emailVerified,
    String tenantId,
    List<String> roles,
    List<String> permissions,
    int tokenVersion) {

  public MeResponse {
    roles = List.copyOf(roles);
    permissions = List.copyOf(permissions);
  }
}
