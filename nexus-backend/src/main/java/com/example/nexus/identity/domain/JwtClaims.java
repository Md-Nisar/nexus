package com.example.nexus.identity.domain;

import java.util.List;

/**
 * Parsed, validated claims extracted from a verified RS256 JWT access token.
 * This is the frozen token contract (Sprint 2); do not add or remove fields without a
 * token_version bump and a migration plan.
 *
 * <p>Contains no PII — {@code sub} is a UUID, {@code email} is intentionally absent.
 */
public record JwtClaims(
    String sub,
    String tenantId,
    boolean emailVerified,
    List<String> roles,
    long iat,
    long exp,
    String jti,
    int tokenVersion) {

  /** Defensive copy prevents callers from mutating the roles list after construction. */
  public JwtClaims {
    roles = List.copyOf(roles);
  }
}
