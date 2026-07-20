package com.example.nexus.identity.domain;

import java.util.List;

/**
 * Parsed, validated claims extracted from a verified RS256 JWT access token.
 * This is the frozen token contract (Sprint 2) — do not add or remove fields without bumping
 * {@link #CURRENT_VERSION} (carried in the {@code schema_version} claim) and a migration plan.
 *
 * <p>{@code tokenVersion} ({@code token_version} claim) is unrelated to the schema version above
 * — it is the per-user password-reset invalidation counter ({@link User#getTokenVersion()}),
 * bumped only when that specific user resets their password.
 *
 * <p>Contains no PII — {@code sub} is a UUID, {@code email} is intentionally absent.
 */
public record JwtClaims(
    String sub,
    String tenantId,
    boolean emailVerified,
    List<String> roles,
    List<String> permissions,
    long iat,
    long exp,
    String jti,
    int tokenVersion,
    int schemaVersion) {

  /** Current frozen-contract schema version — bump whenever a claim is added or removed. */
  public static final int CURRENT_VERSION = 2;

  /** Defensive copies prevent callers from mutating the roles/permissions lists after construction. */
  public JwtClaims {
    roles = List.copyOf(roles);
    permissions = List.copyOf(permissions);
  }
}
