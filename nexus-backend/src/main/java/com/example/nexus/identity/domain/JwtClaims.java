package com.example.nexus.identity.domain;

import java.util.List;
import java.util.Set;

/**
 * Parsed, validated claims extracted from a verified RS256 JWT access token.
 * This is the frozen token contract (Sprint 2) — do not add or remove fields without bumping
 * {@link #CURRENT_VERSION} (carried in the {@code schema_version} claim) and a migration plan.
 *
 * <p>{@code tokenVersion} ({@code token_version} claim) is unrelated to the schema version above
 * — it is the per-user password-reset invalidation counter ({@link User#getTokenVersion()}),
 * bumped only when that specific user resets their password.
 *
 * <p>{@code permEpoch} ({@code perm_epoch} claim, v3) is the per-user permission epoch read at
 * mint time (US-018 A9, design §9.2). A request is rejected when it is lower than the user's
 * current epoch. A v2 token carries no such claim and is treated as epoch 0.
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
    int schemaVersion,
    long permEpoch) {

  /** Current frozen-contract schema version — bump whenever a claim is added or removed. */
  public static final int CURRENT_VERSION = 3;

  /**
   * Schema versions {@code verify()} accepts (US-018 Decision 18, ADR-0022 D7). Widened one
   * release ahead of minting, then contracted, so a rolling deploy never 401s a token minted by
   * the other version. M7 mints v3 and still accepts v2 (as epoch 0) until M7b contracts the set
   * to {3}; v3 is frozen as v2 plus {@code perm_epoch}, and any other claim change is v4.
   */
  public static final Set<Integer> ACCEPTED_VERSIONS = Set.of(2, 3);

  /** Defensive copies prevent callers from mutating the roles/permissions lists after construction. */
  public JwtClaims {
    roles = List.copyOf(roles);
    permissions = List.copyOf(permissions);
  }
}
