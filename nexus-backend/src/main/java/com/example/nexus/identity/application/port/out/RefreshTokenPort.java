package com.example.nexus.identity.application.port.out;

import com.example.nexus.identity.domain.RefreshToken;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Persistence port for refresh token lifecycle operations.
 * Separate from {@link AuthTokenPort} which handles email-verification tokens.
 * Implementations live in {@code identity.infrastructure.persistence}.
 */
public interface RefreshTokenPort {

  /**
   * Persists a new or updated {@link RefreshToken}.
   *
   * @param token the token to save
   */
  void save(RefreshToken token);

  /**
   * Looks up a refresh token by its SHA-256 hash.
   *
   * @param tokenHash hex-encoded SHA-256 of the raw token value
   * @return the matching token, or empty if none exists
   */
  Optional<RefreshToken> findByTokenHash(String tokenHash);

  /**
   * Revokes all active (non-revoked) tokens in the given family.
   * Used for theft detection: when a revoked token is presented, the entire family is revoked.
   *
   * @param familyId the token family to revoke
   * @param revokedAt the revocation timestamp
   */
  void revokeFamily(UUID familyId, Instant revokedAt);

  /**
   * Revokes all active tokens belonging to a user.
   * Used for logout-all, password change, and account lock operations (US-005).
   *
   * @param userId the owning user
   * @param revokedAt the revocation timestamp
   */
  void revokeByUserId(UUID userId, Instant revokedAt);
}
