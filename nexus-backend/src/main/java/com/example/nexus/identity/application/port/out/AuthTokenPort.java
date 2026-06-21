package com.example.nexus.identity.application.port.out;

import com.example.nexus.identity.domain.AuthToken;
import com.example.nexus.identity.domain.AuthTokenType;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Persistence port for {@link AuthToken} lifecycle operations.
 *
 * <p>Implementations live in {@code identity.infrastructure.persistence}.
 */
public interface AuthTokenPort {

  /**
   * Persists a new {@link AuthToken}.
   *
   * @param token the token to save
   * @return the saved token
   */
  AuthToken save(AuthToken token);

  /**
   * Looks up an active (not-yet-consumed) token by its SHA-256 hash.
   *
   * @param tokenHash hex-encoded SHA-256 of the raw token value
   * @return the matching token, or empty if none exists
   */
  Optional<AuthToken> findByTokenHash(String tokenHash);

  /**
   * Counts tokens of a given type issued to a user after a point in time. Used to enforce the
   * per-user resend rate limit (REG-10).
   *
   * @param userId the owning user
   * @param type the token type to count
   * @param since the lower bound (exclusive) of the creation window
   * @return the number of matching tokens
   */
  int countByUserIdAndTypeAndCreatedAtAfter(UUID userId, AuthTokenType type, Instant since);

  /**
   * Marks a token as consumed at the given instant and persists the change.
   *
   * @param token the token to consume
   * @param consumedAt the consumption timestamp
   * @return the updated token
   */
  AuthToken markConsumed(AuthToken token, Instant consumedAt);

  /**
   * Flushes pending writes to the database within the current transaction.
   *
   * <p>Call this immediately after {@link #markConsumed} to force the version-checked UPDATE SQL
   * before the transaction commits, so that {@link org.springframework.dao.OptimisticLockingFailureException}
   * is thrown at a predictable point (inside the caller's try-catch) rather than at commit time.
   */
  void flush();
}
