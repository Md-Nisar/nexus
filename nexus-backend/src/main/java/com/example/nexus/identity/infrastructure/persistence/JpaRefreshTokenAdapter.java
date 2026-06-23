package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.application.port.out.RefreshTokenPort;
import com.example.nexus.identity.domain.RefreshToken;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * JPA-backed {@link RefreshTokenPort}.
 *
 * <p>Bulk revocations use JPQL UPDATE queries that skip already-revoked tokens
 * ({@code WHERE revokedAt IS NULL}), making {@link #revokeFamily} and {@link #revokeByUserId}
 * naturally idempotent. Concurrent single-token rotation is protected by the
 * {@code @Version} optimistic lock on {@link RefreshToken}.
 */
@Component
public class JpaRefreshTokenAdapter implements RefreshTokenPort {

  private final JpaRefreshTokenRepository repo;

  public JpaRefreshTokenAdapter(JpaRefreshTokenRepository repo) {
    this.repo = repo;
  }

  @Override
  public void save(RefreshToken token) {
    repo.save(token);
  }

  @Override
  public Optional<RefreshToken> findByTokenHash(String tokenHash) {
    return repo.findByTokenHash(tokenHash);
  }

  @Override
  public void revokeFamily(UUID familyId, Instant revokedAt) {
    repo.revokeByFamilyId(familyId, revokedAt);
  }

  @Override
  public void revokeByUserId(UUID userId, Instant revokedAt) {
    repo.revokeByUserId(userId, revokedAt);
  }
}
