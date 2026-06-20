package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.domain.AuthToken;
import com.example.nexus.identity.domain.AuthTokenType;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * JPA-backed {@link AuthTokenPort}.
 *
 * <p>Concurrent consumption of the same token is prevented by the {@code @Version} optimistic-lock
 * on {@link AuthToken}. Callers of {@link #markConsumed} must handle
 * {@link org.springframework.dao.OptimisticLockingFailureException} and treat it as a
 * consumed-token scenario (→ 410 TokenExpiredException).
 */
@Component
public class JpaAuthTokenAdapter implements AuthTokenPort {

  private final JpaAuthTokenRepository tokenRepository;

  public JpaAuthTokenAdapter(JpaAuthTokenRepository tokenRepository) {
    this.tokenRepository = tokenRepository;
  }

  @Override
  public AuthToken save(AuthToken token) {
    return tokenRepository.save(token);
  }

  @Override
  public Optional<AuthToken> findByTokenHash(String tokenHash) {
    return tokenRepository.findByTokenHash(tokenHash);
  }

  @Override
  public int countByUserIdAndTypeAndCreatedAtAfter(UUID userId, AuthTokenType type, Instant since) {
    return tokenRepository.countByUserIdAndTypeAndCreatedAtAfter(userId, type, since);
  }

  @Override
  public AuthToken markConsumed(AuthToken token, Instant consumedAt) {
    token.consume(consumedAt);
    return tokenRepository.save(token);
  }

  @Override
  public void flush() {
    tokenRepository.flush();
  }
}
