package com.example.nexus.identity.application.service;

import com.example.nexus.identity.application.TokenHasher;
import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.application.port.out.RefreshTokenPort;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.RefreshToken;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Clock;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Revokes all server-side refresh tokens for the user and records a LOGOUT audit event (US-003).
 *
 * <p>Revocation and audit participate in a single {@code @Transactional} boundary so they
 * commit atomically — an infrastructure failure rolls both back, preventing a phantom
 * LOGOUT event with no corresponding token revocation.
 */
@Service
@Transactional
public class LogoutUseCase {

  private final RefreshTokenPort refreshTokenPort;
  private final AuthEventPort authEventPort;
  private final TokenHasher tokenHasher;
  private final UuidGenerator uuidGenerator;
  private final Clock clock;

  public LogoutUseCase(
      RefreshTokenPort refreshTokenPort,
      AuthEventPort authEventPort,
      TokenHasher tokenHasher,
      UuidGenerator uuidGenerator,
      Clock clock) {
    this.refreshTokenPort = refreshTokenPort;
    this.authEventPort = authEventPort;
    this.tokenHasher = tokenHasher;
    this.uuidGenerator = uuidGenerator;
    this.clock = clock;
  }

  /**
   * Revokes all active refresh tokens for the user and records a LOGOUT audit event (T-7.1).
   *
   * <p>When {@code userId} is available (Bearer token present), revocation uses it directly.
   * When {@code userId} is null but {@code rawRefreshToken} is present, the token is hashed and
   * looked up to derive the userId — this closes the T-7.1 gap for token-less logout (e.g. the
   * user's access token has expired but the refresh cookie is still present). Malformed or
   * unknown cookies degrade gracefully to cookie-clear only.
   *
   * @param userId          authenticated user's UUID from the Bearer token, or {@code null}
   * @param rawRefreshToken raw refresh-token cookie value, or {@code null} if absent
   * @param clientIp        request remote address (T-1.3: {@code getRemoteAddr()} only)
   */
  public void execute(UUID userId, String rawRefreshToken, String clientIp) {
    UUID resolvedUserId = userId;

    if (resolvedUserId == null && rawRefreshToken != null) {
      // Attempt to resolve the user from the refresh cookie so we can revoke all their tokens.
      // Any failure (malformed cookie, unknown hash) degrades gracefully — the cookie is still
      // cleared by the controller, which is the client-visible effect of logout.
      try {
        String hash = tokenHasher.hash(rawRefreshToken);
        Optional<RefreshToken> tokenOpt = refreshTokenPort.findByTokenHash(hash);
        if (tokenOpt.isPresent()) {
          resolvedUserId = tokenOpt.get().getUserId();
        }
      } catch (IllegalArgumentException ignored) {
        // malformed cookie — not a valid hex token, nothing to revoke
      }
    }

    if (resolvedUserId != null) {
      refreshTokenPort.revokeByUserId(resolvedUserId, clock.instant());
    }
    authEventPort.record(
        new AuthEvent(uuidGenerator.newId(), "LOGOUT", "SUCCESS")
            .withUserId(resolvedUserId)
            .withIpAddress(clientIp));
  }
}
