package com.example.nexus.identity.application.service;

import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.application.port.out.RefreshTokenPort;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Clock;
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
  private final UuidGenerator uuidGenerator;
  private final Clock clock;

  public LogoutUseCase(
      RefreshTokenPort refreshTokenPort,
      AuthEventPort authEventPort,
      UuidGenerator uuidGenerator,
      Clock clock) {
    this.refreshTokenPort = refreshTokenPort;
    this.authEventPort = authEventPort;
    this.uuidGenerator = uuidGenerator;
    this.clock = clock;
  }

  /**
   * Revokes all active refresh tokens for {@code userId} and records a LOGOUT audit event.
   *
   * @param userId   authenticated user's UUID, or {@code null} for unauthenticated logout
   *                 (cookie-clear only — no tokens to revoke)
   * @param clientIp request remote address (T-1.3: {@code getRemoteAddr()} only)
   */
  public void execute(UUID userId, String clientIp) {
    if (userId != null) {
      refreshTokenPort.revokeByUserId(userId, clock.instant());
    }
    authEventPort.record(
        new AuthEvent(uuidGenerator.newId(), "LOGOUT", "SUCCESS")
            .withUserId(userId)
            .withIpAddress(clientIp));
  }
}
