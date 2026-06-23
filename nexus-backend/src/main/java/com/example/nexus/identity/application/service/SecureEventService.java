package com.example.nexus.identity.application.service;

import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.application.port.out.RefreshTokenPort;
import com.example.nexus.identity.domain.AuthEvent;
import java.time.Instant;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Application-layer service for security-critical writes that must commit independently
 * of the surrounding request transaction.
 *
 * <p>REQUIRES_NEW on each method ensures audit events and family revocations are durably
 * recorded even when the caller's {@code @Transactional} rolls back (e.g. on
 * {@code AuthenticationException} from a failed login attempt). Placing
 * {@code @Transactional} here rather than on the infrastructure adapters keeps transaction
 * demarcation decisions at the application layer per the project convention.
 */
@Service
public class SecureEventService {

  private final AuthEventPort authEventPort;
  private final RefreshTokenPort refreshTokenPort;

  public SecureEventService(AuthEventPort authEventPort, RefreshTokenPort refreshTokenPort) {
    this.authEventPort = authEventPort;
    this.refreshTokenPort = refreshTokenPort;
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void recordEvent(AuthEvent event) {
    authEventPort.record(event);
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void revokeFamily(UUID familyId, Instant revokedAt) {
    refreshTokenPort.revokeFamily(familyId, revokedAt);
  }
}
