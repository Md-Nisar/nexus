package com.example.nexus.identity.application.service;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.identity.application.TokenGenerator;
import com.example.nexus.identity.application.TokenHasher;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.application.port.out.RefreshTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AccessTokenResult;
import com.example.nexus.identity.domain.AuthConstants;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.LoginResult;
import com.example.nexus.identity.domain.RefreshToken;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Rotates a refresh token: validates the incoming cookie value, detects theft via the family
 * revocation pattern, revokes the old token under optimistic lock, and issues a new access JWT
 * plus a new refresh token in the same family chain (US-003).
 *
 * <p>Security invariants:
 * <ul>
 *   <li>Presenting a revoked token triggers full family revocation before throwing (theft
 *       detection, T-4.2). {@link SecureEventService#revokeFamily} commits independently of
 *       the outer transaction so revocation is durable even when the outer tx rolls back.
 *   <li>Step 5 {@code save()} uses the {@code @Version} optimistic lock — a concurrent rotation
 *       attempt throws {@link OptimisticLockingFailureException}, which is caught and mapped to
 *       AUTH_004 rather than a 500 error.
 *   <li>User status is re-validated at step 7 — account may have been locked since the token
 *       was issued.
 * </ul>
 */
@Service
@Transactional
public class RefreshTokenUseCase {

  private static final Logger log = LoggerFactory.getLogger(RefreshTokenUseCase.class);
  private static final String AUTH_004 = "AUTH_004";
  private static final String MSG_INVALID = "Refresh token invalid";

  private final RefreshTokenPort refreshTokenPort;
  private final UserRegistrationPort userRegistrationPort;
  private final JwtPort jwtPort;
  private final SecureEventService secureEventService;
  private final UuidGenerator uuidGenerator;
  private final TokenGenerator tokenGenerator;
  private final TokenHasher tokenHasher;
  private final Clock clock;

  /** Constructs the use-case with its required collaborators. */
  public RefreshTokenUseCase(
      RefreshTokenPort refreshTokenPort,
      UserRegistrationPort userRegistrationPort,
      JwtPort jwtPort,
      SecureEventService secureEventService,
      UuidGenerator uuidGenerator,
      TokenGenerator tokenGenerator,
      TokenHasher tokenHasher,
      Clock clock) {
    this.refreshTokenPort = refreshTokenPort;
    this.userRegistrationPort = userRegistrationPort;
    this.jwtPort = jwtPort;
    this.secureEventService = secureEventService;
    this.uuidGenerator = uuidGenerator;
    this.tokenGenerator = tokenGenerator;
    this.tokenHasher = tokenHasher;
    this.clock = clock;
  }

  /**
   * Validates {@code tokenCookieValue}, rotates the refresh token, and returns new credentials.
   *
   * @param tokenCookieValue the raw refresh-token value from the {@code HttpOnly} cookie
   * @param clientIp         the client IP address ({@code request.getRemoteAddr()} only — T-1.3)
   * @return new login result with a fresh access JWT and rotated refresh token
   * @throws AuthenticationException if the token is invalid, revoked, expired, or the account
   *                                  is no longer active (AUTH_004 for all cases)
   */
  public LoginResult execute(String tokenCookieValue, String clientIp) {
    Instant now = clock.instant();

    // Step 1: Hash the incoming cookie value — IllegalArgumentException means the attacker-
    // controlled value is not valid hex; treat identically to unknown-token (uniform 401, T-2.3).
    String hash;
    try {
      hash = tokenHasher.hash(tokenCookieValue);
    } catch (IllegalArgumentException e) {
      secureEventService.recordEvent(failureEvent(null, clientIp, "TOKEN_REFRESH_FAILURE"));
      throw new AuthenticationException(AUTH_004, MSG_INVALID);
    }

    // Step 2: Look up by hash — unknown token is a theft signal
    Optional<RefreshToken> tokenOpt = refreshTokenPort.findByTokenHash(hash);
    if (tokenOpt.isEmpty()) {
      secureEventService.recordEvent(failureEvent(null, clientIp, "TOKEN_REFRESH_FAILURE"));
      throw new AuthenticationException(AUTH_004, MSG_INVALID);
    }
    RefreshToken token = tokenOpt.get();

    // Step 3: Theft detection — revoke entire family BEFORE throwing (T-4.2)
    if (token.getRevokedAt() != null) {
      secureEventService.revokeFamily(token.getFamilyId(), now);
      secureEventService.recordEvent(
          new AuthEvent(uuidGenerator.newId(), "REFRESH_FAMILY_REVOKED", "FAILURE")
              .withUserId(token.getUserId())
              .withIpAddress(clientIp));
      throw new AuthenticationException(AUTH_004, MSG_INVALID);
    }

    // Step 4: Expiry check
    if (token.getExpiresAt().isBefore(now)) {
      secureEventService.recordEvent(failureEvent(token.getUserId(), clientIp, "TOKEN_REFRESH_FAILURE"));
      throw new AuthenticationException(AUTH_004, MSG_INVALID);
    }

    // Step 5: Revoke old token (one-time use) under optimistic lock
    token.revoke(now);
    try {
      refreshTokenPort.save(token);
    } catch (OptimisticLockingFailureException e) {
      // Concurrent rotation — another request already consumed this token
      secureEventService.recordEvent(failureEvent(token.getUserId(), clientIp, "TOKEN_REFRESH_FAILURE"));
      throw new AuthenticationException(AUTH_004, MSG_INVALID);
    }

    // Step 6: Re-fetch user
    User user = userRegistrationPort.findById(token.getUserId())
        .orElseThrow(() -> new AuthenticationException(AUTH_004, MSG_INVALID));

    // Step 7: Re-check status (may have changed since token was issued)
    if (user.getStatus() != UserStatus.ACTIVE) {
      secureEventService.recordEvent(failureEvent(user.getId(), clientIp, "TOKEN_REFRESH_FAILURE"));
      throw new AuthenticationException(AUTH_004, MSG_INVALID);
    }

    // Step 8: Issue new access JWT
    AccessTokenResult accessResult = jwtPort.issue(user);

    // Step 9: Create new refresh token in the same family chain
    String newRaw = tokenGenerator.generate();
    RefreshToken newToken = new RefreshToken(
        uuidGenerator.newId(),
        user.getId(),
        tokenHasher.hash(newRaw),
        token.getFamilyId(),
        now.plus(AuthConstants.AUTH_REFRESH_TOKEN_TTL_DAYS, ChronoUnit.DAYS));
    refreshTokenPort.save(newToken);

    // Step 10: Record success — newRaw exits here ONLY, never logged
    secureEventService.recordEvent(
        new AuthEvent(uuidGenerator.newId(), "TOKEN_REFRESH_SUCCESS", "SUCCESS")
            .withUserId(user.getId())
            .withIpAddress(clientIp));

    log.debug("TOKEN_REFRESH_SUCCESS userId={}", user.getId());
    return new LoginResult(accessResult.token(), accessResult.expiresInSeconds(),
        user.getId().toString(), newRaw);
  }

  private AuthEvent failureEvent(UUID userId, String clientIp, String eventType) {
    return new AuthEvent(uuidGenerator.newId(), eventType, "FAILURE")
        .withUserId(userId)
        .withIpAddress(clientIp);
  }
}
