package com.example.nexus.identity.application;

import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.TokenExpiredException;
import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.AuthToken;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.domain.User;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Verifies an email-verification token and transitions the user from PENDING to ACTIVE.
 * All failure paths emit AUTH_VRF_002 to prevent token-state enumeration (anti-enumeration).
 */
@Service
@Transactional
public class VerifyEmailUseCase {

  private static final String CODE = "AUTH_VRF_002";
  private static final String INVALID_LINK = "The verification link is invalid";
  private static final String EXPIRED_LINK = "The verification link has expired.";
  private static final String VERIFIED_LINK = "The verification link is already verified.";
  private static final String MSG = "The verification link is invalid or has expired.";

  private final AuthTokenPort authTokenPort;
  private final UserRegistrationPort userRegistrationPort;
  private final TokenHasher tokenHasher;
  private final AuthEventPort authEventPort;
  private final UuidGenerator uuidGenerator;

  /** Constructs the use-case with its required collaborators. */
  public VerifyEmailUseCase(
      AuthTokenPort authTokenPort,
      UserRegistrationPort userRegistrationPort,
      TokenHasher tokenHasher,
      AuthEventPort authEventPort,
      UuidGenerator uuidGenerator) {
    this.authTokenPort = authTokenPort;
    this.userRegistrationPort = userRegistrationPort;
    this.tokenHasher = tokenHasher;
    this.authEventPort = authEventPort;
    this.uuidGenerator = uuidGenerator;
  }

  /** Consumes {@code rawToken} and activates the associated user account. */
  public void verify(String rawToken, RequestContext ctx) {
    String tokenHash = tokenHasher.hash(rawToken);
    Instant now = Instant.now();

    Optional<AuthToken> tokenOpt = authTokenPort.findByTokenHash(tokenHash);
    if (tokenOpt.isEmpty()) {
      authEventPort.record(failure(null, ctx));
      throw new TokenExpiredException(CODE, INVALID_LINK);
    }
    AuthToken token = tokenOpt.get();

    if (now.isAfter(token.getExpiresAt())) {
      authEventPort.record(failure(token.getUserId(), ctx));
      throw new TokenExpiredException(CODE, EXPIRED_LINK);
    }

    if (token.getConsumedAt() != null) {
      authEventPort.record(failure(token.getUserId(), ctx));
      throw new TokenExpiredException(CODE, VERIFIED_LINK);
    }

    try {
      authTokenPort.markConsumed(token, now);
      authTokenPort.flush(); // force UPDATE SQL now so version conflict surfaces here, not at commit
    } catch (OptimisticLockingFailureException e) {
      throw new TokenExpiredException(CODE, MSG);
    }

    User user = userRegistrationPort.findById(token.getUserId()).orElse(null);
    if (user == null) {
      authEventPort.record(failure(token.getUserId(), ctx));
      throw new TokenExpiredException(CODE, MSG);
    }

    try {
      user.verify(now);
    } catch (IllegalStateException e) {
      authEventPort.record(failure(token.getUserId(), ctx));
      throw new TokenExpiredException(CODE, MSG);
    }

    userRegistrationPort.save(user);
    authEventPort.record(success(token.getUserId(), ctx));
  }

  private AuthEvent failure(UUID userId, RequestContext ctx) {
    return new AuthEvent(uuidGenerator.newId(), "VERIFICATION_FAILED", "FAILURE")
        .withUserId(userId)
        .withIpAddress(ctx.ipAddress())
        .withMetadata(ctx.toMetadataJson());
  }

  private AuthEvent success(UUID userId, RequestContext ctx) {
    return new AuthEvent(uuidGenerator.newId(), "VERIFICATION_SUCCESS", "SUCCESS")
        .withUserId(userId)
        .withIpAddress(ctx.ipAddress())
        .withMetadata(ctx.toMetadataJson());
  }
}
