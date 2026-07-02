package com.example.nexus.identity.application;

import com.example.nexus.common.domain.FieldValidationException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.TokenExpiredException;
import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.PasswordVerifierPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.application.service.SecureEventService;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.AuthEventType;
import com.example.nexus.identity.domain.AuthToken;
import com.example.nexus.identity.domain.AuthTokenType;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Redeems a password-reset token and sets a new password (US-007, AC-2 through AC-6).
 *
 * <p>Transaction boundary: all writes (token consumed, user updated) commit together. Session
 * revocation runs in a separate REQUIRES_NEW sub-transaction via {@link SecureEventService} to
 * guarantee durability independent of the outer transaction.
 */
@Service
@Transactional
public class ResetPasswordUseCase {

  private static final Logger log = LoggerFactory.getLogger(ResetPasswordUseCase.class);

  private static final String CODE_EXPIRED = "AUTH_RST_002";
  private static final String CODE_SAME_PASSWORD = "AUTH_RST_003";
  private static final String MSG_EXPIRED =
      "This reset link has expired or already been used. Please request a new one.";
  private static final String MSG_SAME_PASSWORD =
      "New password must be different from your current password.";

  private final AuthTokenPort authTokenPort;
  private final UserRegistrationPort userRegistrationPort;
  private final PasswordPolicyService passwordPolicyService;
  private final PasswordVerifierPort passwordVerifier;
  private final PasswordHasherPort passwordHasher;
  private final SecureEventService secureEventService;
  private final TokenHasher tokenHasher;
  private final UuidGenerator uuidGenerator;
  private final Clock clock;

  /** Constructs the use-case with its required collaborators. */
  public ResetPasswordUseCase(
      AuthTokenPort authTokenPort,
      UserRegistrationPort userRegistrationPort,
      PasswordPolicyService passwordPolicyService,
      PasswordVerifierPort passwordVerifier,
      PasswordHasherPort passwordHasher,
      SecureEventService secureEventService,
      TokenHasher tokenHasher,
      UuidGenerator uuidGenerator,
      Clock clock) {
    this.authTokenPort = authTokenPort;
    this.userRegistrationPort = userRegistrationPort;
    this.passwordPolicyService = passwordPolicyService;
    this.passwordVerifier = passwordVerifier;
    this.passwordHasher = passwordHasher;
    this.secureEventService = secureEventService;
    this.tokenHasher = tokenHasher;
    this.uuidGenerator = uuidGenerator;
    this.clock = clock;
  }

  /**
   * Validates {@code rawToken}, enforces password policy, and updates the user's credential.
   *
   * @param rawToken    the 64-char hex token from the reset email link
   * @param newPassword the new plaintext password supplied by the user
   * @param ctx         per-request context (IP, traceId) for audit events
   * @throws TokenExpiredException    (AUTH_RST_002 / 410) if the token is not found, expired, or
   *                                  already consumed
   * @throws FieldValidationException (AUTH_PWD_001 / 400) if new password is too short
   * @throws FieldValidationException (AUTH_PWD_002 / 400) if new password is in the denylist
   * @throws FieldValidationException (AUTH_RST_003 / 400) if new password equals current
   */
  public void execute(String rawToken, String newPassword, RequestContext ctx) {
    String tokenHash = tokenHasher.hash(rawToken);
    Instant now = clock.instant();

    Optional<AuthToken> tokenOpt = authTokenPort.findByTokenHash(tokenHash);
    if (tokenOpt.isEmpty()) {
      recordFailure(null, ctx);
      throw new TokenExpiredException(CODE_EXPIRED, MSG_EXPIRED);
    }

    AuthToken token = tokenOpt.get();

    if (token.getType() != AuthTokenType.RESET) {
      recordFailure(token.getUserId(), ctx);
      throw new TokenExpiredException(CODE_EXPIRED, MSG_EXPIRED);
    }

    if (now.isAfter(token.getExpiresAt())) {
      recordFailure(token.getUserId(), ctx);
      throw new TokenExpiredException(CODE_EXPIRED, MSG_EXPIRED);
    }

    if (token.getConsumedAt() != null) {
      recordFailure(token.getUserId(), ctx);
      throw new TokenExpiredException(CODE_EXPIRED, MSG_EXPIRED);
    }

    passwordPolicyService.validate(newPassword);

    User user = userRegistrationPort.findById(token.getUserId())
        .orElseThrow(() -> new IllegalStateException(
            "User not found for valid reset token userId=" + token.getUserId()));

    if (passwordVerifier.matches(newPassword, user.getPasswordHash())) {
      throw new FieldValidationException(CODE_SAME_PASSWORD, "password", MSG_SAME_PASSWORD);
    }

    // Mark consumed first so a concurrent duplicate request fails fast without paying the
    // full Argon2 hash cost (OptimisticLockingFailureException → 410).
    try {
      authTokenPort.markConsumed(token, now);
      authTokenPort.flush();
    } catch (OptimisticLockingFailureException e) {
      throw new TokenExpiredException(CODE_EXPIRED, MSG_EXPIRED);
    }

    String newHash = passwordHasher.hash(newPassword);

    user.applyPasswordReset(newHash);
    userRegistrationPort.save(user);

    try {
      secureEventService.revokeAllUserSessions(user.getId(), now);
    } catch (RuntimeException e) {
      log.warn("SESSION_REVOCATION_PARTIAL userId={} reason={}", user.getId(), e.getMessage());
    }

    secureEventService.recordEvent(
        new AuthEvent(uuidGenerator.newId(), AuthEventType.PASSWORD_CHANGED, "SUCCESS")
            .withUserId(user.getId())
            .withTenantId(user.getTenantId())
            .withIpAddress(ctx.ipAddress())
            .withMetadata(ctx.toMetadataJson()));

    log.debug("PASSWORD_CHANGED userId={}", user.getId());
  }

  private void recordFailure(java.util.UUID userId, RequestContext ctx) {
    // REQUIRES_NEW on recordEvent is load-bearing: this audit commit must survive the outer
    // @Transactional rollback that happens when TokenExpiredException propagates to the caller.
    // Do not remove REQUIRES_NEW from SecureEventService.recordEvent without adding
    // noRollbackFor = TokenExpiredException.class to this method instead.
    secureEventService.recordEvent(
        new AuthEvent(uuidGenerator.newId(), AuthEventType.PASSWORD_RESET_FAILED, "FAILURE")
            .withUserId(userId)
            .withIpAddress(ctx.ipAddress())
            .withMetadata(ctx.toMetadataJson()));
  }
}
