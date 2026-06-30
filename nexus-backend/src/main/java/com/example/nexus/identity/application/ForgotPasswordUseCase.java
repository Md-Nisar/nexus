package com.example.nexus.identity.application;

import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.application.event.PasswordResetEmailEvent;
import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.application.service.SecureEventService;
import com.example.nexus.identity.domain.AuthConstants;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.AuthToken;
import com.example.nexus.identity.domain.AuthTokenType;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Initiates a self-service password reset (US-007, AC-1, AC-5).
 *
 * <p>Always returns normally regardless of whether the email is registered — the controller
 * always responds 202 (anti-enumeration, T-I1). Email dispatch is async via
 * {@link PasswordResetEmailEvent} and {@code @TransactionalEventListener(AFTER_COMMIT)}.
 *
 * <p>Throttle (AC-5): max {@value MAX_RESETS_PER_HOUR} reset tokens per account per hour.
 * Excess requests are silently accepted by the caller but no email is sent; a
 * {@code PASSWORD_RESET_THROTTLED} audit event is recorded instead.
 */
@Service
@Transactional
public class ForgotPasswordUseCase {

  static final int MAX_RESETS_PER_HOUR = 3;

  private static final Logger log = LoggerFactory.getLogger(ForgotPasswordUseCase.class);

  private final UserRegistrationPort userRegistrationPort;
  private final AuthTokenPort authTokenPort;
  private final EmailBlindIndexService emailBlindIndexService;
  private final TokenGenerator tokenGenerator;
  private final TokenHasher tokenHasher;
  private final SecureEventService secureEventService;
  private final UuidGenerator uuidGenerator;
  private final ApplicationEventPublisher eventPublisher;
  private final Clock clock;

  /** Constructs the use-case with its required collaborators. */
  public ForgotPasswordUseCase(
      UserRegistrationPort userRegistrationPort,
      AuthTokenPort authTokenPort,
      EmailBlindIndexService emailBlindIndexService,
      TokenGenerator tokenGenerator,
      TokenHasher tokenHasher,
      SecureEventService secureEventService,
      UuidGenerator uuidGenerator,
      ApplicationEventPublisher eventPublisher,
      Clock clock) {
    this.userRegistrationPort = userRegistrationPort;
    this.authTokenPort = authTokenPort;
    this.emailBlindIndexService = emailBlindIndexService;
    this.tokenGenerator = tokenGenerator;
    this.tokenHasher = tokenHasher;
    this.secureEventService = secureEventService;
    this.uuidGenerator = uuidGenerator;
    this.eventPublisher = eventPublisher;
    this.clock = clock;
  }

  /**
   * Handles a password-reset request for {@code rawEmail} under {@code tenantId}.
   * The {@code ctx} carries the client IP for audit events.
   *
   * <p>Returns normally in all cases; the controller always responds 202 (AC-1).
   *
   * @param tenantId the owning tenant
   * @param rawEmail normalised email address (lowercased and stripped by the caller)
   * @param ctx      per-request context (IP, traceId)
   */
  public void execute(UUID tenantId, String rawEmail, RequestContext ctx) {
    String emailHmac = emailBlindIndexService.blindIndex(rawEmail);
    Optional<User> userOpt = userRegistrationPort.findByTenantAndEmailHmac(tenantId, emailHmac);

    if (userOpt.isEmpty()) {
      // Constant-time dummy equalises CPU-bound work (SecureRandom + hex) with the found path.
      // Residual DB round-trip difference (1 COUNT + 1 INSERT on the found path) is accepted.
      tokenGenerator.generate();
      return;
    }

    User user = userOpt.get();
    Instant now = clock.instant();
    Instant sinceOneHour = now.minus(1, ChronoUnit.HOURS);
    int resetCount = authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(
        user.getId(), AuthTokenType.RESET, sinceOneHour);

    if (resetCount >= MAX_RESETS_PER_HOUR) {
      log.debug("PASSWORD_RESET_THROTTLED userId={}", user.getId());
      secureEventService.recordEvent(
          new AuthEvent(uuidGenerator.newId(), "PASSWORD_RESET_THROTTLED", "FAILURE")
              .withUserId(user.getId())
              .withIpAddress(ctx.ipAddress())
              .withMetadata(ctx.toMetadataJson()));
      return;
    }

    String rawToken = tokenGenerator.generate();
    String tokenHash = tokenHasher.hash(rawToken);
    Instant expiresAt = now.plus(AuthConstants.AUTH_RESET_TOKEN_TTL);
    authTokenPort.save(AuthToken.forReset(uuidGenerator.newId(), user.getId(), tokenHash, expiresAt));

    // Audit event recorded in REQUIRES_NEW before publishEvent so it commits even if a
    // synchronous listener throws (publishEvent is synchronous and propagates exceptions).
    secureEventService.recordEvent(
        new AuthEvent(uuidGenerator.newId(), "PASSWORD_RESET_REQUESTED", "SUCCESS")
            .withUserId(user.getId())
            .withIpAddress(ctx.ipAddress())
            .withMetadata(ctx.toMetadataJson()));

    String plaintextEmail = user.getEmailCipher().value();
    eventPublisher.publishEvent(new PasswordResetEmailEvent(plaintextEmail, rawToken, user.getId()));
  }
}
