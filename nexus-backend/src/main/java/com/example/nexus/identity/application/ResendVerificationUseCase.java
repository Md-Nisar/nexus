package com.example.nexus.identity.application;

import com.example.nexus.common.domain.RateLimitException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.application.event.VerificationEmailEvent;
import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AuthConstants;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.AuthEventType;
import com.example.nexus.identity.domain.AuthToken;
import com.example.nexus.identity.domain.AuthTokenType;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import java.time.Instant;
import java.util.UUID;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Resends a verification email for a PENDING-status user.
 * Returns silently for unknown or non-PENDING accounts (anti-enumeration).
 */
@Service
@Transactional
public class ResendVerificationUseCase {

  private static final String RATE_CODE = "AUTH_RES_001";
  private static final String RATE_MSG =
      "Too many resend requests. Please wait before trying again.";

  private final UserRegistrationPort userRegistrationPort;
  private final AuthTokenPort authTokenPort;
  private final EmailBlindIndexService emailBlindIndexService;
  private final TokenGenerator tokenGenerator;
  private final TokenHasher tokenHasher;
  private final AuthEventPort authEventPort;
  private final UuidGenerator uuidGenerator;
  private final ApplicationEventPublisher eventPublisher;

  /** Constructs the use-case with its required collaborators. */
  public ResendVerificationUseCase(
      UserRegistrationPort userRegistrationPort,
      AuthTokenPort authTokenPort,
      EmailBlindIndexService emailBlindIndexService,
      TokenGenerator tokenGenerator,
      TokenHasher tokenHasher,
      AuthEventPort authEventPort,
      UuidGenerator uuidGenerator,
      ApplicationEventPublisher eventPublisher) {
    this.userRegistrationPort = userRegistrationPort;
    this.authTokenPort = authTokenPort;
    this.emailBlindIndexService = emailBlindIndexService;
    this.tokenGenerator = tokenGenerator;
    this.tokenHasher = tokenHasher;
    this.authEventPort = authEventPort;
    this.uuidGenerator = uuidGenerator;
    this.eventPublisher = eventPublisher;
  }

  /** Sends a new verification email if the account is PENDING and within rate limits. */
  public void resend(UUID tenantId, String rawEmail, RequestContext ctx) {
    String emailHmac = emailBlindIndexService.blindIndex(rawEmail);

    User user = userRegistrationPort
        .findByTenantAndEmailHmac(tenantId, emailHmac)
        .orElse(null);
    if (user == null || user.getStatus() != UserStatus.PENDING) {
      return;
    }

    UUID userId = user.getId();
    enforceRateLimit(tenantId, userId, ctx);

    String rawToken = tokenGenerator.generate();
    String tokenHash = tokenHasher.hash(rawToken);
    Instant expiresAt = Instant.now().plus(AuthConstants.AUTH_VERIFICATION_TOKEN_TTL);

    AuthToken token = AuthToken.forVerification(uuidGenerator.newId(), userId, tokenHash, expiresAt);
    authTokenPort.save(token);

    eventPublisher.publishEvent(new VerificationEmailEvent(rawEmail, rawToken, userId));
    authEventPort.record(
        new AuthEvent(uuidGenerator.newId(), AuthEventType.RESEND_REQUESTED, "SUCCESS")
            .withUserId(userId)
            .withTenantId(tenantId)
            .withIpAddress(ctx.ipAddress())
            .withMetadata(ctx.toMetadataJson()));
  }

  private void enforceRateLimit(UUID tenantId, UUID userId, RequestContext ctx) {
    Instant now = Instant.now();
    if (authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(
        userId, AuthTokenType.VERIFICATION, now.minusSeconds(60)) >= 1) {
      authEventPort.record(
          new AuthEvent(uuidGenerator.newId(), AuthEventType.RESEND_THROTTLED, "BLOCKED")
              .withUserId(userId)
              .withTenantId(tenantId)
              .withIpAddress(ctx.ipAddress())
              .withMetadata(ctx.toMetadataJson()));
      throw new RateLimitException(RATE_CODE, RATE_MSG, 60L);
    }
    if (authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(
        userId, AuthTokenType.VERIFICATION, now.minusSeconds(86_400)) >= 5) {
      authEventPort.record(
          new AuthEvent(uuidGenerator.newId(), AuthEventType.RESEND_THROTTLED, "BLOCKED")
              .withUserId(userId)
              .withTenantId(tenantId)
              .withIpAddress(ctx.ipAddress())
              .withMetadata(ctx.toMetadataJson()));
      throw new RateLimitException(RATE_CODE, RATE_MSG, 3_600L);
    }
  }
}
