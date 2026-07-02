package com.example.nexus.identity.application;

import com.example.nexus.common.domain.LogMaskingUtil;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.application.event.AccountExistsEmailEvent;
import com.example.nexus.identity.application.event.VerificationEmailEvent;
import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AuthConstants;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.AuthEventType;
import com.example.nexus.identity.domain.AuthToken;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Registers a new user or silently acknowledges a duplicate (anti-enumeration, SEC-4).
 *
 * <p>The Argon2id hash is computed on every call — before the duplicate check — so both
 * paths take similar wall-clock time, making it harder for attackers to infer whether an
 * email address is already registered via response timing.
 *
 * <p>The {@code REGISTER}/{@code REGISTRATION_DUPLICATE_EMAIL} audit write stays in this
 * same {@code @Transactional} boundary as the {@code users} INSERT — via {@link AuthEventPort}
 * directly, never {@code SecureEventService}/REQUIRES_NEW — so a late rollback undoes both
 * together, never leaving a {@code REGISTER} event for a user that doesn't exist (US-008 design
 * §7.1, T-08-08, T-R2).
 */
@Service
@Transactional
public class RegisterUserUseCase {

  private static final Logger log = LoggerFactory.getLogger(RegisterUserUseCase.class);

  private final UserRegistrationPort userRegistrationPort;
  private final AuthTokenPort authTokenPort;
  private final EmailBlindIndexService emailBlindIndexService;
  private final PasswordPolicyService passwordPolicyService;
  private final PasswordHasherPort passwordHasherPort;
  private final TokenGenerator tokenGenerator;
  private final TokenHasher tokenHasher;
  private final AuthEventPort authEventPort;
  private final UuidGenerator uuidGenerator;
  private final ApplicationEventPublisher eventPublisher;

  /** Constructs the use-case with its required collaborators. */
  public RegisterUserUseCase(
      UserRegistrationPort userRegistrationPort,
      AuthTokenPort authTokenPort,
      EmailBlindIndexService emailBlindIndexService,
      PasswordPolicyService passwordPolicyService,
      PasswordHasherPort passwordHasherPort,
      TokenGenerator tokenGenerator,
      TokenHasher tokenHasher,
      AuthEventPort authEventPort,
      UuidGenerator uuidGenerator,
      ApplicationEventPublisher eventPublisher) {
    this.userRegistrationPort = userRegistrationPort;
    this.authTokenPort = authTokenPort;
    this.emailBlindIndexService = emailBlindIndexService;
    this.passwordPolicyService = passwordPolicyService;
    this.passwordHasherPort = passwordHasherPort;
    this.tokenGenerator = tokenGenerator;
    this.tokenHasher = tokenHasher;
    this.authEventPort = authEventPort;
    this.uuidGenerator = uuidGenerator;
    this.eventPublisher = eventPublisher;
  }

  /** Registers {@code rawEmail} under {@code tenantId}, or silently acknowledges a duplicate. */
  public void register(UUID tenantId, String rawEmail, String rawPassword, RequestContext ctx) {
    passwordPolicyService.validate(rawPassword);

    String emailHmac = emailBlindIndexService.blindIndex(rawEmail);
    // Hash before duplicate check — equalises timing across new and duplicate paths (SEC-5).
    String passwordHash = passwordHasherPort.hash(rawPassword);

    Optional<User> existing = userRegistrationPort.findByTenantAndEmailHmac(tenantId, emailHmac);
    if (existing.isPresent()) {
      log.debug("Duplicate registration for tenant {} email {}",
          tenantId, LogMaskingUtil.maskEmail(rawEmail));
      eventPublisher.publishEvent(new AccountExistsEmailEvent(rawEmail));
      authEventPort.record(
          new AuthEvent(uuidGenerator.newId(), AuthEventType.REGISTRATION_DUPLICATE_EMAIL, "BLOCKED")
              .withUserId(existing.get().getId())
              .withTenantId(tenantId)
              .withIpAddress(ctx.ipAddress())
              .withMetadata(ctx.toMetadataJson()));
      return;
    }

    Instant now = Instant.now();
    UUID userId = uuidGenerator.newId();

    // EmailCipher holds plaintext; AttributeEncryptor transparently encrypts at the JPA boundary.
    User user = new User(userId, tenantId, new EmailCipher(rawEmail), emailHmac, passwordHash, now);
    userRegistrationPort.save(user);
    log.debug("User {} registered in tenant {}", userId, tenantId);

    String rawToken = tokenGenerator.generate();
    String tokenHash = tokenHasher.hash(rawToken);
    AuthToken token = AuthToken.forVerification(
        uuidGenerator.newId(), userId, tokenHash,
        now.plus(AuthConstants.AUTH_VERIFICATION_TOKEN_TTL));
    authTokenPort.save(token);

    eventPublisher.publishEvent(new VerificationEmailEvent(rawEmail, rawToken, userId));
    authEventPort.record(
        new AuthEvent(uuidGenerator.newId(), AuthEventType.REGISTER, "SUCCESS")
            .withUserId(userId)
            .withTenantId(tenantId)
            .withIpAddress(ctx.ipAddress())
            .withMetadata(ctx.toMetadataJson()));
  }
}
