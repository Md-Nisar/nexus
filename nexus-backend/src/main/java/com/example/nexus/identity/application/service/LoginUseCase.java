package com.example.nexus.identity.application.service;

import com.example.nexus.common.domain.AccountNotVerifiedException;
import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.TokenGenerator;
import com.example.nexus.identity.application.TokenHasher;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.PasswordVerifierPort;
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
import jakarta.annotation.PostConstruct;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Authenticates a user with email + password and issues a JWT access token plus a rotating refresh
 * token (US-003).
 *
 * <p><strong>Security invariants (must not be reordered):</strong>
 * <ol>
 *   <li>Argon2 ALWAYS runs regardless of whether the email exists (T-2.2 anti-enumeration).
 *   <li>Status gate is an ALLOW-LIST — only {@code ACTIVE} proceeds; all other statuses block
 *       (T-2.5).
 *   <li>Rate-limit enforcement is delegated entirely to {@link
 *       com.example.nexus.identity.infrastructure.web.LoginRateLimitFilter}, the single
 *       enforcement point at the Servlet layer (T-6.x). Duplicate use-case checks have been
 *       removed to prevent effective rate-limit halving.
 * </ol>
 */
@Service
@Transactional
public class LoginUseCase {

  private static final Logger log = LoggerFactory.getLogger(LoginUseCase.class);

  private static final String AUTH_001 = "AUTH_001";
  private static final String AUTH_002 = "AUTH_002";

  private final EmailBlindIndexService emailBlindIndexService;
  private final UserRegistrationPort userRegistrationPort;
  private final PasswordVerifierPort passwordVerifier;
  private final PasswordHasherPort passwordHasher;
  private final RefreshTokenPort refreshTokenPort;
  private final JwtPort jwtPort;
  private final SecureEventService secureEventService;
  private final TokenGenerator tokenGenerator;
  private final TokenHasher tokenHasher;
  private final UuidGenerator uuidGenerator;
  private final Clock clock;

  private String dummyHash;

  /** Constructs the use-case with its required collaborators. */
  public LoginUseCase(
      EmailBlindIndexService emailBlindIndexService,
      UserRegistrationPort userRegistrationPort,
      PasswordVerifierPort passwordVerifier,
      PasswordHasherPort passwordHasher,
      RefreshTokenPort refreshTokenPort,
      JwtPort jwtPort,
      SecureEventService secureEventService,
      TokenGenerator tokenGenerator,
      TokenHasher tokenHasher,
      UuidGenerator uuidGenerator,
      Clock clock) {
    this.emailBlindIndexService = emailBlindIndexService;
    this.userRegistrationPort = userRegistrationPort;
    this.passwordVerifier = passwordVerifier;
    this.passwordHasher = passwordHasher;
    this.refreshTokenPort = refreshTokenPort;
    this.jwtPort = jwtPort;
    this.secureEventService = secureEventService;
    this.tokenGenerator = tokenGenerator;
    this.tokenHasher = tokenHasher;
    this.uuidGenerator = uuidGenerator;
    this.clock = clock;
  }

  /**
   * Pre-computes the dummy Argon2 hash using the runtime profile's parameters.
   * Field is immutable after this method returns.
   */
  @PostConstruct
  void init() {
    this.dummyHash = passwordHasher.hash("__nexus_dummy_timing_constant__");
    log.info("LoginUseCase dummy-hash initialised (anti-enumeration timing constant ready)");
  }

  /**
   * Authenticates {@code email} + {@code rawPassword} under {@code tenantId} and returns tokens.
   * The {@code ctx} carries the client IP for rate-limiting and audit events.
   *
   * @param tenantId  the owning tenant (from controller config, never from request body)
   * @param email     the raw email address supplied by the user
   * @param rawPassword the plaintext password supplied by the user
   * @param ctx       per-request context (IP address, trace ID)
   * @return login result containing access token, refresh token, and expiry
   * @throws AuthenticationException       if credentials are invalid or account is locked/disabled
   * @throws AccountNotVerifiedException   if the account is pending email verification (AUTH_002)
   */
  public LoginResult execute(UUID tenantId, String email, String rawPassword, RequestContext ctx) {
    String clientIp = ctx.ipAddress();

    // Step 1: Look up user — assign found flag, DO NOT branch yet (anti-enumeration)
    String emailHmac = emailBlindIndexService.blindIndex(email);
    Optional<User> userOpt = userRegistrationPort.findByTenantAndEmailHmac(tenantId, emailHmac);
    boolean found = userOpt.isPresent();

    // Step 2: Argon2 verify — ALWAYS RUNS regardless of found (T-2.2)
    boolean passwordMatch = found
        ? passwordVerifier.matches(rawPassword, userOpt.get().getPasswordHash())
        : passwordVerifier.matches(rawPassword, dummyHash);

    // Step 3: Fail on unknown user OR wrong password — IDENTICAL code path for both
    if (!found || !passwordMatch) {
      secureEventService.recordEvent(
          new AuthEvent(uuidGenerator.newId(), "LOGIN_FAILURE", "FAILURE")
              .withIpAddress(clientIp)
              .withMetadata(ctx.toMetadataJson()));
      throw new AuthenticationException(AUTH_001, "Invalid email or password");
    }

    // Step 4: Status gate — ACTIVE allowlist (T-2.5 — allowlist, not denylist)
    User user = userOpt.get();
    if (user.getStatus() == UserStatus.PENDING) {
      secureEventService.recordEvent(
          new AuthEvent(uuidGenerator.newId(), "LOGIN_PENDING_ACCOUNT", "FAILURE")
              .withUserId(user.getId())
              .withIpAddress(clientIp)
              .withMetadata(ctx.toMetadataJson()));
      throw new AccountNotVerifiedException(AUTH_002, "Account not verified. Please check your email.");
    }
    if (user.getStatus() != UserStatus.ACTIVE) {
      // LOCKED, DISABLED, or any future status — NEVER fall through to token issuance
      secureEventService.recordEvent(
          new AuthEvent(uuidGenerator.newId(), "LOGIN_FAILURE", "FAILURE")
              .withUserId(user.getId())
              .withIpAddress(clientIp)
              .withMetadata(ctx.toMetadataJson()));
      throw new AuthenticationException(AUTH_001, "Invalid email or password");
    }

    // Step 5: Issue access JWT
    AccessTokenResult accessResult = jwtPort.issue(user);

    // Step 6: Generate refresh token
    String rawRefreshToken = tokenGenerator.generate();
    String tokenHash = tokenHasher.hash(rawRefreshToken);
    UUID familyId = uuidGenerator.newId();
    UUID tokenId = uuidGenerator.newId();
    Instant expiresAt = clock.instant().plus(AuthConstants.AUTH_REFRESH_TOKEN_TTL_DAYS, ChronoUnit.DAYS);

    // Step 7: Persist refresh token
    refreshTokenPort.save(new RefreshToken(tokenId, user.getId(), tokenHash, familyId, expiresAt));

    // Step 8: Record success and return — rawRefreshToken exits here ONLY, never logged
    secureEventService.recordEvent(
        new AuthEvent(uuidGenerator.newId(), "LOGIN_SUCCESS", "SUCCESS")
            .withUserId(user.getId())
            .withIpAddress(clientIp)
            .withMetadata(ctx.toMetadataJson()));

    log.debug("LOGIN_SUCCESS userId={} tenantId={}", user.getId(), tenantId);
    return new LoginResult(accessResult.token(), accessResult.expiresInSeconds(),
        user.getId().toString(), rawRefreshToken);
  }
}
