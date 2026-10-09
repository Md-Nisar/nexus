package com.example.nexus.identity.application.service;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.common.domain.RefreshThrottledException;
import com.example.nexus.identity.application.TokenGenerator;
import com.example.nexus.identity.application.TokenHasher;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.application.port.out.RateLimitResult;
import com.example.nexus.identity.application.port.out.RateLimitStore;
import com.example.nexus.identity.application.port.out.RefreshTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AccessTokenResult;
import com.example.nexus.identity.domain.AuthConstants;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.AuthEventType;
import com.example.nexus.identity.domain.LoginResult;
import com.example.nexus.identity.domain.RefreshToken;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.domain.UuidGenerator;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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
 *       Reuse comes first (US-018 RC-51): the revocation always runs before any rate-limit
 *       bucket is consulted, and {@code TOKEN_REFRESH_REUSE} is written whenever it revoked at
 *       least one unrevoked token. A replay that revoked nothing is an ordinary failure. The
 *       revoked count is used only for that decision and is never logged, returned or stored.
 *   <li>Two buckets live here because only here are the token's family and the outcome known
 *       (US-018 T-013): {@code REFRESH_FAMILY:{sha256(familyId)}} bounds each session, and
 *       {@code REFRESH_IP_FAIL:{ip}} bounds failure outcomes per source and is consumed before
 *       the {@code TOKEN_REFRESH_FAILURE} write, so unauthenticated audit volume stays bounded.
 *       The failure bucket never blocks a valid token. The SHA-256 only keeps the (non-secret)
 *       family id out of keys and logs; it is not a MAC.
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
  private static final String OUTCOME_FAILURE = "FAILURE";
  private static final String FAMILY_KEY_PREFIX = "REFRESH_FAMILY:";
  private static final String FAIL_KEY_PREFIX = "REFRESH_IP_FAIL:";
  private static final String COUNTER_FAILURE_THROTTLED = "nexus.auth.refresh_failure_throttled";

  private final RefreshTokenPort refreshTokenPort;
  private final UserRegistrationPort userRegistrationPort;
  private final JwtPort jwtPort;
  private final SecureEventService secureEventService;
  private final UuidGenerator uuidGenerator;
  private final TokenGenerator tokenGenerator;
  private final TokenHasher tokenHasher;
  private final Clock clock;
  private final RateLimitStore rateLimitStore;
  private final Counter failureThrottled;
  private final int familyMaxAttempts;
  private final int failureMaxAttempts;
  private final int windowSeconds;

  // WARN-once-per-window state for throttled failures; guarded by warnLock.
  private final Object warnLock = new Object();
  private Instant lastWarnAt;
  private long suppressedSinceLastWarn;

  /** Constructs the use-case with its required collaborators. */
  public RefreshTokenUseCase(
      RefreshTokenPort refreshTokenPort,
      UserRegistrationPort userRegistrationPort,
      JwtPort jwtPort,
      SecureEventService secureEventService,
      UuidGenerator uuidGenerator,
      TokenGenerator tokenGenerator,
      TokenHasher tokenHasher,
      Clock clock,
      RateLimitStore rateLimitStore,
      MeterRegistry meterRegistry,
      @Value("${nexus.security.rate-limit.refresh-family-max-attempts}") int familyMaxAttempts,
      @Value("${nexus.security.rate-limit.refresh-fail-max-attempts}") int failureMaxAttempts,
      @Value("${nexus.security.rate-limit.ip-window-seconds}") int windowSeconds) {
    this.refreshTokenPort = refreshTokenPort;
    this.userRegistrationPort = userRegistrationPort;
    this.jwtPort = jwtPort;
    this.secureEventService = secureEventService;
    this.uuidGenerator = uuidGenerator;
    this.tokenGenerator = tokenGenerator;
    this.tokenHasher = tokenHasher;
    this.clock = clock;
    this.rateLimitStore = rateLimitStore;
    this.failureThrottled = Counter.builder(COUNTER_FAILURE_THROTTLED).register(meterRegistry);
    this.familyMaxAttempts = familyMaxAttempts;
    this.failureMaxAttempts = failureMaxAttempts;
    this.windowSeconds = windowSeconds;
  }

  /**
   * Validates {@code tokenCookieValue}, rotates the refresh token, and returns new credentials.
   *
   * @param tokenCookieValue the raw refresh-token value from the {@code HttpOnly} cookie
   * @param clientIp         the client IP address ({@code request.getRemoteAddr()} only — T-1.3)
   * @return new login result with a fresh access JWT and rotated refresh token
   * @throws AuthenticationException if the token is invalid, revoked, expired, or the account
   *                                  is no longer active (AUTH_004 for all cases)
   * @throws RefreshThrottledException if the token's family bucket or the source IP's failure
   *                                   bucket is exhausted (429 with {@code Retry-After})
   */
  public LoginResult execute(String tokenCookieValue, String clientIp) {
    Instant now = clock.instant();

    // Step 1: Hash the incoming cookie value — IllegalArgumentException means the attacker-
    // controlled value is not valid hex; treat identically to unknown-token (uniform 401, T-2.3).
    String hash;
    try {
      hash = tokenHasher.hash(tokenCookieValue);
    } catch (IllegalArgumentException e) {
      throw failure(clientIp, () -> failureEvent((UUID) null, clientIp, AuthEventType.TOKEN_REFRESH_FAILURE));
    }

    // Step 2: Look up by hash — unknown token is a theft signal
    Optional<RefreshToken> tokenOpt = refreshTokenPort.findByTokenHash(hash);
    if (tokenOpt.isEmpty()) {
      throw failure(clientIp, () -> failureEvent((UUID) null, clientIp, AuthEventType.TOKEN_REFRESH_FAILURE));
    }
    RefreshToken token = tokenOpt.get();

    // Step 3: Theft detection — revoke entire family BEFORE throwing (T-4.2). Reuse comes first
    // (RC-51): no bucket is consulted before revokeFamily, so a throttled source cannot suppress
    // the theft response or its evidence. The committed count decides reuse vs ordinary failure.
    if (token.getRevokedAt() != null) {
      int revoked = secureEventService.revokeFamily(token.getFamilyId(), now);
      if (revoked >= 1) {
        secureEventService.recordEvent(
            new AuthEvent(uuidGenerator.newId(), AuthEventType.TOKEN_REFRESH_REUSE, OUTCOME_FAILURE)
                .withUserId(token.getUserId())
                .withIpAddress(clientIp));
        throw new AuthenticationException(AUTH_004, MSG_INVALID);
      }
      // Family already revoked: nothing new to protect, so this is an ordinary failure (L-2).
      throw failure(clientIp,
          () -> failureEvent(token.getUserId(), clientIp, AuthEventType.TOKEN_REFRESH_FAILURE));
    }

    // Step 3b: Per-family bucket — only a token found in the DB has a family (RC-32)
    consumeFamilyBucket(token.getFamilyId());

    // Step 4: Expiry check
    if (token.getExpiresAt().isBefore(now)) {
      throw failure(clientIp,
          () -> failureEvent(token.getUserId(), clientIp, AuthEventType.TOKEN_REFRESH_FAILURE));
    }

    // Step 5: Revoke old token (one-time use) under optimistic lock
    token.revoke(now);
    try {
      refreshTokenPort.save(token);
    } catch (OptimisticLockingFailureException e) {
      // Concurrent rotation — another request already consumed this token
      throw failure(clientIp,
          () -> failureEvent(token.getUserId(), clientIp, AuthEventType.TOKEN_REFRESH_FAILURE));
    }

    // Step 6: Re-fetch user
    User user = userRegistrationPort.findById(token.getUserId())
        .orElseThrow(() -> new AuthenticationException(AUTH_004, MSG_INVALID));

    // Step 7: Re-check status (may have changed since token was issued)
    if (user.getStatus() != UserStatus.ACTIVE) {
      // Unlike the pre-load failure branches above, `user` is already loaded here, so the
      // tenant is resolvable — use the User-aware overload (T-08-06 per-flow tenant table).
      throw failure(clientIp,
          () -> failureEvent(user, clientIp, AuthEventType.TOKEN_REFRESH_FAILURE));
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
        new AuthEvent(uuidGenerator.newId(), AuthEventType.TOKEN_REFRESH_SUCCESS, "SUCCESS")
            .withUserId(user.getId())
            .withTenantId(user.getTenantId())
            .withIpAddress(clientIp));

    log.debug("TOKEN_REFRESH_SUCCESS userId={}", user.getId());
    return new LoginResult(accessResult.token(), accessResult.expiresInSeconds(),
        user.getId().toString(), newRaw);
  }

  /**
   * Handles a failure outcome: consumes the per-IP failure bucket BEFORE the audit write (RC-43).
   * When the bucket rejects, no audit row is written and the request gets 429 (thrown here);
   * otherwise the {@code TOKEN_REFRESH_FAILURE} row is recorded and the uniform AUTH_004 is
   * returned for the caller to throw.
   */
  private AuthenticationException failure(String clientIp, Supplier<AuthEvent> event) {
    RateLimitResult result =
        rateLimitStore.tryConsume(FAIL_KEY_PREFIX + clientIp, windowSeconds, failureMaxAttempts);
    if (!result.allowed()) {
      recordThrottledFailure();
      throw new RefreshThrottledException(result.retryAfterSeconds());
    }
    secureEventService.recordEvent(event.get());
    return new AuthenticationException(AUTH_004, MSG_INVALID);
  }

  private void consumeFamilyBucket(UUID familyId) {
    RateLimitResult result = rateLimitStore.tryConsume(
        FAMILY_KEY_PREFIX + sha256Hex(familyId.toString()), windowSeconds, familyMaxAttempts);
    if (!result.allowed()) {
      throw new RefreshThrottledException(result.retryAfterSeconds());
    }
  }

  /**
   * Counts a throttled failure and emits at most one WARN per window. The WARN carries the number
   * of rejections since the previous WARN and never the source IP.
   */
  private void recordThrottledFailure() {
    failureThrottled.increment();
    Instant now = clock.instant();
    long suppressed;
    synchronized (warnLock) {
      suppressedSinceLastWarn++;
      if (lastWarnAt != null && now.isBefore(lastWarnAt.plusSeconds(windowSeconds))) {
        return;
      }
      lastWarnAt = now;
      suppressed = suppressedSinceLastWarn;
      suppressedSinceLastWarn = 0;
    }
    log.warn("AUTH_REFRESH_FAILURE_THROTTLED suppressedCount={}", suppressed);
  }

  private static String sha256Hex(String value) {
    try {
      return HexFormat.of().formatHex(
          MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is required by the JDK specification", e);
    }
  }

  private AuthEvent failureEvent(UUID userId, String clientIp, AuthEventType eventType) {
    return new AuthEvent(uuidGenerator.newId(), eventType, OUTCOME_FAILURE)
        .withUserId(userId)
        .withIpAddress(clientIp);
  }

  /**
   * Failure-event variant used only where a {@link User} is already loaded in scope (the Step-7
   * post-load status re-check) — carries the tenant from the loaded entity, unlike the UUID-only
   * overload used by the pre-load failure branches (invalid hash, unknown token, expired,
   * optimistic-lock conflict), which stay tenant-NULL.
   */
  private AuthEvent failureEvent(User user, String clientIp, AuthEventType eventType) {
    return new AuthEvent(uuidGenerator.newId(), eventType, OUTCOME_FAILURE)
        .withUserId(user.getId())
        .withTenantId(user.getTenantId())
        .withIpAddress(clientIp);
  }
}
