package com.example.nexus.identity.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.common.domain.RateLimitException;
import com.example.nexus.identity.application.TokenGenerator;
import com.example.nexus.identity.application.TokenHasher;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.application.port.out.RateLimitResult;
import com.example.nexus.identity.application.port.out.RateLimitStore;
import com.example.nexus.identity.application.port.out.RefreshTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AccessTokenResult;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.LoginResult;
import com.example.nexus.identity.domain.RefreshToken;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.domain.UuidGenerator;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.slf4j.LoggerFactory;
import org.springframework.dao.OptimisticLockingFailureException;

@Tag("UnitTest")
class RefreshTokenUseCaseTest {

  private RefreshTokenPort refreshTokenPort;
  private UserRegistrationPort userRegistrationPort;
  private JwtPort jwtPort;
  private SecureEventService secureEventService;
  private UuidGenerator uuidGenerator;
  private TokenGenerator tokenGenerator;
  private TokenHasher tokenHasher;
  private RateLimitStore rateLimitStore;
  private SimpleMeterRegistry meterRegistry;
  private MutableClock clock;
  private ListAppender<ILoggingEvent> logAppender;

  private RefreshTokenUseCase useCase;

  private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");
  private static final Instant FUTURE = NOW.plus(14, ChronoUnit.DAYS);

  // Raw cookie value and its corresponding DB-stored hash
  private static final String COOKIE_VALUE = "aa".repeat(32);
  private static final String STORED_HASH  = "bb".repeat(32);

  // New raw token generated on rotation and its hash
  private static final String NEW_RAW  = "cc".repeat(32);
  private static final String NEW_HASH = "dd".repeat(32);

  private static final String CLIENT_IP = "10.0.0.1";
  private static final int WINDOW_SECONDS = 60;
  private static final int FAMILY_MAX = 30;
  private static final int FAIL_MAX = 30;
  private static final String FAIL_KEY = "REFRESH_IP_FAIL:" + CLIENT_IP;
  private static final String COUNTER = "nexus.auth.refresh_failure_throttled";
  private static final String FAMILY_COUNTER = "nexus.auth.refresh_family_throttled";

  @BeforeEach
  void setUp() {
    refreshTokenPort = mock(RefreshTokenPort.class);
    userRegistrationPort = mock(UserRegistrationPort.class);
    jwtPort = mock(JwtPort.class);
    secureEventService = mock(SecureEventService.class);
    uuidGenerator = mock(UuidGenerator.class);
    tokenGenerator = mock(TokenGenerator.class);
    tokenHasher = mock(TokenHasher.class);
    rateLimitStore = mock(RateLimitStore.class);
    meterRegistry = new SimpleMeterRegistry();
    clock = new MutableClock(NOW);
    when(rateLimitStore.tryConsume(any(), eq(WINDOW_SECONDS), eq(FAMILY_MAX)))
        .thenReturn(RateLimitResult.permit());
    when(rateLimitStore.tryConsume(any(), eq(WINDOW_SECONDS), eq(FAIL_MAX)))
        .thenReturn(RateLimitResult.permit());
    when(secureEventService.revokeFamily(any(), any())).thenReturn(1);
    logAppender = new ListAppender<>();
    logAppender.start();
    ((Logger) LoggerFactory.getLogger(RefreshTokenUseCase.class)).addAppender(logAppender);

    when(uuidGenerator.newId()).thenReturn(UUID.randomUUID());
    when(tokenGenerator.generate()).thenReturn(NEW_RAW);
    when(tokenHasher.hash(COOKIE_VALUE)).thenReturn(STORED_HASH);
    when(tokenHasher.hash(NEW_RAW)).thenReturn(NEW_HASH);

    useCase = new RefreshTokenUseCase(
        refreshTokenPort, userRegistrationPort, jwtPort, secureEventService,
        uuidGenerator, tokenGenerator, tokenHasher, clock,
        rateLimitStore, meterRegistry, FAMILY_MAX, FAIL_MAX, WINDOW_SECONDS);
  }

  @AfterEach
  void detachAppender() {
    ((Logger) LoggerFactory.getLogger(RefreshTokenUseCase.class)).detachAppender(logAppender);
  }

  @Test
  void execute_happyPath_rotates_token_and_returns_loginResult() {
    UUID userId = UUID.randomUUID();
    UUID familyId = UUID.randomUUID();
    RefreshToken token = validToken(userId, familyId);
    User user = activeUser(userId);

    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.of(token));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(user));
    when(jwtPort.issue(user)).thenReturn(new AccessTokenResult("new.jwt.token", 900L, "jti-1"));

    LoginResult result = useCase.execute(COOKIE_VALUE, CLIENT_IP);

    assertThat(result.accessToken()).isEqualTo("new.jwt.token");
    assertThat(result.expiresInSeconds()).isEqualTo(900L);
    assertThat(result.userId()).isEqualTo(userId.toString());
    assertThat(result.rawRefreshToken()).isEqualTo(NEW_RAW);

    // Old token revoked, new token saved
    verify(refreshTokenPort).save(argThat(t -> t.getRevokedAt() != null)); // old revoked
    verify(refreshTokenPort).save(argThat(t ->                              // new token
        t.getTokenHash().equals(NEW_HASH) && t.getFamilyId().equals(familyId)));
  }

  @Test
  void should_setTenantIdFromLoadedUser_when_refreshSucceeds() {
    UUID userId = UUID.randomUUID();
    UUID familyId = UUID.randomUUID();
    RefreshToken token = validToken(userId, familyId);
    User user = activeUser(userId);

    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.of(token));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(user));
    when(jwtPort.issue(user)).thenReturn(new AccessTokenResult("new.jwt.token", 900L, "jti-1"));

    useCase.execute(COOKIE_VALUE, CLIENT_IP);

    verify(secureEventService).recordEvent(argThat(event ->
        "TOKEN_REFRESH_SUCCESS".equals(event.getEventType())
        && user.getTenantId().equals(event.getTenantId())));
  }

  @Test
  void execute_unknownToken_records_failure_and_throws_AUTH_004() {
    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_004"));

    verify(secureEventService).recordEvent(any());
    verify(secureEventService, never()).revokeFamily(any(), any());
  }

  @Test
  void should_leaveTenantIdNull_when_refreshFailsUnknownToken() {
    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class);

    verify(secureEventService).recordEvent(argThat(event ->
        "TOKEN_REFRESH_FAILURE".equals(event.getEventType()) && event.getTenantId() == null));
  }

  @Test
  void execute_revokedToken_revokes_family_emits_event_and_throws_AUTH_004() {
    UUID userId = UUID.randomUUID();
    UUID familyId = UUID.randomUUID();
    RefreshToken revokedToken = validToken(userId, familyId);
    revokedToken.revoke(NOW.minusSeconds(60)); // mark as already revoked (theft scenario)

    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.of(revokedToken));

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_004"));

    // Theft detection: family MUST be revoked before throwing
    verify(secureEventService).revokeFamily(familyId, NOW);
    verify(secureEventService).recordEvent(argThat(event ->
        "TOKEN_REFRESH_REUSE".equals(event.getEventType())
        && userId.equals(event.getUserId())));
    verify(jwtPort, never()).issue(any());
  }

  @Test
  void should_leaveTenantIdNull_when_refreshReuseDetected() {
    // Reuse detection only knows token.getUserId() — no User entity is loaded on this branch,
    // so no tenant source exists (design §5: "only token.getUserId() known" stays NULL).
    UUID userId = UUID.randomUUID();
    UUID familyId = UUID.randomUUID();
    RefreshToken revokedToken = validToken(userId, familyId);
    revokedToken.revoke(NOW.minusSeconds(60));

    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.of(revokedToken));

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class);

    verify(secureEventService).recordEvent(argThat(event ->
        "TOKEN_REFRESH_REUSE".equals(event.getEventType()) && event.getTenantId() == null));
  }

  @Test
  void execute_expiredToken_records_failure_and_throws_AUTH_004() {
    UUID userId = UUID.randomUUID();
    RefreshToken expiredToken = new RefreshToken(
        UUID.randomUUID(), userId, STORED_HASH, UUID.randomUUID(),
        NOW.minusSeconds(1)); // expired 1s ago

    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.of(expiredToken));

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_004"));

    verify(refreshTokenPort, never()).save(any());
    verify(jwtPort, never()).issue(any());
  }

  @Test
  void execute_optimisticLockOnSave_records_failure_and_throws_AUTH_004() {
    UUID userId = UUID.randomUUID();
    RefreshToken token = validToken(userId, UUID.randomUUID());
    User user = activeUser(userId);

    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.of(token));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(user));
    doThrow(new OptimisticLockingFailureException("concurrent rotation"))
        .when(refreshTokenPort).save(argThat(t -> t.getRevokedAt() != null));

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_004"));

    verify(jwtPort, never()).issue(any());
  }

  @Test
  void execute_userNotFound_after_validToken_throws_AUTH_004() {
    UUID userId = UUID.randomUUID();
    RefreshToken token = validToken(userId, UUID.randomUUID());

    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.of(token));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_004"));

    verify(jwtPort, never()).issue(any());
  }

  @Test
  void execute_nonActiveUser_records_failure_and_throws_AUTH_004() {
    UUID userId = UUID.randomUUID();
    RefreshToken token = validToken(userId, UUID.randomUUID());
    User lockedUser = userWithStatus(userId, UserStatus.LOCKED);

    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.of(token));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(lockedUser));

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_004"));

    // C5: Step 7 MUST record an audit event — non-active accounts are a security signal
    verify(secureEventService).recordEvent(argThat(event ->
        "TOKEN_REFRESH_FAILURE".equals(event.getEventType())
        && userId.equals(event.getUserId())));
    verify(jwtPort, never()).issue(any());
  }

  @Test
  void should_setTenantIdFromLoadedUser_when_statusCheckFailsAfterUserLoaded() {
    // Step 7 status re-check happens AFTER the Step-6 User load, so unlike the pre-load
    // failure branches, this one has a reliable tenant source (design §5 refinement).
    UUID userId = UUID.randomUUID();
    RefreshToken token = validToken(userId, UUID.randomUUID());
    User lockedUser = userWithStatus(userId, UserStatus.LOCKED);

    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.of(token));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(lockedUser));

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class);

    verify(secureEventService).recordEvent(argThat(event ->
        "TOKEN_REFRESH_FAILURE".equals(event.getEventType())
        && lockedUser.getTenantId().equals(event.getTenantId())));
  }

  @Test
  void execute_malformedCookieValue_returns401_not500() {
    // Attacker sends a cookie that is not valid hex — HexFormat.parseHex throws IAE.
    // The use case must catch it and return AUTH_004 (not propagate as 500).
    String malformed = "not-valid-hex!!";
    when(tokenHasher.hash(malformed)).thenThrow(new IllegalArgumentException("bad hex"));

    assertThatThrownBy(() -> useCase.execute(malformed, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class)
        .hasFieldOrPropertyWithValue("code", "AUTH_004");

    verify(secureEventService).recordEvent(argThat(e -> "TOKEN_REFRESH_FAILURE".equals(e.getEventType())));
  }

  // --- US-018 T-013: refresh limits (RC-32, RC-43, RC-51, L-2, L-3) ---

  @Test
  void should_consumeFamilyBucketAfterLookup_when_tokenIsValid() {
    UUID userId = UUID.randomUUID();
    UUID familyId = UUID.randomUUID();
    User user = activeUser(userId);
    when(refreshTokenPort.findByTokenHash(STORED_HASH))
        .thenReturn(Optional.of(validToken(userId, familyId)));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(user));
    when(jwtPort.issue(user)).thenReturn(new AccessTokenResult("new.jwt.token", 900L, "jti-1"));

    useCase.execute(COOKIE_VALUE, CLIENT_IP);

    InOrder order = inOrder(refreshTokenPort, rateLimitStore);
    order.verify(refreshTokenPort).findByTokenHash(STORED_HASH);
    order.verify(rateLimitStore).tryConsume(familyKey(familyId), WINDOW_SECONDS, FAMILY_MAX);
    order.verify(refreshTokenPort, times(2)).save(any());
  }

  @Test
  void should_neverConsumeFamilyBucket_when_tokenIsUnknown() {
    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.empty());
    when(rateLimitStore.tryConsume(FAIL_KEY, WINDOW_SECONDS, FAIL_MAX))
        .thenReturn(RateLimitResult.permit());

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class);

    verify(rateLimitStore, never()).tryConsume(argThat(k -> k.startsWith("REFRESH_FAMILY:")),
        any(Integer.class), any(Integer.class));
  }

  @Test
  void should_neverConsumeFamilyBucket_when_cookieIsNotHex() {
    when(tokenHasher.hash("zz")).thenThrow(new IllegalArgumentException("bad hex"));
    when(rateLimitStore.tryConsume(FAIL_KEY, WINDOW_SECONDS, FAIL_MAX))
        .thenReturn(RateLimitResult.permit());

    assertThatThrownBy(() -> useCase.execute("zz", CLIENT_IP))
        .isInstanceOf(AuthenticationException.class);

    verify(rateLimitStore, never()).tryConsume(argThat(k -> k.startsWith("REFRESH_FAMILY:")),
        any(Integer.class), any(Integer.class));
  }

  @Test
  void should_throw429WithRetryAfterAndNotRotate_when_familyBucketExhausted() {
    UUID userId = UUID.randomUUID();
    UUID familyId = UUID.randomUUID();
    when(refreshTokenPort.findByTokenHash(STORED_HASH))
        .thenReturn(Optional.of(validToken(userId, familyId)));
    when(rateLimitStore.tryConsume(familyKey(familyId), WINDOW_SECONDS, FAMILY_MAX))
        .thenReturn(RateLimitResult.reject(17));

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(RateLimitException.class)
        .hasFieldOrPropertyWithValue("retryAfterSeconds", 17L);

    verify(refreshTokenPort, never()).save(any());
    verify(secureEventService, never()).recordEvent(any());
  }

  @Test
  void should_countFamilyThrottle_when_familyBucketRejects() {
    UUID familyId = UUID.randomUUID();
    when(refreshTokenPort.findByTokenHash(STORED_HASH))
        .thenReturn(Optional.of(validToken(UUID.randomUUID(), familyId)));
    when(rateLimitStore.tryConsume(familyKey(familyId), WINDOW_SECONDS, FAMILY_MAX))
        .thenReturn(RateLimitResult.reject(17));

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(RateLimitException.class);

    assertThat(meterRegistry.counter(FAMILY_COUNTER).count()).isEqualTo(1.0);
    assertThat(meterRegistry.counter(COUNTER).count()).isZero();
  }

  @Test
  void should_emitOneFamilyWarnPerWindowWithoutFamilyIdOrIp_when_familyBucketKeepsRejecting() {
    UUID familyId = UUID.randomUUID();
    when(refreshTokenPort.findByTokenHash(STORED_HASH))
        .thenReturn(Optional.of(validToken(UUID.randomUUID(), familyId)));
    when(rateLimitStore.tryConsume(familyKey(familyId), WINDOW_SECONDS, FAMILY_MAX))
        .thenReturn(RateLimitResult.reject(17));

    for (int i = 0; i < 4; i++) {
      assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
          .isInstanceOf(RateLimitException.class);
    }

    assertThat(warnMessages()).singleElement().satisfies(message -> assertThat(message)
        .contains("AUTH_REFRESH_FAMILY_THROTTLED").contains("rejectedCount=1")
        .doesNotContain(CLIENT_IP).doesNotContain(familyId.toString())
        .doesNotContain(familyKey(familyId).substring("REFRESH_FAMILY:".length())));

    clock.advance(Duration.ofSeconds(WINDOW_SECONDS));
    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(RateLimitException.class);

    assertThat(warnMessages()).hasSize(2);
    assertThat(warnMessages().get(1)).contains("rejectedCount=4");
    assertThat(meterRegistry.counter(FAMILY_COUNTER).count()).isEqualTo(5.0);
  }

  @Test
  void should_keepFailureAndFamilyWarnWindowsIndependent() {
    UUID familyId = UUID.randomUUID();
    when(rateLimitStore.tryConsume(familyKey(familyId), WINDOW_SECONDS, FAMILY_MAX))
        .thenReturn(RateLimitResult.reject(17));
    when(rateLimitStore.tryConsume(FAIL_KEY, WINDOW_SECONDS, FAIL_MAX))
        .thenReturn(RateLimitResult.reject(30));
    when(refreshTokenPort.findByTokenHash(STORED_HASH))
        .thenReturn(Optional.of(validToken(UUID.randomUUID(), familyId)));
    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(RateLimitException.class);
    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.empty());
    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(RateLimitException.class);

    assertThat(warnMessages()).hasSize(2);
  }

  @Test
  void should_notConsumeFailureBucket_when_refreshSucceeds() {
    UUID userId = UUID.randomUUID();
    User user = activeUser(userId);
    when(refreshTokenPort.findByTokenHash(STORED_HASH))
        .thenReturn(Optional.of(validToken(userId, UUID.randomUUID())));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(user));
    when(jwtPort.issue(user)).thenReturn(new AccessTokenResult("new.jwt.token", 900L, "jti-1"));

    useCase.execute(COOKIE_VALUE, CLIENT_IP);

    verify(rateLimitStore, never()).tryConsume(eq(FAIL_KEY), any(Integer.class), any(Integer.class));
  }

  @Test
  void should_consumeFailureBucketBeforeAuditWrite_when_tokenIsUnknown() {
    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.empty());
    when(rateLimitStore.tryConsume(FAIL_KEY, WINDOW_SECONDS, FAIL_MAX))
        .thenReturn(RateLimitResult.permit());

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class);

    InOrder order = inOrder(rateLimitStore, secureEventService);
    order.verify(rateLimitStore).tryConsume(FAIL_KEY, WINDOW_SECONDS, FAIL_MAX);
    order.verify(secureEventService).recordEvent(
        argThat(e -> "TOKEN_REFRESH_FAILURE".equals(e.getEventType())));
  }

  @Test
  void should_consumeFailureBucket_when_cookieIsNotHexExpiredOrUserInactive() {
    when(rateLimitStore.tryConsume(FAIL_KEY, WINDOW_SECONDS, FAIL_MAX))
        .thenReturn(RateLimitResult.permit());
    when(tokenHasher.hash("zz")).thenThrow(new IllegalArgumentException("bad hex"));
    RefreshToken expired = new RefreshToken(
        UUID.randomUUID(), UUID.randomUUID(), STORED_HASH, UUID.randomUUID(), NOW.minusSeconds(1));
    UUID userId = UUID.randomUUID();
    RefreshToken live = validToken(userId, UUID.randomUUID());
    User lockedUser = userWithStatus(userId, UserStatus.LOCKED);
    when(refreshTokenPort.findByTokenHash(STORED_HASH))
        .thenReturn(Optional.of(expired))
        .thenReturn(Optional.of(live));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(lockedUser));

    assertThatThrownBy(() -> useCase.execute("zz", CLIENT_IP))
        .isInstanceOf(AuthenticationException.class);
    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class);
    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class);

    verify(rateLimitStore, times(3)).tryConsume(FAIL_KEY, WINDOW_SECONDS, FAIL_MAX);
  }

  @Test
  void should_consumeFailureBucket_when_optimisticLockLosesRotationRace() {
    UUID userId = UUID.randomUUID();
    when(rateLimitStore.tryConsume(FAIL_KEY, WINDOW_SECONDS, FAIL_MAX))
        .thenReturn(RateLimitResult.permit());
    when(refreshTokenPort.findByTokenHash(STORED_HASH))
        .thenReturn(Optional.of(validToken(userId, UUID.randomUUID())));
    doThrow(new OptimisticLockingFailureException("concurrent rotation"))
        .when(refreshTokenPort).save(any());

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class);

    verify(rateLimitStore).tryConsume(FAIL_KEY, WINDOW_SECONDS, FAIL_MAX);
  }

  @Test
  void should_return200_when_validRefreshFollowsThirtyInvalidFromSameIp() {
    // Real counting store semantics: first 30 failures permitted, 31st rejected.
    int[] failures = {0};
    when(rateLimitStore.tryConsume(FAIL_KEY, WINDOW_SECONDS, FAIL_MAX)).thenAnswer(inv ->
        ++failures[0] <= FAIL_MAX ? RateLimitResult.permit() : RateLimitResult.reject(40));
    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.empty());
    for (int i = 0; i < FAIL_MAX; i++) {
      assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
          .isInstanceOf(AuthenticationException.class);
    }
    UUID userId = UUID.randomUUID();
    User user = activeUser(userId);
    String validCookie = "ee".repeat(32);
    String validHash = "ff".repeat(32);
    when(tokenHasher.hash(validCookie)).thenReturn(validHash);
    when(refreshTokenPort.findByTokenHash(validHash)).thenReturn(Optional.of(
        new RefreshToken(UUID.randomUUID(), userId, validHash, UUID.randomUUID(), FUTURE)));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(user));
    when(jwtPort.issue(user)).thenReturn(new AccessTokenResult("new.jwt.token", 900L, "jti-1"));

    LoginResult result = useCase.execute(validCookie, CLIENT_IP);

    assertThat(result.accessToken()).isEqualTo("new.jwt.token");
  }

  @Test
  void should_throw429WithRetryAfterAndWriteNoAuditRow_when_thirtyFirstInvalidRefresh() {
    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.empty());
    when(rateLimitStore.tryConsume(FAIL_KEY, WINDOW_SECONDS, FAIL_MAX))
        .thenReturn(RateLimitResult.reject(42));

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(RateLimitException.class)
        .hasFieldOrPropertyWithValue("retryAfterSeconds", 42L);

    verify(secureEventService, never()).recordEvent(any());
    assertThat(meterRegistry.counter(COUNTER).count()).isEqualTo(1.0);
  }

  @Test
  void should_emitOneWarnPerWindowWithRejectedCountAndNoIp_when_failureBucketKeepsRejecting() {
    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.empty());
    when(rateLimitStore.tryConsume(FAIL_KEY, WINDOW_SECONDS, FAIL_MAX))
        .thenReturn(RateLimitResult.reject(30));

    for (int i = 0; i < 5; i++) {
      assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
          .isInstanceOf(RateLimitException.class);
    }
    assertThat(warnMessages()).hasSize(1);
    assertThat(warnMessages().get(0))
        .contains("AUTH_REFRESH_FAILURE_THROTTLED").contains("rejectedCount=1")
        .doesNotContain(CLIENT_IP);

    clock.advance(Duration.ofSeconds(WINDOW_SECONDS));
    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(RateLimitException.class);

    assertThat(warnMessages()).hasSize(2);
    assertThat(warnMessages().get(1)).contains("rejectedCount=5");
    assertThat(meterRegistry.counter(COUNTER).count()).isEqualTo(6.0);
  }

  @Test
  void should_runRevokeFamilyBeforeFailureBucket_when_revokedTokenPresented() {
    UUID userId = UUID.randomUUID();
    UUID familyId = UUID.randomUUID();
    RefreshToken revoked = validToken(userId, familyId);
    revoked.revoke(NOW.minusSeconds(60));
    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.of(revoked));
    when(secureEventService.revokeFamily(familyId, NOW)).thenReturn(1);

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class)
        .hasFieldOrPropertyWithValue("code", "AUTH_004");

    verify(rateLimitStore, never()).tryConsume(eq(FAIL_KEY), any(Integer.class), any(Integer.class));
    verify(rateLimitStore, never()).tryConsume(argThat(k -> k.startsWith("REFRESH_FAMILY:")),
        any(Integer.class), any(Integer.class));
  }

  @Test
  void should_writeExactlyOneReuseRowAndReturn401_when_replayRevokesFamilyWithFailureBucketExhausted() {
    // RC-51: the exhausted failure bucket must not suppress theft response or evidence.
    UUID userId = UUID.randomUUID();
    UUID familyId = UUID.randomUUID();
    RefreshToken revoked = validToken(userId, familyId);
    revoked.revoke(NOW.minusSeconds(60));
    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.of(revoked));
    when(secureEventService.revokeFamily(familyId, NOW)).thenReturn(3);
    when(rateLimitStore.tryConsume(FAIL_KEY, WINDOW_SECONDS, FAIL_MAX))
        .thenReturn(RateLimitResult.reject(30));

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class)
        .hasFieldOrPropertyWithValue("code", "AUTH_004")
        .hasMessage("Refresh token invalid");

    verify(secureEventService, times(1)).recordEvent(
        argThat(e -> "TOKEN_REFRESH_REUSE".equals(e.getEventType())));
    verify(secureEventService, never()).recordEvent(
        argThat(e -> "TOKEN_REFRESH_FAILURE".equals(e.getEventType())));
  }

  @Test
  void should_throttleWithNoRow_when_secondReplayRevokesNothingAndFailureBucketExhausted() {
    UUID familyId = UUID.randomUUID();
    RefreshToken revoked = validToken(UUID.randomUUID(), familyId);
    revoked.revoke(NOW.minusSeconds(60));
    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.of(revoked));
    when(secureEventService.revokeFamily(familyId, NOW)).thenReturn(0);
    when(rateLimitStore.tryConsume(FAIL_KEY, WINDOW_SECONDS, FAIL_MAX))
        .thenReturn(RateLimitResult.reject(30));

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(RateLimitException.class);

    verify(secureEventService, never()).recordEvent(any());
  }

  @Test
  void should_writeOneFailureRowAndNoReuseRow_when_replayRevokesNothingAndBucketNotExhausted() {
    // L-2: a replay that revoked nothing is an ordinary failure, not reuse evidence.
    UUID familyId = UUID.randomUUID();
    RefreshToken revoked = validToken(UUID.randomUUID(), familyId);
    revoked.revoke(NOW.minusSeconds(60));
    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.of(revoked));
    when(secureEventService.revokeFamily(familyId, NOW)).thenReturn(0);
    when(rateLimitStore.tryConsume(FAIL_KEY, WINDOW_SECONDS, FAIL_MAX))
        .thenReturn(RateLimitResult.permit());

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class)
        .hasFieldOrPropertyWithValue("code", "AUTH_004");

    verify(secureEventService, times(1)).recordEvent(
        argThat(e -> "TOKEN_REFRESH_FAILURE".equals(e.getEventType())));
    verify(secureEventService, never()).recordEvent(
        argThat(e -> "TOKEN_REFRESH_REUSE".equals(e.getEventType())));
  }

  @Test
  void should_return401Auth004AndNeverRotate_when_successorOfRevokedFamilyPresented() {
    // After the replay revoked the family, the attacker's successor is itself a revoked token:
    // revokeFamily finds nothing, so it is an ordinary 401 (bucket permitting), never a 200.
    UUID familyId = UUID.randomUUID();
    RefreshToken successor = validToken(UUID.randomUUID(), familyId);
    successor.revoke(NOW.minusSeconds(1));
    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.of(successor));
    when(secureEventService.revokeFamily(familyId, NOW)).thenReturn(0);

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class)
        .hasFieldOrPropertyWithValue("code", "AUTH_004");

    verify(jwtPort, never()).issue(any());
  }

  @Test
  void should_keepRevokedCountOutOfLogsAndMetadata_when_reuseDetected() {
    UUID familyId = UUID.randomUUID();
    RefreshToken revoked = validToken(UUID.randomUUID(), familyId);
    revoked.revoke(NOW.minusSeconds(60));
    when(refreshTokenPort.findByTokenHash(STORED_HASH)).thenReturn(Optional.of(revoked));
    when(secureEventService.revokeFamily(familyId, NOW)).thenReturn(7);

    assertThatThrownBy(() -> useCase.execute(COOKIE_VALUE, CLIENT_IP))
        .isInstanceOf(AuthenticationException.class);

    verify(secureEventService).recordEvent(argThat(e -> e.getMetadata() == null
        || e.getMetadata().isEmpty()));
    assertThat(logAppender.list).noneMatch(e -> e.getFormattedMessage().contains("7"));
  }

  // --- helpers ---

  private java.util.List<String> warnMessages() {
    return logAppender.list.stream()
        .filter(e -> e.getLevel() == Level.WARN)
        .map(ILoggingEvent::getFormattedMessage)
        .toList();
  }

  private static String familyKey(UUID familyId) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(familyId.toString().getBytes(StandardCharsets.UTF_8));
      return "REFRESH_FAMILY:" + HexFormat.of().formatHex(digest);
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Advanceable {@link Clock}; {@code Clock.fixed} cannot move. */
  private static final class MutableClock extends Clock {
    private Instant now;

    MutableClock(Instant start) {
      this.now = start;
    }

    void advance(Duration d) {
      now = now.plus(d);
    }

    @Override public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override public Instant instant() {
      return now;
    }
  }

  private RefreshToken validToken(UUID userId, UUID familyId) {
    return new RefreshToken(UUID.randomUUID(), userId, STORED_HASH, familyId, FUTURE);
  }

  private User activeUser(UUID userId) {
    return userWithStatus(userId, UserStatus.ACTIVE);
  }

  private User userWithStatus(UUID userId, UserStatus status) {
    User user = mock(User.class);
    when(user.getId()).thenReturn(userId);
    when(user.getStatus()).thenReturn(status);
    when(user.getTokenVersion()).thenReturn(0);
    when(user.getTenantId()).thenReturn(UUID.randomUUID());
    return user;
  }
}
