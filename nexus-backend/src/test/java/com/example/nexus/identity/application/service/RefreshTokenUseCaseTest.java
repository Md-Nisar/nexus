package com.example.nexus.identity.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.identity.application.TokenGenerator;
import com.example.nexus.identity.application.TokenHasher;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.application.port.out.RefreshTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AccessTokenResult;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.LoginResult;
import com.example.nexus.identity.domain.RefreshToken;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
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
  private Clock clock;

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

  @BeforeEach
  void setUp() {
    refreshTokenPort = mock(RefreshTokenPort.class);
    userRegistrationPort = mock(UserRegistrationPort.class);
    jwtPort = mock(JwtPort.class);
    secureEventService = mock(SecureEventService.class);
    uuidGenerator = mock(UuidGenerator.class);
    tokenGenerator = mock(TokenGenerator.class);
    tokenHasher = mock(TokenHasher.class);
    clock = Clock.fixed(NOW, ZoneOffset.UTC);

    when(uuidGenerator.newId()).thenReturn(UUID.randomUUID());
    when(tokenGenerator.generate()).thenReturn(NEW_RAW);
    when(tokenHasher.hash(COOKIE_VALUE)).thenReturn(STORED_HASH);
    when(tokenHasher.hash(NEW_RAW)).thenReturn(NEW_HASH);

    useCase = new RefreshTokenUseCase(
        refreshTokenPort, userRegistrationPort, jwtPort, secureEventService,
        uuidGenerator, tokenGenerator, tokenHasher, clock);
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

  // --- helpers ---

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
