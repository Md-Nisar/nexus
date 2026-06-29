package com.example.nexus.identity.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.AccountLockedException;
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
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.LoginResult;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.data.Offset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class LoginUseCaseTest {

  private EmailBlindIndexService emailBlindIndexService;
  private UserRegistrationPort userRegistrationPort;
  private PasswordVerifierPort passwordVerifier;
  private PasswordHasherPort passwordHasher;
  private RefreshTokenPort refreshTokenPort;
  private JwtPort jwtPort;
  private SecureEventService secureEventService;
  private TokenGenerator tokenGenerator;
  private TokenHasher tokenHasher;
  private UuidGenerator uuidGenerator;
  private Clock clock;

  private LoginUseCase useCase;

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final RequestContext CTX = new RequestContext("192.168.1.1", "trace-001");
  private static final String EMAIL = "user@example.com";
  private static final String PASSWORD = "P@ssw0rd!!";
  private static final String EMAIL_HMAC = "deadbeef".repeat(8); // 64-char hex
  private static final String DUMMY_HASH = "$argon2id$dummy";
  private static final String RAW_REFRESH = "a".repeat(64);
  private static final String TOKEN_HASH = "b".repeat(64);

  @BeforeEach
  void setUp() {
    emailBlindIndexService = mock(EmailBlindIndexService.class);
    userRegistrationPort = mock(UserRegistrationPort.class);
    passwordVerifier = mock(PasswordVerifierPort.class);
    passwordHasher = mock(PasswordHasherPort.class);
    refreshTokenPort = mock(RefreshTokenPort.class);
    jwtPort = mock(JwtPort.class);
    secureEventService = mock(SecureEventService.class);
    tokenGenerator = mock(TokenGenerator.class);
    tokenHasher = mock(TokenHasher.class);
    uuidGenerator = mock(UuidGenerator.class);
    clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);

    when(emailBlindIndexService.blindIndex(EMAIL)).thenReturn(EMAIL_HMAC);
    when(passwordHasher.hash(any())).thenReturn(DUMMY_HASH);
    when(uuidGenerator.newId()).thenReturn(UUID.randomUUID());
    when(tokenGenerator.generate()).thenReturn(RAW_REFRESH);
    when(tokenHasher.hash(RAW_REFRESH)).thenReturn(TOKEN_HASH);

    useCase = new LoginUseCase(
        emailBlindIndexService, userRegistrationPort, passwordVerifier, passwordHasher,
        refreshTokenPort, jwtPort, secureEventService, tokenGenerator,
        tokenHasher, uuidGenerator, clock);
    useCase.init(); // simulates @PostConstruct
  }

  @Test
  void execute_happyPath_returns_loginResult() {
    User user = activeUser();
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(PASSWORD, user.getPasswordHash())).thenReturn(true);
    when(jwtPort.issue(user)).thenReturn(new AccessTokenResult("jwt.tok", 900L, "jti-1"));

    LoginResult result = useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX);

    assertThat(result.accessToken()).isEqualTo("jwt.tok");
    assertThat(result.expiresInSeconds()).isEqualTo(900L);
    assertThat(result.userId()).isEqualTo(user.getId().toString());
    assertThat(result.rawRefreshToken()).isEqualTo(RAW_REFRESH);
    verify(refreshTokenPort).save(any());
    verify(secureEventService, times(1)).recordEvent(any());
  }

  @Test
  void execute_wrongPassword_throws_AUTH_001() {
    User user = activeUser();
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(PASSWORD, user.getPasswordHash())).thenReturn(false);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_001"));

    verify(refreshTokenPort, never()).save(any());
  }

  @Test
  void execute_unknownEmail_still_calls_argon2_then_throws_AUTH_001() {
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.empty());

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_001"));

    // Anti-enumeration (T-2.2): Argon2 MUST run even when user not found
    verify(passwordVerifier).matches(eq(PASSWORD), eq(DUMMY_HASH));
    verify(refreshTokenPort, never()).save(any());
  }

  @Test
  void execute_pendingUser_correctPassword_throws_AUTH_002() {
    User user = userWithStatus(UserStatus.PENDING);
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(PASSWORD, user.getPasswordHash())).thenReturn(true);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX))
        .isInstanceOf(AccountNotVerifiedException.class)
        .satisfies(e -> assertThat(((AccountNotVerifiedException) e).code()).isEqualTo("AUTH_002"));

    verify(refreshTokenPort, never()).save(any());
  }

  // Updated: LOCKED accounts now throw AccountLockedException (AUTH_LCK_001), not AUTH_001
  @Test
  void execute_lockedUser_correctPassword_throws_AccountLockedException() {
    User user = lockedUserWithExpiry(clock.instant().plusSeconds(500));
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(PASSWORD, user.getPasswordHash())).thenReturn(true);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX))
        .isInstanceOf(AccountLockedException.class)
        .satisfies(e -> assertThat(((AccountLockedException) e).code()).isEqualTo("AUTH_LCK_001"));

    verify(refreshTokenPort, never()).save(any());
  }

  @Test
  void execute_disabledUser_correctPassword_throws_AUTH_001() {
    User user = userWithStatus(UserStatus.DISABLED);
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(PASSWORD, user.getPasswordHash())).thenReturn(true);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_001"));

    verify(refreshTokenPort, never()).save(any());
  }

  // -----------------------------------------------------------------------
  // T-007: Lockout pre-check tests
  // -----------------------------------------------------------------------

  @Test
  void execute_lockedAccount_throwsAccountLockedExceptionWithRetryAfter() {
    Instant lockedUntil = clock.instant().plusSeconds(500);
    User user = lockedUserWithExpiry(lockedUntil);
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(PASSWORD, user.getPasswordHash())).thenReturn(true);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX))
        .isInstanceOf(AccountLockedException.class)
        .satisfies(e -> {
          AccountLockedException ale = (AccountLockedException) e;
          assertThat(ale.code()).isEqualTo("AUTH_LCK_001");
          assertThat(ale.retryAfterSeconds()).isCloseTo(500L, Offset.offset(2L));
        });

    verify(secureEventService, never()).persistFailedAttempt(any(), any());
  }

  @Test
  void execute_lockedAccount_recordsLoginFailureEvent() {
    Instant lockedUntil = clock.instant().plusSeconds(500);
    User user = lockedUserWithExpiry(lockedUntil);
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(PASSWORD, user.getPasswordHash())).thenReturn(true);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX))
        .isInstanceOf(AccountLockedException.class);

    ArgumentCaptor<AuthEvent> eventCaptor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(secureEventService).recordEvent(eventCaptor.capture());
    assertThat(eventCaptor.getValue().getEventType()).isEqualTo("LOGIN_FAILURE");
  }

  @Test
  void execute_wrongPassword_foundUser_callsPersistFailedAttempt() {
    User user = activeUser();
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(PASSWORD, user.getPasswordHash())).thenReturn(false);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_001"));

    verify(secureEventService).persistFailedAttempt(eq(user.getId()), any(Instant.class));
  }

  @Test
  void execute_wrongPassword_unknownUser_doesNotCallPersistFailedAttempt() {
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.empty());

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_001"));

    verify(secureEventService, never()).persistFailedAttempt(any(), any());
  }

  @Test
  void execute_expiredLock_correctPassword_unlocksAndResetsCounter() {
    // LOCKED user whose lock has expired — unlockIfExpired returns true and status is now ACTIVE
    User user = mock(User.class);
    when(user.getId()).thenReturn(UUID.randomUUID());
    when(user.getPasswordHash()).thenReturn("$argon2id$stored");
    when(user.getTenantId()).thenReturn(TENANT_ID);
    when(user.getTokenVersion()).thenReturn(0);
    // Starts LOCKED but unlockIfExpired flips it to ACTIVE
    when(user.getStatus()).thenReturn(UserStatus.ACTIVE);
    when(user.unlockIfExpired(any(Instant.class))).thenReturn(true);
    when(user.getFailedAttemptCount()).thenReturn(0);

    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(PASSWORD, "$argon2id$stored")).thenReturn(true);
    when(jwtPort.issue(user)).thenReturn(new AccessTokenResult("jwt.tok", 900L, "jti-1"));

    LoginResult result = useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX);

    assertThat(result).isNotNull();
    verify(secureEventService).persistResetAttempts(user.getId());

    ArgumentCaptor<AuthEvent> eventCaptor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(secureEventService, times(2)).recordEvent(eventCaptor.capture());
    assertThat(eventCaptor.getAllValues())
        .anyMatch(e -> e.getEventType().equals("ACCOUNT_UNLOCKED"))
        .anyMatch(e -> e.getEventType().equals("LOGIN_SUCCESS"));
  }

  @Test
  void execute_activeUser_cleanLogin_doesNotCallPersistResetAttempts() {
    User user = activeUser();
    when(user.getFailedAttemptCount()).thenReturn(0);
    when(user.unlockIfExpired(any(Instant.class))).thenReturn(false);
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(PASSWORD, user.getPasswordHash())).thenReturn(true);
    when(jwtPort.issue(user)).thenReturn(new AccessTokenResult("jwt.tok", 900L, "jti-1"));

    useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX);

    verify(secureEventService, never()).persistResetAttempts(any());
  }

  @Test
  void execute_activeUser_withNonZeroCount_callsPersistResetAttempts() {
    User user = activeUser();
    when(user.getFailedAttemptCount()).thenReturn(3);
    when(user.unlockIfExpired(any(Instant.class))).thenReturn(false);
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(PASSWORD, user.getPasswordHash())).thenReturn(true);
    when(jwtPort.issue(user)).thenReturn(new AccessTokenResult("jwt.tok", 900L, "jti-1"));

    useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX);

    verify(secureEventService).persistResetAttempts(user.getId());
  }

  // -----------------------------------------------------------------------
  // T-008 gap: LOCKED account + WRONG password must still return 423, not 401.
  // Step 4 (lock check) fires after Argon2 (Step 2) — the lock gate wins regardless
  // of whether the password matched.
  // -----------------------------------------------------------------------

  @Test
  void execute_lockedAccount_wrongPassword_throwsAccountLockedException() {
    Instant lockedUntil = clock.instant().plusSeconds(500);
    User user = lockedUserWithExpiry(lockedUntil);
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    // Wrong password — but the LOCKED check (Step 4) fires before Step 5 (credential gate)
    when(passwordVerifier.matches(PASSWORD, user.getPasswordHash())).thenReturn(false);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX))
        .isInstanceOf(AccountLockedException.class)
        .satisfies(e -> assertThat(((AccountLockedException) e).code()).isEqualTo("AUTH_LCK_001"));

    verify(jwtPort, never()).issue(any());
  }

  // -----------------------------------------------------------------------
  // ACCOUNT_UNLOCKED event must NOT be emitted on a clean login (justUnlocked == false)
  // -----------------------------------------------------------------------

  @Test
  void execute_cleanLogin_doesNotEmitAccountUnlockedEvent() {
    User user = activeUser();
    when(user.getFailedAttemptCount()).thenReturn(0);
    when(user.unlockIfExpired(any(Instant.class))).thenReturn(false);
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(PASSWORD, user.getPasswordHash())).thenReturn(true);
    when(jwtPort.issue(user)).thenReturn(new AccessTokenResult("jwt.tok", 900L, "jti-1"));

    useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX);

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(secureEventService, times(1)).recordEvent(captor.capture());
    assertThat(captor.getAllValues())
        .noneMatch(e -> "ACCOUNT_UNLOCKED".equals(e.getEventType()));
  }

  // -----------------------------------------------------------------------
  // ACCOUNT_UNLOCKED event must carry the userId (not null) when emitted
  // -----------------------------------------------------------------------

  @Test
  void execute_expiredLock_emitsAccountUnlockedEventWithUserId() {
    User user = mock(User.class);
    UUID userId = UUID.randomUUID();
    when(user.getId()).thenReturn(userId);
    when(user.getPasswordHash()).thenReturn("$argon2id$stored");
    when(user.getTenantId()).thenReturn(TENANT_ID);
    when(user.getTokenVersion()).thenReturn(0);
    when(user.getStatus()).thenReturn(UserStatus.ACTIVE);
    when(user.unlockIfExpired(any(Instant.class))).thenReturn(true);
    when(user.getFailedAttemptCount()).thenReturn(0);

    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(PASSWORD, "$argon2id$stored")).thenReturn(true);
    when(jwtPort.issue(user)).thenReturn(new AccessTokenResult("jwt.tok", 900L, "jti-1"));

    useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX);

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(secureEventService, times(2)).recordEvent(captor.capture());
    AuthEvent unlockedEvent = captor.getAllValues().stream()
        .filter(e -> "ACCOUNT_UNLOCKED".equals(e.getEventType()))
        .findFirst()
        .orElseThrow(() -> new AssertionError("ACCOUNT_UNLOCKED event not recorded"));
    assertThat(unlockedEvent.getUserId()).isEqualTo(userId);
    assertThat(unlockedEvent.getOutcome()).isEqualTo("SUCCESS");
  }

  // Argon2-always invariant (M-1 / T-015): Argon2 MUST run before the lock check
  @Test
  @DisplayName("Argon2 runs before lock check on locked-account path — closes T-LCK-5 timing oracle (M-1)")
  void execute_lockedAccount_argon2StillRunsBeforeLockCheck() {
    Instant lockedUntil = clock.instant().plusSeconds(500);
    User user = lockedUserWithExpiry(lockedUntil);
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    // password check result is irrelevant — lock check fires regardless
    when(passwordVerifier.matches(any(), any())).thenReturn(true);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX))
        .isInstanceOf(AccountLockedException.class);

    // Argon2 must have been invoked exactly once before the AccountLockedException was thrown
    verify(passwordVerifier, times(1)).matches(eq(PASSWORD), eq("$argon2id$stored"));
  }

  @Test
  @DisplayName("Argon2 runs exactly once on wrong-password path — same call count as locked path (M-1 / T-015)")
  void execute_wrongPassword_argon2Runs() {
    // Both the locked-account and wrong-password paths must invoke Argon2 exactly once.
    // Identical invocation counts prevent a timing side-channel that would distinguish
    // the two rejection reasons (T-LCK-5 timing oracle closure, M-1).
    User user = activeUser();
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(PASSWORD, user.getPasswordHash())).thenReturn(false);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_001"));

    verify(passwordVerifier, times(1)).matches(eq(PASSWORD), eq("$argon2id$stored"));
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  private User activeUser() {
    return userWithStatus(UserStatus.ACTIVE);
  }

  private User userWithStatus(UserStatus status) {
    User user = mock(User.class);
    when(user.getId()).thenReturn(UUID.randomUUID());
    when(user.getStatus()).thenReturn(status);
    when(user.getPasswordHash()).thenReturn("$argon2id$stored");
    when(user.getTenantId()).thenReturn(TENANT_ID);
    when(user.getTokenVersion()).thenReturn(0);
    return user;
  }

  private User lockedUserWithExpiry(Instant lockedUntil) {
    User user = mock(User.class);
    when(user.getId()).thenReturn(UUID.randomUUID());
    when(user.getStatus()).thenReturn(UserStatus.LOCKED);
    when(user.getPasswordHash()).thenReturn("$argon2id$stored");
    when(user.getTenantId()).thenReturn(TENANT_ID);
    when(user.getTokenVersion()).thenReturn(0);
    when(user.getLockedUntil()).thenReturn(lockedUntil);
    // Lock is still active — unlockIfExpired returns false
    when(user.unlockIfExpired(any(Instant.class))).thenReturn(false);
    return user;
  }
}
