package com.example.nexus.identity.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
import com.example.nexus.identity.domain.LoginResult;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Security-focused unit tests for {@link LoginUseCase} (IMPL-13 / T-2.x, T-1.7).
 *
 * <p>Covers credential-failure paths, account-status gates, and anti-enumeration timing.
 * Rate-limit enforcement has moved to {@code LoginRateLimitFilter} (C4) — see
 * {@code LoginRateLimitFilterTest} for those scenarios.
 *
 * <p>No Spring context — pure JUnit 5 + Mockito.
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class LoginUseCaseSecurityTest {

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

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000002");
  private static final String EMAIL = "security-test@example.com";
  private static final String RAW_PASSWORD = "S3cur!tyT3st#";
  private static final String EMAIL_HMAC = "emailhmac";
  private static final String DUMMY_HASH = "$argon2id$dummy";
  private static final RequestContext CTX = new RequestContext("203.0.113.5", "trace-1", null);

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
    uuidGenerator = UUID::randomUUID;
    clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);

    lenient().when(emailBlindIndexService.blindIndex(anyString())).thenReturn(EMAIL_HMAC);
    // Must return non-null so init() sets dummyHash correctly
    when(passwordHasher.hash(anyString())).thenReturn(DUMMY_HASH);

    useCase = new LoginUseCase(
        emailBlindIndexService, userRegistrationPort, passwordVerifier, passwordHasher,
        refreshTokenPort, jwtPort, secureEventService, tokenGenerator,
        tokenHasher, uuidGenerator, clock);
    useCase.init(); // simulates @PostConstruct — must run after stubs are set
  }

  // -----------------------------------------------------------------------
  // T-2.2: Unknown email
  // -----------------------------------------------------------------------

  /**
   * T-2.2: An attempt with an email that exists in no tenant must throw AUTH_001.
   * The credential failure path must fire before any status check.
   */
  @Test
  void should_returnAuth001_when_emailUnknown() {
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.empty());
    when(passwordVerifier.matches(any(), any())).thenReturn(false);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, RAW_PASSWORD, CTX))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_001"));
  }

  /**
   * T-2.2: Even when the email is not found, the use-case must still invoke Argon2 with the
   * pre-computed dummy hash to prevent timing-based user-enumeration.
   */
  @Test
  void should_invokeArgon2WithDummyHash_when_emailUnknown() {
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.empty());
    when(passwordVerifier.matches(eq(RAW_PASSWORD), eq(DUMMY_HASH))).thenReturn(false);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, RAW_PASSWORD, CTX))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_001"));

    // Anti-enumeration (T-2.2): Argon2 MUST run with dummyHash when user is not found
    verify(passwordVerifier).matches(RAW_PASSWORD, DUMMY_HASH);
  }

  // -----------------------------------------------------------------------
  // T-2.2: Wrong password — user found
  // -----------------------------------------------------------------------

  /**
   * T-2.2: A wrong password for a known ACTIVE user must produce AUTH_001 (indistinguishable
   * from the unknown-email case to prevent account enumeration).
   */
  @Test
  void should_returnAuth001_when_passwordWrong() {
    User user = mockUser(UserStatus.ACTIVE, "$argon2id$stored");
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(RAW_PASSWORD, "$argon2id$stored")).thenReturn(false);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, RAW_PASSWORD, CTX))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_001"));
  }

  // -----------------------------------------------------------------------
  // T-2.3: PENDING account
  // -----------------------------------------------------------------------

  /**
   * T-2.3: When user is PENDING and password is wrong, AUTH_001 must be thrown (credential
   * failure fires before the status gate — the attacker must not learn the account is pending).
   */
  @Test
  void should_returnAuth001_when_pendingAndWrongPassword() {
    User user = mockUser(UserStatus.PENDING, "$argon2id$stored");
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(RAW_PASSWORD, "$argon2id$stored")).thenReturn(false);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, RAW_PASSWORD, CTX))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_001"));
  }

  /**
   * T-2.3: When user is PENDING and correct password is supplied, AUTH_002 must be thrown
   * to prompt the user to verify their email — distinct from AUTH_001 only when credentials match.
   */
  @Test
  void should_returnAuth002_when_pendingAndCorrectPassword() {
    User user = mockUser(UserStatus.PENDING, "$argon2id$stored");
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(RAW_PASSWORD, "$argon2id$stored")).thenReturn(true);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, RAW_PASSWORD, CTX))
        .isInstanceOf(AccountNotVerifiedException.class)
        .satisfies(e -> assertThat(((AccountNotVerifiedException) e).code()).isEqualTo("AUTH_002"));
  }

  // -----------------------------------------------------------------------
  // T-2.5: LOCKED and DISABLED accounts
  // -----------------------------------------------------------------------

  /**
   * T-2.5 / T-007: A LOCKED account with a correct password must be blocked with AUTH_LCK_001.
   * Token issuance must never occur for non-ACTIVE accounts.
   */
  @Test
  void should_returnAuthLck001_when_accountLocked() {
    // Lock is still active — unlockIfExpired returns false, lockedUntil is in the future
    Instant lockedUntil = clock.instant().plusSeconds(900);
    User user = mockUser(UserStatus.LOCKED, "$argon2id$stored");
    lenient().when(user.getLockedUntil()).thenReturn(lockedUntil);
    lenient().when(user.unlockIfExpired(any())).thenReturn(false);
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(RAW_PASSWORD, "$argon2id$stored")).thenReturn(true);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, RAW_PASSWORD, CTX))
        .isInstanceOf(AccountLockedException.class)
        .satisfies(e -> assertThat(((AccountLockedException) e).code()).isEqualTo("AUTH_LCK_001"));

    verify(jwtPort, never()).issue(any());
  }

  /**
   * T-2.5: A DISABLED account with a correct password must be blocked with AUTH_001.
   * The status gate is an allow-list (ACTIVE only) — all other statuses are denied.
   */
  @Test
  void should_returnAuth001_when_accountDisabled() {
    User user = mockUser(UserStatus.DISABLED, "$argon2id$stored");
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(RAW_PASSWORD, "$argon2id$stored")).thenReturn(true);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, RAW_PASSWORD, CTX))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_001"));

    verify(jwtPort, never()).issue(any());
  }

  // -----------------------------------------------------------------------
  // Happy path — ACTIVE with correct credentials
  // -----------------------------------------------------------------------

  /**
   * Happy path: an ACTIVE user with correct credentials should receive tokens, and the
   * secure-event and refresh-token ports must be invoked exactly as the protocol requires.
   */
  @Test
  void should_succeed_when_activeAndCorrectPassword() {
    User user = mockUser(UserStatus.ACTIVE, "$argon2id$stored");
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(RAW_PASSWORD, "$argon2id$stored")).thenReturn(true);
    when(jwtPort.issue(user)).thenReturn(new AccessTokenResult("jwt-token", 900L, "jti-1"));
    when(tokenGenerator.generate()).thenReturn("a".repeat(64));
    when(tokenHasher.hash(anyString())).thenReturn("refreshhash");

    LoginResult result = useCase.execute(TENANT_ID, EMAIL, RAW_PASSWORD, CTX);

    assertThat(result.accessToken()).isEqualTo("jwt-token");
    assertThat(result.rawRefreshToken()).isNotNull();
    verify(jwtPort).issue(user);
    verify(refreshTokenPort).save(any());
    verify(secureEventService, atLeastOnce()).recordEvent(any());
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  private User mockUser(UserStatus status, String passwordHash) {
    User user = mock(User.class);
    lenient().when(user.getId()).thenReturn(UUID.randomUUID());
    lenient().when(user.getTenantId()).thenReturn(TENANT_ID);
    lenient().when(user.getStatus()).thenReturn(status);
    lenient().when(user.getPasswordHash()).thenReturn(passwordHash);
    lenient().when(user.getTokenVersion()).thenReturn(0);
    return user;
  }
}
