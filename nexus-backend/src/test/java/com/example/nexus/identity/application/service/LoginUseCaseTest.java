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
import org.junit.jupiter.api.Test;

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

  @Test
  void execute_lockedUser_correctPassword_throws_AUTH_001() {
    User user = userWithStatus(UserStatus.LOCKED);
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(passwordVerifier.matches(PASSWORD, user.getPasswordHash())).thenReturn(true);

    assertThatThrownBy(() -> useCase.execute(TENANT_ID, EMAIL, PASSWORD, CTX))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_001"));

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
}
