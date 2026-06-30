package com.example.nexus.identity.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.FieldValidationException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.TokenExpiredException;
import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.PasswordVerifierPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.application.service.SecureEventService;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.AuthToken;
import com.example.nexus.identity.domain.AuthTokenType;
import com.example.nexus.identity.domain.EmailCipher;
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
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.OptimisticLockingFailureException;

@ExtendWith(MockitoExtension.class)
class ResetPasswordUseCaseTest {

  private static final String RAW_TOKEN = "a".repeat(64);
  private static final String TOKEN_HASH = "b".repeat(64);
  private static final String NEW_PASSWORD = "MyStr0ngNewP@ss!";
  private static final String NEW_HASH = "argon2id-new-hash";
  private static final String OLD_HASH = "argon2id-old-hash";
  private static final Instant NOW = Instant.parse("2026-06-30T10:00:00Z");
  private static final RequestContext CTX = new RequestContext("1.2.3.4", "trace-abc");

  @Mock private AuthTokenPort authTokenPort;
  @Mock private UserRegistrationPort userRegistrationPort;
  @Mock private PasswordPolicyService passwordPolicyService;
  @Mock private PasswordVerifierPort passwordVerifier;
  @Mock private PasswordHasherPort passwordHasher;
  @Mock private SecureEventService secureEventService;
  @Mock private TokenHasher tokenHasher;
  @Mock private UuidGenerator uuidGenerator;

  private ResetPasswordUseCase useCase;

  @BeforeEach
  void setUp() {
    Clock fixedClock = Clock.fixed(NOW, ZoneOffset.UTC);
    useCase = new ResetPasswordUseCase(
        authTokenPort, userRegistrationPort, passwordPolicyService, passwordVerifier,
        passwordHasher, secureEventService, tokenHasher, uuidGenerator, fixedClock);

    lenient().when(tokenHasher.hash(RAW_TOKEN)).thenReturn(TOKEN_HASH);
    lenient().when(uuidGenerator.newId()).thenAnswer(inv -> UUID.randomUUID());
    lenient().when(passwordHasher.hash(NEW_PASSWORD)).thenReturn(NEW_HASH);
  }

  private AuthToken validToken(UUID userId) {
    return AuthToken.forReset(UUID.randomUUID(), userId, TOKEN_HASH, NOW.plusSeconds(3600));
  }

  private User activeUser(UUID userId) {
    User u = new User(userId, UUID.randomUUID(), new EmailCipher("a@b.com"), "hmac", OLD_HASH, Instant.now());
    u.verify(Instant.now());
    return u;
  }

  @Test
  void execute_tokenNotFound_throws410() {
    when(tokenHasher.hash(RAW_TOKEN)).thenReturn(TOKEN_HASH);
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> useCase.execute(RAW_TOKEN, NEW_PASSWORD, CTX))
        .isInstanceOf(TokenExpiredException.class)
        .hasMessageContaining("expired or already been used");
  }

  @Test
  void execute_tokenWrongType_throws410() {
    UUID userId = UUID.randomUUID();
    AuthToken verifyToken = AuthToken.forVerification(
        UUID.randomUUID(), userId, TOKEN_HASH, NOW.plusSeconds(3600));
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(verifyToken));

    assertThatThrownBy(() -> useCase.execute(RAW_TOKEN, NEW_PASSWORD, CTX))
        .isInstanceOf(TokenExpiredException.class);
  }

  @Test
  void execute_tokenExpired_throws410() {
    UUID userId = UUID.randomUUID();
    AuthToken expired = AuthToken.forReset(UUID.randomUUID(), userId, TOKEN_HASH, NOW.minusSeconds(1));
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(expired));

    assertThatThrownBy(() -> useCase.execute(RAW_TOKEN, NEW_PASSWORD, CTX))
        .isInstanceOf(TokenExpiredException.class);
  }

  @Test
  void execute_tokenAlreadyConsumed_throws410() {
    UUID userId = UUID.randomUUID();
    AuthToken token = validToken(userId);
    token.consume(NOW.minusSeconds(60));
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));

    assertThatThrownBy(() -> useCase.execute(RAW_TOKEN, NEW_PASSWORD, CTX))
        .isInstanceOf(TokenExpiredException.class);
  }

  @Test
  void execute_optimisticLockOnFlush_throws410() {
    UUID userId = UUID.randomUUID();
    AuthToken token = validToken(userId);
    User user = activeUser(userId);
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(user));
    when(passwordVerifier.matches(NEW_PASSWORD, OLD_HASH)).thenReturn(false);
    when(authTokenPort.markConsumed(any(), any())).thenReturn(token);
    org.mockito.Mockito.doThrow(new OptimisticLockingFailureException("conflict"))
        .when(authTokenPort).flush();

    assertThatThrownBy(() -> useCase.execute(RAW_TOKEN, NEW_PASSWORD, CTX))
        .isInstanceOf(TokenExpiredException.class);
  }

  @Test
  void execute_passwordTooShort_throws400WithAuthPwd001() {
    UUID userId = UUID.randomUUID();
    AuthToken token = validToken(userId);
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
    // passwordPolicyService.validate() throws before findById is called; no user stub required
    org.mockito.Mockito.doThrow(new FieldValidationException("AUTH_PWD_001", "password", "too short"))
        .when(passwordPolicyService).validate(NEW_PASSWORD);

    assertThatThrownBy(() -> useCase.execute(RAW_TOKEN, NEW_PASSWORD, CTX))
        .isInstanceOf(FieldValidationException.class)
        .hasFieldOrPropertyWithValue("code", "AUTH_PWD_001");
  }

  @Test
  void execute_passwordInDenylist_throws400WithAuthPwd002() {
    UUID userId = UUID.randomUUID();
    AuthToken token = validToken(userId);
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
    // passwordPolicyService.validate() throws before findById is called; no user stub required
    org.mockito.Mockito.doThrow(new FieldValidationException("AUTH_PWD_002", "password", "too common"))
        .when(passwordPolicyService).validate(NEW_PASSWORD);

    assertThatThrownBy(() -> useCase.execute(RAW_TOKEN, NEW_PASSWORD, CTX))
        .isInstanceOf(FieldValidationException.class)
        .hasFieldOrPropertyWithValue("code", "AUTH_PWD_002");
  }

  @Test
  void execute_sameAsCurrentPassword_throws400WithAuthRst003() {
    UUID userId = UUID.randomUUID();
    AuthToken token = validToken(userId);
    User user = activeUser(userId);
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(user));
    when(passwordVerifier.matches(NEW_PASSWORD, OLD_HASH)).thenReturn(true);

    assertThatThrownBy(() -> useCase.execute(RAW_TOKEN, NEW_PASSWORD, CTX))
        .isInstanceOf(FieldValidationException.class)
        .hasFieldOrPropertyWithValue("code", "AUTH_RST_003");
  }

  @Test
  void execute_happyPath_consumesTokenSavesUserRevokesSessionsRecordsEvent() {
    UUID userId = UUID.randomUUID();
    AuthToken token = validToken(userId);
    User user = activeUser(userId);
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(user));
    when(passwordVerifier.matches(NEW_PASSWORD, OLD_HASH)).thenReturn(false);
    when(authTokenPort.markConsumed(any(), any())).thenReturn(token);
    when(userRegistrationPort.save(any())).thenAnswer(inv -> inv.getArgument(0));

    useCase.execute(RAW_TOKEN, NEW_PASSWORD, CTX);

    verify(authTokenPort).markConsumed(token, NOW);
    verify(authTokenPort).flush();
    verify(userRegistrationPort).save(user);
    verify(secureEventService).revokeAllUserSessions(userId, NOW);

    ArgumentCaptor<AuthEvent> eventCaptor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(secureEventService).recordEvent(eventCaptor.capture());
    assertThat(eventCaptor.getValue().getEventType()).isEqualTo("PASSWORD_CHANGED");
    assertThat(eventCaptor.getValue().getOutcome()).isEqualTo("SUCCESS");
  }

  @Test
  void execute_happyPath_passwordHashUpdatedAndStatusActive() {
    UUID userId = UUID.randomUUID();
    AuthToken token = validToken(userId);
    // Start as a LOCKED user to verify AC-4
    User user = new User(userId, UUID.randomUUID(), new EmailCipher("a@b.com"), "hmac", OLD_HASH, Instant.now());
    user.verify(Instant.now());
    user.lockAccount(NOW.plusSeconds(900));

    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(user));
    when(passwordVerifier.matches(NEW_PASSWORD, OLD_HASH)).thenReturn(false);
    when(authTokenPort.markConsumed(any(), any())).thenReturn(token);
    when(userRegistrationPort.save(any())).thenAnswer(inv -> inv.getArgument(0));

    useCase.execute(RAW_TOKEN, NEW_PASSWORD, CTX);

    assertThat(user.getPasswordHash()).isEqualTo(NEW_HASH);
    assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
    assertThat(user.getFailedAttemptCount()).isZero();
    assertThat(user.getLockedUntil()).isNull();
  }

  @Test
  void execute_failedToken_recordsPasswordResetFailedAuditEvent() {
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> useCase.execute(RAW_TOKEN, NEW_PASSWORD, CTX))
        .isInstanceOf(TokenExpiredException.class);

    ArgumentCaptor<AuthEvent> eventCaptor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(secureEventService).recordEvent(eventCaptor.capture());
    assertThat(eventCaptor.getValue().getEventType()).isEqualTo("PASSWORD_RESET_FAILED");
    assertThat(eventCaptor.getValue().getOutcome()).isEqualTo("FAILURE");
  }

  @Test
  void execute_sessionRevocationFailure_isSwallowedAndPasswordStillSaved() {
    UUID userId = UUID.randomUUID();
    AuthToken token = validToken(userId);
    User user = activeUser(userId);
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(user));
    when(passwordVerifier.matches(NEW_PASSWORD, OLD_HASH)).thenReturn(false);
    when(authTokenPort.markConsumed(any(), any())).thenReturn(token);
    when(userRegistrationPort.save(any())).thenAnswer(inv -> inv.getArgument(0));
    org.mockito.Mockito.doThrow(new RuntimeException("revocation-failure"))
        .when(secureEventService).revokeAllUserSessions(any(), any());

    // Should not throw; WARN is logged and PASSWORD_CHANGED audit event still records
    useCase.execute(RAW_TOKEN, NEW_PASSWORD, CTX);

    verify(userRegistrationPort).save(user);
    org.mockito.ArgumentCaptor<AuthEvent> captor =
        org.mockito.ArgumentCaptor.forClass(AuthEvent.class);
    verify(secureEventService).recordEvent(captor.capture());
    assertThat(captor.getValue().getEventType()).isEqualTo("PASSWORD_CHANGED");
  }

  @Test
  void execute_happyPath_doesNotPublishEmailEvent() {
    UUID userId = UUID.randomUUID();
    AuthToken token = validToken(userId);
    User user = activeUser(userId);
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(user));
    when(passwordVerifier.matches(NEW_PASSWORD, OLD_HASH)).thenReturn(false);
    when(authTokenPort.markConsumed(any(), any())).thenReturn(token);
    when(userRegistrationPort.save(any())).thenAnswer(inv -> inv.getArgument(0));

    // No ApplicationEventPublisher injected — verifies no event is published by this use-case
    // (email was sent at forgot-password time, not at reset time)
    useCase.execute(RAW_TOKEN, NEW_PASSWORD, CTX);

    verify(secureEventService).revokeAllUserSessions(userId, NOW);
  }
}
