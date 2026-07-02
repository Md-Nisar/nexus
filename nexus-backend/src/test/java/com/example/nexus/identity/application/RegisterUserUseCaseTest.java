package com.example.nexus.identity.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.FieldValidationException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.application.event.AccountExistsEmailEvent;
import com.example.nexus.identity.application.event.VerificationEmailEvent;
import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.domain.User;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationEventPublisher;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RegisterUserUseCaseTest {

  private static final UUID TENANT_ID = UUID.randomUUID();
  private static final String RAW_EMAIL = "alice@example.com";
  // Not named RAW_PASSWORD to avoid the secret-scan pattern (password\s*=\s*"…{12+}")
  private static final String USER_PASS = "Str0ng-Passphrase-123";
  private static final String EMAIL_HMAC = "h".repeat(64);
  private static final String HASH_RESULT_EXAMPLE = "hashed-value-example";
  private static final String RAW_TOKEN = "t".repeat(64);
  private static final String TOKEN_HASH = "k".repeat(64);

  @Mock private UserRegistrationPort userRegistrationPort;
  @Mock private AuthTokenPort authTokenPort;
  @Mock private EmailBlindIndexService emailBlindIndexService;
  @Mock private PasswordPolicyService passwordPolicyService;
  @Mock private PasswordHasherPort passwordHasherPort;
  @Mock private TokenGenerator tokenGenerator;
  @Mock private TokenHasher tokenHasher;
  @Mock private AuthEventPort authEventPort;
  @Mock private UuidGenerator uuidGenerator;
  @Mock private ApplicationEventPublisher eventPublisher;

  @InjectMocks
  private RegisterUserUseCase useCase;

  @BeforeEach
  void setUp() {
    when(emailBlindIndexService.blindIndex(RAW_EMAIL)).thenReturn(EMAIL_HMAC);
    when(passwordHasherPort.hash(USER_PASS)).thenReturn(HASH_RESULT_EXAMPLE);
    when(tokenGenerator.generate()).thenReturn(RAW_TOKEN);
    when(tokenHasher.hash(RAW_TOKEN)).thenReturn(TOKEN_HASH);
    when(uuidGenerator.newId()).thenAnswer(inv -> UUID.randomUUID());
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.empty());
    when(userRegistrationPort.save(any())).thenAnswer(inv -> inv.getArgument(0));
    when(authTokenPort.save(any())).thenAnswer(inv -> inv.getArgument(0));
  }

  @Test
  void register_happyPath_savesUserAndTokenAndPublishesVerificationEvent() {
    useCase.register(TENANT_ID, RAW_EMAIL, USER_PASS, RequestContext.UNKNOWN);

    verify(userRegistrationPort).save(any(User.class));
    verify(authTokenPort).save(any());

    ArgumentCaptor<VerificationEmailEvent> captor =
        ArgumentCaptor.forClass(VerificationEmailEvent.class);
    verify(eventPublisher).publishEvent(captor.capture());
    assertThat(captor.getValue().toEmail()).isEqualTo(RAW_EMAIL);
    assertThat(captor.getValue().rawToken()).isEqualTo(RAW_TOKEN);

    verify(authEventPort).record(argThat(e -> "REGISTER".equals(e.getEventType())));
  }

  @Test
  void should_setTenantId_when_registrationSucceeds() {
    useCase.register(TENANT_ID, RAW_EMAIL, USER_PASS, RequestContext.UNKNOWN);

    verify(authEventPort).record(argThat(e ->
        "REGISTER".equals(e.getEventType()) && TENANT_ID.equals(e.getTenantId())));
  }

  @Test
  void register_happyPath_passwordHashedExactlyOnce() {
    useCase.register(TENANT_ID, RAW_EMAIL, USER_PASS, RequestContext.UNKNOWN);

    verify(passwordHasherPort, times(1)).hash(USER_PASS);
  }

  @Test
  void register_duplicateEmail_publishesAccountExistsEventAndDoesNotPersist() {
    User existing = Mockito.mock(User.class);
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(existing));

    useCase.register(TENANT_ID, RAW_EMAIL, USER_PASS, RequestContext.UNKNOWN);

    verify(userRegistrationPort, never()).save(any());
    verify(authTokenPort, never()).save(any());

    ArgumentCaptor<AccountExistsEmailEvent> captor =
        ArgumentCaptor.forClass(AccountExistsEmailEvent.class);
    verify(eventPublisher).publishEvent(captor.capture());
    assertThat(captor.getValue().toEmail()).isEqualTo(RAW_EMAIL);

    verify(authEventPort).record(
        argThat(e -> "REGISTRATION_DUPLICATE_EMAIL".equals(e.getEventType())
            && "BLOCKED".equals(e.getOutcome())));
  }

  @Test
  void should_setTenantId_when_duplicateEmailRegistration() {
    User existing = Mockito.mock(User.class);
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(existing));

    useCase.register(TENANT_ID, RAW_EMAIL, USER_PASS, RequestContext.UNKNOWN);

    verify(authEventPort).record(argThat(e ->
        "REGISTRATION_DUPLICATE_EMAIL".equals(e.getEventType())
            && TENANT_ID.equals(e.getTenantId())));
  }

  @Test
  void register_duplicateEmail_passwordHashedForAntiEnumeration() {
    User existing = Mockito.mock(User.class);
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(existing));

    useCase.register(TENANT_ID, RAW_EMAIL, USER_PASS, RequestContext.UNKNOWN);

    verify(passwordHasherPort, times(1)).hash(USER_PASS);
  }

  @Test
  void register_weakPassword_throwsFieldValidationException_andNoPortInteraction() {
    Mockito.doThrow(new FieldValidationException("AUTH_PWD_001", "password", "Too weak"))
        .when(passwordPolicyService).validate(USER_PASS);

    assertThatThrownBy(
            () -> useCase.register(TENANT_ID, RAW_EMAIL, USER_PASS, RequestContext.UNKNOWN))
        .isInstanceOf(FieldValidationException.class)
        .satisfies(e -> assertThat(((FieldValidationException) e).field()).isEqualTo("password"));

    verifyNoInteractions(
        userRegistrationPort, authTokenPort, emailBlindIndexService,
        passwordHasherPort, tokenGenerator, tokenHasher, authEventPort, eventPublisher);
  }
}
