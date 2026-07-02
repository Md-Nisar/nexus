package com.example.nexus.identity.application;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.application.event.PasswordResetEmailEvent;
import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.application.service.SecureEventService;
import com.example.nexus.identity.domain.AuthConstants;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.AuthToken;
import com.example.nexus.identity.domain.AuthTokenType;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

@ExtendWith(MockitoExtension.class)
class ForgotPasswordUseCaseTest {

  private static final UUID TENANT_ID = UUID.randomUUID();
  private static final UUID USER_ID = UUID.randomUUID();
  private static final String RAW_EMAIL = "alice@example.com";
  private static final String EMAIL_HMAC = "hmac-of-alice";
  private static final String RAW_TOKEN = "a".repeat(64);
  private static final String TOKEN_HASH = "b".repeat(64);
  private static final Instant NOW = Instant.parse("2026-06-30T10:00:00Z");
  private static final RequestContext CTX = new RequestContext("1.2.3.4", "trace-123", null);

  @Mock private UserRegistrationPort userRegistrationPort;
  @Mock private AuthTokenPort authTokenPort;
  @Mock private EmailBlindIndexService emailBlindIndexService;
  @Mock private TokenGenerator tokenGenerator;
  @Mock private TokenHasher tokenHasher;
  @Mock private SecureEventService secureEventService;
  @Mock private UuidGenerator uuidGenerator;
  @Mock private ApplicationEventPublisher eventPublisher;

  private User user;

  @BeforeEach
  void setUp() {
    lenient().when(uuidGenerator.newId()).thenAnswer(inv -> UUID.randomUUID());
    lenient().when(emailBlindIndexService.blindIndex(RAW_EMAIL)).thenReturn(EMAIL_HMAC);
    lenient().when(tokenGenerator.generate()).thenReturn(RAW_TOKEN);
    lenient().when(tokenHasher.hash(RAW_TOKEN)).thenReturn(TOKEN_HASH);

    user = new User(USER_ID, TENANT_ID, new EmailCipher(RAW_EMAIL), EMAIL_HMAC, "hash", Instant.now());
    user.verify(Instant.now());
  }

  private ForgotPasswordUseCase buildWithClock(Instant fixedInstant) {
    Clock fixedClock = Clock.fixed(fixedInstant, ZoneOffset.UTC);
    return new ForgotPasswordUseCase(
        userRegistrationPort, authTokenPort, emailBlindIndexService,
        tokenGenerator, tokenHasher, secureEventService, uuidGenerator, eventPublisher, fixedClock);
  }

  @Test
  void execute_unknownEmail_doesNothingAndReturnsNormally() {
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.empty());
    ForgotPasswordUseCase uc = buildWithClock(NOW);

    uc.execute(TENANT_ID, RAW_EMAIL, CTX);

    verify(authTokenPort, never()).save(any());
    verify(eventPublisher, never()).publishEvent(any());
    verify(secureEventService, never()).recordEvent(any());
  }

  @Test
  void execute_firstReset_savesTokenAndPublishesEmailEvent() {
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    Instant sinceOneHour = NOW.minus(1, ChronoUnit.HOURS);
    when(authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(USER_ID, AuthTokenType.RESET, sinceOneHour))
        .thenReturn(0);
    when(authTokenPort.save(any())).thenAnswer(inv -> inv.getArgument(0));

    ForgotPasswordUseCase uc = buildWithClock(NOW);
    uc.execute(TENANT_ID, RAW_EMAIL, CTX);

    ArgumentCaptor<AuthToken> tokenCaptor = ArgumentCaptor.forClass(AuthToken.class);
    verify(authTokenPort).save(tokenCaptor.capture());
    AuthToken saved = tokenCaptor.getValue();
    org.assertj.core.api.Assertions.assertThat(saved.getType()).isEqualTo(AuthTokenType.RESET);
    org.assertj.core.api.Assertions.assertThat(saved.getTokenHash()).isEqualTo(TOKEN_HASH);
    org.assertj.core.api.Assertions.assertThat(saved.getUserId()).isEqualTo(USER_ID);
    org.assertj.core.api.Assertions.assertThat(saved.getExpiresAt())
        .isEqualTo(NOW.plus(AuthConstants.AUTH_RESET_TOKEN_TTL));

    ArgumentCaptor<PasswordResetEmailEvent> evtCaptor =
        ArgumentCaptor.forClass(PasswordResetEmailEvent.class);
    verify(eventPublisher).publishEvent(evtCaptor.capture());
    org.assertj.core.api.Assertions.assertThat(evtCaptor.getValue().toEmail()).isEqualTo(RAW_EMAIL);
    org.assertj.core.api.Assertions.assertThat(evtCaptor.getValue().rawToken()).isEqualTo(RAW_TOKEN);

    // Audit event must have been recorded (in REQUIRES_NEW) before publishEvent was called
    ArgumentCaptor<AuthEvent> auditCaptor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(secureEventService).recordEvent(auditCaptor.capture());
    org.assertj.core.api.Assertions.assertThat(auditCaptor.getValue().getEventType())
        .isEqualTo("PASSWORD_RESET_REQUESTED");
  }

  @Test
  void should_setTenantId_when_resetRequested() {
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    Instant sinceOneHour = NOW.minus(1, ChronoUnit.HOURS);
    when(authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(USER_ID, AuthTokenType.RESET, sinceOneHour))
        .thenReturn(0);
    when(authTokenPort.save(any())).thenAnswer(inv -> inv.getArgument(0));

    ForgotPasswordUseCase uc = buildWithClock(NOW);
    uc.execute(TENANT_ID, RAW_EMAIL, CTX);

    ArgumentCaptor<AuthEvent> auditCaptor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(secureEventService).recordEvent(auditCaptor.capture());
    org.assertj.core.api.Assertions.assertThat(auditCaptor.getValue().getTenantId())
        .isEqualTo(TENANT_ID);
  }

  @Test
  void execute_thirdReset_stillSendsEmail() {
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    Instant sinceOneHour = NOW.minus(1, ChronoUnit.HOURS);
    when(authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(USER_ID, AuthTokenType.RESET, sinceOneHour))
        .thenReturn(ForgotPasswordUseCase.MAX_RESETS_PER_HOUR - 1);
    when(authTokenPort.save(any())).thenAnswer(inv -> inv.getArgument(0));

    ForgotPasswordUseCase uc = buildWithClock(NOW);
    uc.execute(TENANT_ID, RAW_EMAIL, CTX);

    verify(authTokenPort).save(any());
    verify(eventPublisher).publishEvent(any(PasswordResetEmailEvent.class));
  }

  @Test
  void execute_fourthReset_suppressesEmailAndRecordsThrottledEvent() {
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    Instant sinceOneHour = NOW.minus(1, ChronoUnit.HOURS);
    when(authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(USER_ID, AuthTokenType.RESET, sinceOneHour))
        .thenReturn(ForgotPasswordUseCase.MAX_RESETS_PER_HOUR);

    ForgotPasswordUseCase uc = buildWithClock(NOW);
    uc.execute(TENANT_ID, RAW_EMAIL, CTX);

    verify(authTokenPort, never()).save(any());
    verify(eventPublisher, never()).publishEvent(any());

    ArgumentCaptor<AuthEvent> eventCaptor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(secureEventService).recordEvent(eventCaptor.capture());
    org.assertj.core.api.Assertions.assertThat(eventCaptor.getValue().getEventType())
        .isEqualTo("PASSWORD_RESET_THROTTLED");
  }

  @Test
  void execute_throttledRequest_auditEventContainsUserIdAndIpAddress() {
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    Instant sinceOneHour = NOW.minus(1, ChronoUnit.HOURS);
    when(authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(USER_ID, AuthTokenType.RESET, sinceOneHour))
        .thenReturn(ForgotPasswordUseCase.MAX_RESETS_PER_HOUR);

    ForgotPasswordUseCase uc = buildWithClock(NOW);
    uc.execute(TENANT_ID, RAW_EMAIL, CTX);

    ArgumentCaptor<AuthEvent> eventCaptor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(secureEventService).recordEvent(eventCaptor.capture());
    AuthEvent evt = eventCaptor.getValue();
    org.assertj.core.api.Assertions.assertThat(evt.getEventType())
        .isEqualTo("PASSWORD_RESET_THROTTLED");
    org.assertj.core.api.Assertions.assertThat(evt.getOutcome()).isEqualTo("FAILURE");
    org.assertj.core.api.Assertions.assertThat(evt.getUserId()).isEqualTo(USER_ID);
    org.assertj.core.api.Assertions.assertThat(evt.getIpAddress())
        .isEqualTo(CTX.ipAddress());
  }

  @Test
  void should_setTenantId_when_resetThrottled() {
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    Instant sinceOneHour = NOW.minus(1, ChronoUnit.HOURS);
    when(authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(USER_ID, AuthTokenType.RESET, sinceOneHour))
        .thenReturn(ForgotPasswordUseCase.MAX_RESETS_PER_HOUR);

    ForgotPasswordUseCase uc = buildWithClock(NOW);
    uc.execute(TENANT_ID, RAW_EMAIL, CTX);

    ArgumentCaptor<AuthEvent> eventCaptor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(secureEventService).recordEvent(eventCaptor.capture());
    org.assertj.core.api.Assertions.assertThat(eventCaptor.getValue().getEventType())
        .isEqualTo("PASSWORD_RESET_THROTTLED");
    org.assertj.core.api.Assertions.assertThat(eventCaptor.getValue().getTenantId())
        .isEqualTo(TENANT_ID);
  }

  @Test
  void execute_happyPath_recordsPasswordResetRequestedAuditEvent() {
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(user));
    when(authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(eq(USER_ID), eq(AuthTokenType.RESET), any()))
        .thenReturn(0);
    when(authTokenPort.save(any())).thenAnswer(inv -> inv.getArgument(0));

    ForgotPasswordUseCase uc = buildWithClock(NOW);
    uc.execute(TENANT_ID, RAW_EMAIL, CTX);

    ArgumentCaptor<AuthEvent> eventCaptor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(secureEventService).recordEvent(eventCaptor.capture());
    org.assertj.core.api.Assertions.assertThat(eventCaptor.getValue().getEventType())
        .isEqualTo("PASSWORD_RESET_REQUESTED");
    org.assertj.core.api.Assertions.assertThat(eventCaptor.getValue().getOutcome())
        .isEqualTo("SUCCESS");
  }
}
