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
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

/**
 * Unit tests for {@link ForgotPasswordUseCase}: password reset request flow.
 *
 * <p>Test strategy:
 * <ul>
 *   <li>Unknown email: returns normally without side effects (anti-enumeration)
 *   <li>First reset in window: creates token and sends email
 *   <li>Rate limiting: 4th reset within 1 hour suppresses email and records throttled event
 *   <li>Audit events: verifies tenant ID and outcome are recorded correctly
 * </ul>
 *
 * <p>Mocks: all ports and services; uses fixed Clock for deterministic token TTL.
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
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

  /**
   * Verifies anti-enumeration: when email does not exist, use case returns normally without
   * side effects (no token, no event, no audit). This prevents attackers from discovering
   * registered email addresses via timing or observing emails sent.
   *
   * <p>Given: unknown email address
   * When: execute() called
   * Then: no port interactions occur
   */
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

  /**
   * Verifies happy path: first password reset request within the hourly window creates a reset
   * token with correct TTL and publishes password reset email, with audit event recorded.
   *
   * <p>Given: registered verified user, no prior reset in past hour
   * When: execute() called
   * Then: reset token saved with correct hash and expiry; email event published; audit event recorded
   */
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

    ArgumentCaptor<AuthEvent> auditCaptor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(secureEventService).recordEvent(auditCaptor.capture());
    org.assertj.core.api.Assertions.assertThat(auditCaptor.getValue().getEventType())
        .isEqualTo("PASSWORD_RESET_REQUESTED");
  }

  /**
   * Verifies that PASSWORD_RESET_REQUESTED audit events carry the tenant ID for multi-tenancy support.
   *
   * <p>Given: successful password reset request
   * When: audit event is recorded
   * Then: event contains the correct tenant ID
   */
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

  /**
   * Verifies rate limiting boundary: the 3rd reset within one hour (under the max of 4)
   * still sends email and creates token.
   *
   * <p>Given: user with 3 reset requests in past hour (at max - 1)
   * When: another reset is requested
   * Then: token and email event are created normally
   */
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

  /**
   * Verifies rate limiting enforcement: 4th reset within one hour is throttled — no token or
   * email sent, but PASSWORD_RESET_THROTTLED audit event is recorded (protects against abuse).
   *
   * <p>Given: user with already 4 reset requests in past hour (at max)
   * When: another reset is requested
   * Then: no token or email event; throttled audit event recorded
   */
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

  /**
   * Verifies throttled audit event carries sufficient forensic detail: user ID, IP address,
   * and FAILURE outcome for security monitoring and abuse detection.
   *
   * <p>Given: throttled password reset request
   * When: audit event is recorded
   * Then: event contains user ID, IP address, and FAILURE outcome
   */
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

  /**
   * Verifies that PASSWORD_RESET_THROTTLED audit events carry the tenant ID even when rate
   * limited (multi-tenancy support for all event types).
   *
   * <p>Given: throttled password reset request
   * When: audit event is recorded
   * Then: event contains the correct tenant ID
   */
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

  /**
   * Verifies that successful password reset request generates a PASSWORD_RESET_REQUESTED audit
   * event with SUCCESS outcome for compliance and security monitoring.
   *
   * <p>Given: valid password reset request within rate limit
   * When: audit event is recorded
   * Then: event type is PASSWORD_RESET_REQUESTED with SUCCESS outcome
   */
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
