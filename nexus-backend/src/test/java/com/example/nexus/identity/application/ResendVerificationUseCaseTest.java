package com.example.nexus.identity.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.DomainException;
import com.example.nexus.common.domain.RateLimitException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.application.event.VerificationEmailEvent;
import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AuthTokenType;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationEventPublisher;

/**
 * Unit tests for {@link ResendVerificationUseCase}: verification email resend flow with rate limiting.
 *
 * <p>Test strategy:
 * <ul>
 *   <li>Unknown email: silent acknowledgment (anti-enumeration)
 *   <li>Verified user: silent acknowledgment (cannot re-verify)
 *   <li>Pending user: creates and sends verification email
 *   <li>Rate limiting: max resends per hour enforced; throttled event recorded
 *   <li>Audit events: verifies tenant ID and outcome on all paths
 * </ul>
 *
 * <p>Mocks: all ports and services; lenient strictness.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ResendVerificationUseCaseTest {

  private static final UUID TENANT_ID = UUID.randomUUID();
  private static final String RAW_EMAIL = "alice@example.com";
  private static final String EMAIL_HMAC = "hmac".repeat(16); // 64 chars

  @Mock private UserRegistrationPort userRegistrationPort;
  @Mock private AuthTokenPort authTokenPort;
  @Mock private EmailBlindIndexService emailBlindIndexService;
  @Mock private TokenGenerator tokenGenerator;
  @Mock private TokenHasher tokenHasher;
  @Mock private AuthEventPort authEventPort;
  @Mock private UuidGenerator uuidGenerator;
  @Mock private ApplicationEventPublisher eventPublisher;

  @InjectMocks
  private ResendVerificationUseCase useCase;

  private User pendingUser;

  @BeforeEach
  void setUp() {
    when(emailBlindIndexService.blindIndex(RAW_EMAIL)).thenReturn(EMAIL_HMAC);
    when(uuidGenerator.newId()).thenAnswer(inv -> UUID.randomUUID());
    when(tokenGenerator.generate()).thenReturn("r".repeat(64));
    when(tokenHasher.hash("r".repeat(64))).thenReturn("h".repeat(64));

    pendingUser = org.mockito.Mockito.mock(User.class);
    when(pendingUser.getId()).thenReturn(UUID.randomUUID());
    when(pendingUser.getStatus()).thenReturn(UserStatus.PENDING);

    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.of(pendingUser));
  }

  @Test
  void resend_success_savesTokenAndPublishesVerificationEvent() {
    when(authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(
        any(), eq(AuthTokenType.VERIFICATION), any(Instant.class))).thenReturn(0);

    useCase.resend(TENANT_ID, RAW_EMAIL, RequestContext.UNKNOWN);

    verify(authTokenPort).save(any());
    ArgumentCaptor<VerificationEmailEvent> captor =
        ArgumentCaptor.forClass(VerificationEmailEvent.class);
    verify(eventPublisher).publishEvent(captor.capture());
    assertThat(captor.getValue().toEmail()).isEqualTo(RAW_EMAIL);
    assertThat(captor.getValue().rawToken()).isEqualTo("r".repeat(64));
    verify(authEventPort).record(argThat(e -> "RESEND_REQUESTED".equals(e.getEventType())
        && "SUCCESS".equals(e.getOutcome())));
  }

  @Test
  void should_setTenantId_when_resendRequested() {
    when(authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(
        any(), eq(AuthTokenType.VERIFICATION), any(Instant.class))).thenReturn(0);

    useCase.resend(TENANT_ID, RAW_EMAIL, RequestContext.UNKNOWN);

    verify(authEventPort).record(argThat(e ->
        "RESEND_REQUESTED".equals(e.getEventType()) && TENANT_ID.equals(e.getTenantId())));
  }

  @Test
  void resend_secondCallWithin60s_throwsRateLimitException_withRetryAfter60() {
    when(authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(
        any(), eq(AuthTokenType.VERIFICATION), any(Instant.class))).thenReturn(1);

    assertThatThrownBy(() -> useCase.resend(TENANT_ID, RAW_EMAIL, RequestContext.UNKNOWN))
        .isInstanceOf(RateLimitException.class)
        .satisfies(e -> {
          assertThat(((DomainException) e).code()).isEqualTo("AUTH_RES_001");
          assertThat(((RateLimitException) e).retryAfterSeconds()).isEqualTo(60L);
        });
    verify(eventPublisher, never()).publishEvent(any());
    verify(authEventPort).record(argThat(e -> "RESEND_THROTTLED".equals(e.getEventType())
        && "BLOCKED".equals(e.getOutcome())));
  }

  @Test
  void should_setTenantId_when_resendThrottledWithin60s() {
    when(authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(
        any(), eq(AuthTokenType.VERIFICATION), any(Instant.class))).thenReturn(1);

    assertThatThrownBy(() -> useCase.resend(TENANT_ID, RAW_EMAIL, RequestContext.UNKNOWN))
        .isInstanceOf(RateLimitException.class);

    verify(authEventPort).record(argThat(e ->
        "RESEND_THROTTLED".equals(e.getEventType()) && TENANT_ID.equals(e.getTenantId())));
  }

  @Test
  void resend_sixthCallWithin24h_throwsRateLimitException_withRetryAfter3600() {
    // 60s window returns 0 (no recent token), 24h window returns 5 (throttle)
    when(authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(
        any(), eq(AuthTokenType.VERIFICATION), any(Instant.class)))
        .thenReturn(0)  // first call: 60s window → no throttle
        .thenReturn(5); // second call: 24h window → throttle

    assertThatThrownBy(() -> useCase.resend(TENANT_ID, RAW_EMAIL, RequestContext.UNKNOWN))
        .isInstanceOf(RateLimitException.class)
        .satisfies(e -> {
          assertThat(((DomainException) e).code()).isEqualTo("AUTH_RES_001");
          assertThat(((RateLimitException) e).retryAfterSeconds()).isEqualTo(3600L);
        });
    verify(eventPublisher, never()).publishEvent(any());
    verify(authEventPort).record(argThat(e -> "RESEND_THROTTLED".equals(e.getEventType())
        && "BLOCKED".equals(e.getOutcome())));
  }

  @Test
  void resend_unknownEmail_returnsWithoutAnyEvent() {
    when(userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, EMAIL_HMAC))
        .thenReturn(Optional.empty());

    assertThatCode(() -> useCase.resend(TENANT_ID, RAW_EMAIL, RequestContext.UNKNOWN))
        .doesNotThrowAnyException();
    verify(eventPublisher, never()).publishEvent(any());
  }

  @Test
  void resend_activeAccount_returnsWithoutAnyEvent() {
    when(pendingUser.getStatus()).thenReturn(UserStatus.ACTIVE);

    assertThatCode(() -> useCase.resend(TENANT_ID, RAW_EMAIL, RequestContext.UNKNOWN))
        .doesNotThrowAnyException();
    verify(eventPublisher, never()).publishEvent(any());
  }

  @Test
  void resend_lockedAccount_returnsWithoutAnyEvent() {
    when(pendingUser.getStatus()).thenReturn(UserStatus.LOCKED);

    assertThatCode(() -> useCase.resend(TENANT_ID, RAW_EMAIL, RequestContext.UNKNOWN))
        .doesNotThrowAnyException();
    verify(eventPublisher, never()).publishEvent(any());
  }
}
