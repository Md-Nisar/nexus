package com.example.nexus.identity.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.common.domain.DomainException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.TokenExpiredException;
import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.AuthToken;
import com.example.nexus.identity.domain.AuthTokenType;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.domain.User;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.OptimisticLockingFailureException;

@ExtendWith(MockitoExtension.class)
class VerifyEmailUseCaseTest {

  private static final String RAW_TOKEN = "a".repeat(64);
  private static final String TOKEN_HASH = "b".repeat(64);

  @Mock private AuthTokenPort authTokenPort;
  @Mock private UserRegistrationPort userRegistrationPort;
  @Mock private TokenHasher tokenHasher;
  @Mock private AuthEventPort authEventPort;
  @Mock private UuidGenerator uuidGenerator;

  @InjectMocks
  private VerifyEmailUseCase useCase;

  @BeforeEach
  void setUp() {
    when(tokenHasher.hash(RAW_TOKEN)).thenReturn(TOKEN_HASH);
    lenient().when(uuidGenerator.newId()).thenAnswer(inv -> UUID.randomUUID());
  }

  @Test
  void verify_happyPath_transitionsUserToActiveAndRecordsSuccessAudit() {
    UUID userId = UUID.randomUUID();
    AuthToken token = new AuthToken(UUID.randomUUID(), userId,
        AuthTokenType.VERIFICATION, TOKEN_HASH, Instant.now().plusSeconds(3600));
    User user = mock(User.class);

    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
    when(authTokenPort.markConsumed(eq(token), any(Instant.class))).thenReturn(token);
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(user));
    when(userRegistrationPort.save(user)).thenReturn(user);

    useCase.verify(RAW_TOKEN, RequestContext.UNKNOWN);

    verify(user).verify(any(Instant.class));
    verify(userRegistrationPort).save(user);
    verify(authEventPort).record(any());
  }

  @Test
  void should_setTenantIdFromLoadedUser_when_verifySucceeds() {
    UUID userId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    AuthToken token = new AuthToken(UUID.randomUUID(), userId,
        AuthTokenType.VERIFICATION, TOKEN_HASH, Instant.now().plusSeconds(3600));
    User user = mock(User.class);
    when(user.getTenantId()).thenReturn(tenantId);

    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
    when(authTokenPort.markConsumed(eq(token), any(Instant.class))).thenReturn(token);
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(user));
    when(userRegistrationPort.save(user)).thenReturn(user);

    useCase.verify(RAW_TOKEN, RequestContext.UNKNOWN);

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(authEventPort).record(captor.capture());
    assertThat(captor.getValue().getEventType()).isEqualTo("VERIFY");
    assertThat(captor.getValue().getTenantId()).isEqualTo(tenantId);
  }

  @Test
  void verify_tokenNotFound_throwsTokenExpiredWithCode_AUTH_VRF_002() {
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.empty());

    assertThrowsVrf002(() -> useCase.verify(RAW_TOKEN, RequestContext.UNKNOWN));
  }

  @Test
  void should_leaveTenantIdNull_when_verificationFailedBeforeUserLoaded_tokenNotFound() {
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.empty());

    assertThrowsVrf002(() -> useCase.verify(RAW_TOKEN, RequestContext.UNKNOWN));

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(authEventPort).record(captor.capture());
    assertThat(captor.getValue().getEventType()).isEqualTo("VERIFICATION_FAILED");
    assertThat(captor.getValue().getTenantId()).isNull();
  }

  @Test
  void verify_tokenExpired_throwsTokenExpiredWithCode_AUTH_VRF_002() {
    AuthToken expired = new AuthToken(UUID.randomUUID(), UUID.randomUUID(),
        AuthTokenType.VERIFICATION, TOKEN_HASH, Instant.now().minusSeconds(1));
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(expired));

    assertThrowsVrf002(() -> useCase.verify(RAW_TOKEN, RequestContext.UNKNOWN));
  }

  @Test
  void verify_tokenConsumed_throwsTokenExpiredWithCode_AUTH_VRF_002() {
    AuthToken consumed = new AuthToken(UUID.randomUUID(), UUID.randomUUID(),
        AuthTokenType.VERIFICATION, TOKEN_HASH, Instant.now().plusSeconds(3600));
    consumed.consume(Instant.now().minusSeconds(60));
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(consumed));

    assertThrowsVrf002(() -> useCase.verify(RAW_TOKEN, RequestContext.UNKNOWN));
  }

  @Test
  void verify_userNotFound_throwsTokenExpiredWithCode_AUTH_VRF_002() {
    UUID userId = UUID.randomUUID();
    AuthToken token = new AuthToken(UUID.randomUUID(), userId,
        AuthTokenType.VERIFICATION, TOKEN_HASH, Instant.now().plusSeconds(3600));
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
    when(authTokenPort.markConsumed(eq(token), any(Instant.class))).thenReturn(token);
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.empty());

    assertThrowsVrf002(() -> useCase.verify(RAW_TOKEN, RequestContext.UNKNOWN));
  }

  @Test
  void verify_optimisticLockConflict_throwsTokenExpiredWithCode_AUTH_VRF_002() {
    UUID userId = UUID.randomUUID();
    AuthToken token = new AuthToken(UUID.randomUUID(), userId,
        AuthTokenType.VERIFICATION, TOKEN_HASH, Instant.now().plusSeconds(3600));
    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
    when(authTokenPort.markConsumed(eq(token), any(Instant.class)))
        .thenThrow(new OptimisticLockingFailureException("concurrent modification"));

    assertThrowsVrf002(() -> useCase.verify(RAW_TOKEN, RequestContext.UNKNOWN));
  }

  @Test
  void verify_userAlreadyActive_throwsTokenExpiredWithCode_AUTH_VRF_002() {
    // Covers the path where user.verify() throws IllegalStateException because the user is
    // no longer PENDING (e.g., manually activated or a data-integrity anomaly). The use-case
    // catches IllegalStateException and re-wraps it so the API response is identical to all
    // other failure paths — callers cannot distinguish this case.
    UUID userId = UUID.randomUUID();
    AuthToken token = new AuthToken(UUID.randomUUID(), userId,
        AuthTokenType.VERIFICATION, TOKEN_HASH, Instant.now().plusSeconds(3600));
    User alreadyActiveUser = mock(User.class);

    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
    when(authTokenPort.markConsumed(eq(token), any(Instant.class))).thenReturn(token);
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(alreadyActiveUser));
    org.mockito.Mockito.doThrow(new IllegalStateException("Cannot verify user in status ACTIVE; expected PENDING"))
        .when(alreadyActiveUser).verify(any(Instant.class));

    assertThrowsVrf002(() -> useCase.verify(RAW_TOKEN, RequestContext.UNKNOWN));
  }

  @Test
  void should_setTenantIdFromLoadedUser_when_verificationFailedAfterUserLoaded() {
    // Same scenario as verify_userAlreadyActive above, but asserts the tenant is populated:
    // the User IS already loaded in scope when user.verify() throws IllegalStateException,
    // so unlike the pre-load failure branches, this one has a reliable tenant source.
    UUID userId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    AuthToken token = new AuthToken(UUID.randomUUID(), userId,
        AuthTokenType.VERIFICATION, TOKEN_HASH, Instant.now().plusSeconds(3600));
    User alreadyActiveUser = mock(User.class);
    when(alreadyActiveUser.getTenantId()).thenReturn(tenantId);

    when(authTokenPort.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
    when(authTokenPort.markConsumed(eq(token), any(Instant.class))).thenReturn(token);
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(alreadyActiveUser));
    org.mockito.Mockito.doThrow(new IllegalStateException("Cannot verify user in status ACTIVE; expected PENDING"))
        .when(alreadyActiveUser).verify(any(Instant.class));

    assertThrowsVrf002(() -> useCase.verify(RAW_TOKEN, RequestContext.UNKNOWN));

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(authEventPort).record(captor.capture());
    assertThat(captor.getValue().getEventType()).isEqualTo("VERIFICATION_FAILED");
    assertThat(captor.getValue().getTenantId()).isEqualTo(tenantId);
  }

  private static void assertThrowsVrf002(ThrowingCallable action) {
    assertThatThrownBy(action)
        .isInstanceOf(TokenExpiredException.class)
        .satisfies(e -> assertThat(((DomainException) e).code()).isEqualTo("AUTH_VRF_002"));
  }
}
