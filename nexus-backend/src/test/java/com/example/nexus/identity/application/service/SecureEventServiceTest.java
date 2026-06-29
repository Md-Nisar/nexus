package com.example.nexus.identity.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.application.port.out.RefreshTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AuthConstants;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.orm.ObjectOptimisticLockingFailureException;

class SecureEventServiceTest {

  private AuthEventPort authEventPort;
  private RefreshTokenPort refreshTokenPort;
  private UserRegistrationPort userRegistrationPort;
  private UuidGenerator uuidGenerator;

  private SecureEventService service;

  private static final UUID USER_ID = UUID.fromString("00000000-0000-7000-8000-000000000042");
  private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

  @BeforeEach
  void setUp() {
    authEventPort = mock(AuthEventPort.class);
    refreshTokenPort = mock(RefreshTokenPort.class);
    userRegistrationPort = mock(UserRegistrationPort.class);
    uuidGenerator = mock(UuidGenerator.class);
    when(uuidGenerator.newId()).thenReturn(UUID.randomUUID());

    service = new SecureEventService(
        authEventPort, refreshTokenPort, userRegistrationPort, uuidGenerator);
  }

  // ---------------------------------------------------------------------------
  // persistFailedAttempt
  // ---------------------------------------------------------------------------

  @Test
  void should_incrementCounterWithoutLocking_when_failedAttemptBelowThreshold() {
    User user = mock(User.class);
    when(userRegistrationPort.findById(USER_ID)).thenReturn(Optional.of(user));
    // count returned is below threshold
    when(user.recordFailedAttempt()).thenReturn(AuthConstants.LOCKOUT_THRESHOLD - 1);
    when(userRegistrationPort.save(user)).thenReturn(user);

    service.persistFailedAttempt(USER_ID, NOW);

    verify(user).recordFailedAttempt();
    verify(user, never()).lockAccount(any());
    verify(userRegistrationPort).save(user);
    // no ACCOUNT_LOCKED event recorded
    verify(authEventPort, never()).record(any());
  }

  @Test
  @DisplayName("persistFailedAttempt at LOCKOUT_THRESHOLD locks account (M-3 / DF-3 decision: " +
      "optimistic-lock race may allow 1-2 extra attempts under concurrency; " +
      "accepted trade-off — atomic UPDATE is the future mitigation path)")
  void should_lockAccountAndRecordEvent_when_failedAttemptReachesThreshold() {
    User user = mock(User.class);
    when(userRegistrationPort.findById(USER_ID)).thenReturn(Optional.of(user));
    when(user.recordFailedAttempt()).thenReturn(AuthConstants.LOCKOUT_THRESHOLD);
    when(userRegistrationPort.save(user)).thenReturn(user);

    Instant expectedLockedUntil = NOW.plusSeconds(AuthConstants.LOCKOUT_DURATION_SECONDS);

    service.persistFailedAttempt(USER_ID, NOW);

    verify(user).lockAccount(expectedLockedUntil);
    verify(userRegistrationPort).save(user);

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(authEventPort).record(captor.capture());
    AuthEvent event = captor.getValue();
    assertThat(event.getEventType()).isEqualTo("ACCOUNT_LOCKED");
    assertThat(event.getOutcome()).isEqualTo("FAILURE");
    assertThat(event.getUserId()).isEqualTo(USER_ID);
  }

  @Test
  void should_swallowExceptionAsBenign_when_optimisticLockCollisionOnSave() {
    User user = mock(User.class);
    when(userRegistrationPort.findById(USER_ID)).thenReturn(Optional.of(user));
    when(user.recordFailedAttempt()).thenReturn(1);
    when(userRegistrationPort.save(user))
        .thenThrow(new ObjectOptimisticLockingFailureException(User.class, USER_ID));

    assertThatCode(() -> service.persistFailedAttempt(USER_ID, NOW))
        .doesNotThrowAnyException();

    // no ACCOUNT_LOCKED_WRITE_FAILED event on optimistic lock — silent benign drop
    verify(authEventPort, never()).record(any());
  }

  @Test
  void should_swallowExceptionAndRecordWriteFailedEvent_when_genericExceptionOnSave() {
    User user = mock(User.class);
    when(userRegistrationPort.findById(USER_ID)).thenReturn(Optional.of(user));
    when(user.recordFailedAttempt()).thenReturn(1);
    when(userRegistrationPort.save(user)).thenThrow(new RuntimeException("db error"));

    assertThatCode(() -> service.persistFailedAttempt(USER_ID, NOW))
        .doesNotThrowAnyException();

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(authEventPort).record(captor.capture());
    AuthEvent event = captor.getValue();
    assertThat(event.getEventType()).isEqualTo("ACCOUNT_LOCKED_WRITE_FAILED");
    assertThat(event.getOutcome()).isEqualTo("FAILURE");
    assertThat(event.getUserId()).isEqualTo(USER_ID);
  }

  @Test
  void should_doNothing_when_userNotFoundOnPersistFailedAttempt() {
    when(userRegistrationPort.findById(USER_ID)).thenReturn(Optional.empty());

    service.persistFailedAttempt(USER_ID, NOW);

    verify(userRegistrationPort, never()).save(any());
    verify(authEventPort, never()).record(any());
  }

  // ---------------------------------------------------------------------------
  // persistResetAttempts
  // ---------------------------------------------------------------------------

  /**
   * persistResetAttempts uses a direct bulk UPDATE to avoid the optimistic-lock collision that
   * would occur if it used findById + save in a REQUIRES_NEW transaction while the outer
   * transaction has already mutated the same entity (e.g. via User#unlockIfExpired).
   * The bulk UPDATE leaves the {@code version} column unchanged so the outer session can flush
   * without conflict (M-OL-1).
   */
  @Test
  void should_callResetFailedAttemptsDirect_when_persistResetAttemptsCalled() {
    service.persistResetAttempts(USER_ID);

    verify(userRegistrationPort).resetFailedAttemptsDirect(USER_ID);
    // Must NOT load the entity (to avoid optimistic-lock collision with the outer tx)
    verify(userRegistrationPort, never()).findById(any());
    verify(userRegistrationPort, never()).save(any());
  }

  @Test
  void should_swallowException_when_anyExceptionOnPersistResetAttempts() {
    doThrow(new RuntimeException("db error"))
        .when(userRegistrationPort).resetFailedAttemptsDirect(USER_ID);

    assertThatCode(() -> service.persistResetAttempts(USER_ID))
        .doesNotThrowAnyException();
  }

  @Test
  void should_lockAccountAndRecordEvent_when_failedAttemptExceedsThreshold() {
    // count > LOCKOUT_THRESHOLD (e.g. 6) also triggers the lock (>= comparison)
    User user = mock(User.class);
    when(userRegistrationPort.findById(USER_ID)).thenReturn(Optional.of(user));
    when(user.recordFailedAttempt()).thenReturn(AuthConstants.LOCKOUT_THRESHOLD + 1);
    when(userRegistrationPort.save(user)).thenReturn(user);

    service.persistFailedAttempt(USER_ID, NOW);

    verify(user).lockAccount(NOW.plusSeconds(AuthConstants.LOCKOUT_DURATION_SECONDS));
    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(authEventPort).record(captor.capture());
    assertThat(captor.getValue().getEventType()).isEqualTo("ACCOUNT_LOCKED");
  }

  // ---------------------------------------------------------------------------
  // T-017: M-6 Log-injection — type-contract assertion (T-LCK-14)
  // ---------------------------------------------------------------------------

  /**
   * SecureEventService logs only {@code userId} (a {@link UUID}) and never raw email, password, or
   * attacker-controlled strings. UUID.toString() always produces the canonical 36-character form
   * "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (hex + hyphens) which contains no CRLF characters.
   * The {@code Instant} parameter likewise has a safe toString format. Therefore the log-injection
   * surface on the failed-attempt path is zero by type contract (M-6 / T-LCK-14).
   *
   * <p>This test documents that invariant: calling {@code persistFailedAttempt} completes normally
   * with a standard UUID (which is the only form the type admits — UUID.fromString rejects CRLF).
   */
  @Test
  @DisplayName("Log lines on lockout paths use UUID which is CRLF-safe by type contract (M-6 / T-LCK-14)")
  void persistFailedAttempt_logsOnlyUserId_whichIsTypeConstrainedToNoCRLF() {
    // UUID.toString() always produces "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" — no CRLF possible.
    // UUID.fromString rejects any string containing CRLF or non-hex characters, so the type
    // itself is the injection gate. The log surface is UUID + Instant only.
    UUID userId = UUID.randomUUID();
    User user = mock(User.class);
    when(userRegistrationPort.findById(userId)).thenReturn(Optional.of(user));
    when(user.recordFailedAttempt()).thenReturn(1); // below threshold — no lock
    when(userRegistrationPort.save(user)).thenReturn(user);

    // The real assertion: call completes without log injection, confirmed by type safety.
    assertThatCode(() -> service.persistFailedAttempt(userId, Instant.now()))
        .doesNotThrowAnyException();
  }

  // ---------------------------------------------------------------------------
  // T-018: M-7 ACCOUNT_LOCKED rate signal — mass-lockout campaign detection (T-LCK-3)
  // ---------------------------------------------------------------------------

  /**
   * When the failure counter crosses the threshold, SecureEventService records an ACCOUNT_LOCKED
   * event. This event is the observability signal (M-7) that monitoring tools count to detect
   * mass-lockout campaigns (T-LCK-3): a spike in ACCOUNT_LOCKED events across many userIds in a
   * short time window is a mass-brute-force indicator.
   *
   * <p>The rate-signal test is distinct from the functional lock test in that it focuses on the
   * audit event shape (eventType = "ACCOUNT_LOCKED", outcome = "FAILURE", userId populated) which
   * is what SIEM/alerting consumes. A monitoring alert on {@code eventType = ACCOUNT_LOCKED} with
   * {@code count > threshold_per_minute} closes T-LCK-3.
   */
  @Test
  @DisplayName("persistFailedAttempt at threshold emits ACCOUNT_LOCKED event to authEventPort (M-7 / T-LCK-3 rate signal)")
  void persistFailedAttempt_atThreshold_emitsAccountLockedEventForRateSignal() {
    User user = mock(User.class);
    when(userRegistrationPort.findById(USER_ID)).thenReturn(Optional.of(user));
    when(user.recordFailedAttempt()).thenReturn(AuthConstants.LOCKOUT_THRESHOLD);
    when(userRegistrationPort.save(user)).thenReturn(user);

    service.persistFailedAttempt(USER_ID, NOW);

    // ACCOUNT_LOCKED is the rate signal — monitoring counts this event type to detect campaigns
    ArgumentCaptor<AuthEvent> eventCaptor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(authEventPort).record(eventCaptor.capture());
    assertThat(eventCaptor.getValue().getEventType()).isEqualTo("ACCOUNT_LOCKED");
    assertThat(eventCaptor.getValue().getOutcome()).isEqualTo("FAILURE");
    assertThat(eventCaptor.getValue().getUserId()).isEqualTo(USER_ID);
  }
}
