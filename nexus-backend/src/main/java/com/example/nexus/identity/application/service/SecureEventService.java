package com.example.nexus.identity.application.service;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Application-layer service for security-critical writes that must commit independently
 * of the surrounding request transaction.
 *
 * <p>REQUIRES_NEW on each method ensures audit events and family revocations are durably
 * recorded even when the caller's {@code @Transactional} rolls back (e.g. on
 * {@code AuthenticationException} from a failed login attempt). Placing
 * {@code @Transactional} here rather than on the infrastructure adapters keeps transaction
 * demarcation decisions at the application layer per the project convention.
 */
@Service
public class SecureEventService {

  private static final Logger log = LoggerFactory.getLogger(SecureEventService.class);

  private final AuthEventPort authEventPort;
  private final RefreshTokenPort refreshTokenPort;
  private final UserRegistrationPort userRegistrationPort;
  private final UuidGenerator uuidGenerator;

  public SecureEventService(
      AuthEventPort authEventPort,
      RefreshTokenPort refreshTokenPort,
      UserRegistrationPort userRegistrationPort,
      UuidGenerator uuidGenerator) {
    this.authEventPort = authEventPort;
    this.refreshTokenPort = refreshTokenPort;
    this.userRegistrationPort = userRegistrationPort;
    this.uuidGenerator = uuidGenerator;
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void recordEvent(AuthEvent event) {
    authEventPort.record(event);
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void revokeFamily(UUID familyId, Instant revokedAt) {
    refreshTokenPort.revokeFamily(familyId, revokedAt);
  }

  /**
   * Re-reads the user in a new transaction, increments the failure counter, and — if the new
   * count reaches {@link AuthConstants#LOCKOUT_THRESHOLD} — locks the account until
   * {@code now + LOCKOUT_DURATION_SECONDS} and records an ACCOUNT_LOCKED event.
   *
   * <p>Commits independently of the caller's rolled-back login transaction (REQUIRES_NEW).
   *
   * <p>Exception policy (DF-2 / M-8):
   * <ul>
   *   <li>{@link ObjectOptimisticLockingFailureException} — swallowed as benign lost increment
   *       (two concurrent failures race; one wins, one is lost).
   *   <li>Any other exception — logged at WARN with {@code userId} only; an
   *       {@code ACCOUNT_LOCKED_WRITE_FAILED} audit event is recorded; the exception is NOT
   *       rethrown so the caller can still throw AUTH_001 rather than a 500.
   * </ul>
   */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void persistFailedAttempt(UUID userId, Instant now) {
    try {
      Optional<User> userOpt = userRegistrationPort.findById(userId);
      if (userOpt.isEmpty()) {
        return; // user vanished between lookup and write — benign
      }
      User user = userOpt.get();
      int count = user.recordFailedAttempt();
      if (count >= AuthConstants.LOCKOUT_THRESHOLD) {
        user.lockAccount(now.plusSeconds(AuthConstants.LOCKOUT_DURATION_SECONDS));
        authEventPort.record(
            new AuthEvent(uuidGenerator.newId(), "ACCOUNT_LOCKED", "FAILURE")
                .withUserId(userId));
        log.warn("ACCOUNT_LOCKED userId={}", userId);
      }
      userRegistrationPort.save(user);
    } catch (ObjectOptimisticLockingFailureException e) {
      log.debug(
          "ACCOUNT_LOCK_INCREMENT_LOST userId={} (optimistic lock collision, benign)", userId);
    } catch (Exception e) {
      log.warn("ACCOUNT_LOCKED_WRITE_FAILED userId={}", userId, e);
      authEventPort.record(
          new AuthEvent(uuidGenerator.newId(), "ACCOUNT_LOCKED_WRITE_FAILED", "FAILURE")
              .withUserId(userId));
    }
  }

  /**
   * Revokes all active refresh-token families for the given user in an independent transaction.
   *
   * <p>REQUIRES_NEW ensures the revocation is durable even if the caller's transaction rolls back.
   * Called by {@code ResetPasswordUseCase} after a successful password reset (AC-3).
   */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void revokeAllUserSessions(UUID userId, Instant revokedAt) {
    refreshTokenPort.revokeByUserId(userId, revokedAt);
  }

  /**
   * Resets the failure counter and clears the lockout timestamp for the given user.
   *
   * <p>Uses a direct bulk UPDATE (bypassing the {@code @Version} optimistic-lock check) so this
   * method is safe to call from a REQUIRES_NEW boundary even when the outer transaction has
   * already mutated the same {@link User} entity in its session (e.g. after
   * {@code User#unlockIfExpired}). A load+save approach would increment {@code version} to V+1
   * inside the REQUIRES_NEW tx, causing an {@code ObjectOptimisticLockingFailureException} when
   * the outer tx later flushes its in-memory entity at version V (M-OL-1).
   *
   * <p>Swallows all exceptions — a failed reset on a successful login is benign; the counter
   * will be reset on the next successful login anyway.
   */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void persistResetAttempts(UUID userId) {
    try {
      userRegistrationPort.resetFailedAttemptsDirect(userId);
    } catch (Exception e) {
      log.warn("ACCOUNT_RESET_WRITE_FAILED userId={}", userId, e);
    }
  }
}
