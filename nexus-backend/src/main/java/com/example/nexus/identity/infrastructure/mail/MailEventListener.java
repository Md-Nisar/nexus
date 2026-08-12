package com.example.nexus.identity.infrastructure.mail;

import com.example.nexus.common.observation.ExecutionObserver;
import com.example.nexus.identity.application.event.AccountExistsEmailEvent;
import com.example.nexus.identity.application.event.PasswordResetEmailEvent;
import com.example.nexus.identity.application.event.VerificationEmailEvent;
import com.example.nexus.identity.application.port.out.MailSenderPort;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Bridges Spring application events to the {@link MailSenderPort}.
 *
 * <p>{@code @TransactionalEventListener(AFTER_COMMIT)} guarantees dispatch only after the
 * registration transaction commits — no email is sent if the DB write rolls back.
 * {@code @Async} offloads SMTP to the shared async executor so the HTTP response is not
 * blocked by mail latency. Both handler methods must return {@code void}.
 */
@Component
public class MailEventListener {

  private static final String EVENT_PROCESSING = "event_processing";
  private static final String EXECUTION_TYPE_ASYNC = "async";

  private final MailSenderPort mailSenderPort;
  private final ExecutionObserver executionObserver;

  public MailEventListener(MailSenderPort mailSenderPort, ExecutionObserver executionObserver) {
    this.mailSenderPort = mailSenderPort;
    this.executionObserver = executionObserver;
  }

  /**
   * Listens for {@link VerificationEmailEvent} after the registration transaction commits
   * and dispatches the verification email asynchronously.
   *
   * @param event the verification email event containing the email address and token
   */
  @Async
  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  public void onVerificationEmail(VerificationEmailEvent event) {
    executionObserver.observe(
        EVENT_PROCESSING,
        EXECUTION_TYPE_ASYNC,
        "onVerificationEmail",
        true, // Log success at INFO
        true, // Terminal async boundary
        () -> mailSenderPort.sendVerificationEmail(event.toEmail(), event.rawToken())
    );
  }

  /**
   * Listens for {@link AccountExistsEmailEvent} after the registration transaction commits
   * and dispatches a notification email to the existing account owner.
   *
   * @param event the account-exists email event containing the email address
   */
  @Async
  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  public void onAccountExists(AccountExistsEmailEvent event) {
    executionObserver.observe(
        EVENT_PROCESSING,
        EXECUTION_TYPE_ASYNC,
        "onAccountExists",
        true,
        true,
        () -> mailSenderPort.sendAccountExistsEmail(event.toEmail())
    );
  }

  /**
   * Listens for {@link PasswordResetEmailEvent} after the password-reset-request transaction commits
   * and dispatches the reset link email asynchronously.
   *
   * @param event the password-reset email event containing the email address and reset token
   */
  @Async
  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  public void onPasswordReset(PasswordResetEmailEvent event) {
    executionObserver.observe(
        EVENT_PROCESSING,
        EXECUTION_TYPE_ASYNC,
        "onPasswordReset",
        true,
        true,
        () -> mailSenderPort.sendPasswordResetEmail(event.toEmail(), event.rawToken())
    );
  }
}
