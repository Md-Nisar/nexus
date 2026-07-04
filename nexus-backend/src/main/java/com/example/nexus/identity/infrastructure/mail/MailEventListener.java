package com.example.nexus.identity.infrastructure.mail;

import com.example.nexus.common.domain.LogMaskingUtil;
import com.example.nexus.identity.application.event.AccountExistsEmailEvent;
import com.example.nexus.identity.application.event.PasswordResetEmailEvent;
import com.example.nexus.identity.application.event.VerificationEmailEvent;
import com.example.nexus.identity.application.port.out.MailSenderPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

  private static final Logger log = LoggerFactory.getLogger(MailEventListener.class);

  private final MailSenderPort mailSenderPort;

  public MailEventListener(MailSenderPort mailSenderPort) {
    this.mailSenderPort = mailSenderPort;
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
    log.debug("Dispatching verification email to {}", LogMaskingUtil.maskEmail(event.toEmail()));
    mailSenderPort.sendVerificationEmail(event.toEmail(), event.rawToken());
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
    log.debug("Dispatching account-exists email to {}", LogMaskingUtil.maskEmail(event.toEmail()));
    mailSenderPort.sendAccountExistsEmail(event.toEmail());
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
    log.debug("Dispatching password-reset email to {}", LogMaskingUtil.maskEmail(event.toEmail()));
    mailSenderPort.sendPasswordResetEmail(event.toEmail(), event.rawToken());
  }
}
