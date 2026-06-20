package com.example.nexus.identity.infrastructure.mail;

import com.example.nexus.common.domain.LogMaskingUtil;
import com.example.nexus.identity.application.event.AccountExistsEmailEvent;
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

  @Async
  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  public void onVerificationEmail(VerificationEmailEvent event) {
    log.debug("Dispatching verification email to {}", LogMaskingUtil.maskEmail(event.toEmail()));
    mailSenderPort.sendVerificationEmail(event.toEmail(), event.rawToken());
  }

  @Async
  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  public void onAccountExists(AccountExistsEmailEvent event) {
    log.debug("Dispatching account-exists email to {}", LogMaskingUtil.maskEmail(event.toEmail()));
    mailSenderPort.sendAccountExistsEmail(event.toEmail());
  }
}
