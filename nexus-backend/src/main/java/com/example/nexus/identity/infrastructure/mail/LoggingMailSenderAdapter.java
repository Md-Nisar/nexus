package com.example.nexus.identity.infrastructure.mail;

import com.example.nexus.common.domain.LogMaskingUtil;
import com.example.nexus.identity.application.port.out.MailSenderPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * No-op {@link MailSenderPort} that logs instead of sending mail.
 *
 * <p>Active when {@code spring.mail.host=disabled} (smoke tests, IT contexts). Causes
 * {@link SmtpMailSenderAdapter} to be skipped via its {@code @ConditionalOnMissingBean}.
 * The raw token is never logged (SEC-3) — only the masked email address appears.
 */
@Component
@ConditionalOnProperty(name = "spring.mail.host", havingValue = "disabled")
public class LoggingMailSenderAdapter implements MailSenderPort {

  private static final Logger log = LoggerFactory.getLogger(LoggingMailSenderAdapter.class);

  @Override
  public void sendVerificationEmail(String toEmail, String rawToken) {
    log.info("[MAIL-STUB] Verification email → {} (token omitted)",
        LogMaskingUtil.maskEmail(toEmail));
  }

  @Override
  public void sendAccountExistsEmail(String toEmail) {
    log.info("[MAIL-STUB] Account-exists email → {}", LogMaskingUtil.maskEmail(toEmail));
  }
}
