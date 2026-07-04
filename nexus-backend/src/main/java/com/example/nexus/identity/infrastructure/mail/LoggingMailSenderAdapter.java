package com.example.nexus.identity.infrastructure.mail;

import com.example.nexus.common.observation.ExecutionObserver;
import com.example.nexus.identity.application.port.out.MailSenderPort;
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

  private final ExecutionObserver executionObserver;

  public LoggingMailSenderAdapter(ExecutionObserver executionObserver) {
    this.executionObserver = executionObserver;
  }

  @Override
  public void sendVerificationEmail(String toEmail, String rawToken) {
    executionObserver.observe(
        "integration_call",
        "async",
        "sendVerificationEmail",
        true, // Log success at INFO for stubbed integration
        false, // Not terminal boundary
        () -> {
          // No-op stub
          return null;
        }
    );
  }

  @Override
  public void sendAccountExistsEmail(String toEmail) {
    executionObserver.observe(
        "integration_call",
        "async",
        "sendAccountExistsEmail",
        true,
        false,
        () -> {
          // No-op stub
          return null;
        }
    );
  }

  @Override
  public void sendPasswordResetEmail(String toEmail, String rawToken) {
    executionObserver.observe(
        "integration_call",
        "async",
        "sendPasswordResetEmail",
        true,
        false,
        () -> {
          // No-op stub
          return null;
        }
    );
  }
}
