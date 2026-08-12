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

  private static final String EVENT_INTEGRATION_CALL = "integration_call";
  private static final String EXECUTION_TYPE_ASYNC = "async";

  private final ExecutionObserver executionObserver;

  public LoggingMailSenderAdapter(ExecutionObserver executionObserver) {
    this.executionObserver = executionObserver;
  }

  @Override
  public void sendVerificationEmail(String toEmail, String rawToken) {
    executionObserver.observe(
        EVENT_INTEGRATION_CALL,
        EXECUTION_TYPE_ASYNC,
        "sendVerificationEmail",
        true, // Log success at INFO for stubbed integration
        false, // Not terminal boundary
        () -> null
    );
  }

  @Override
  public void sendAccountExistsEmail(String toEmail) {
    executionObserver.observe(
        EVENT_INTEGRATION_CALL,
        EXECUTION_TYPE_ASYNC,
        "sendAccountExistsEmail",
        true,
        false,
        () -> null
    );
  }

  @Override
  public void sendPasswordResetEmail(String toEmail, String rawToken) {
    executionObserver.observe(
        EVENT_INTEGRATION_CALL,
        EXECUTION_TYPE_ASYNC,
        "sendPasswordResetEmail",
        true,
        false,
        () -> null
    );
  }
}
