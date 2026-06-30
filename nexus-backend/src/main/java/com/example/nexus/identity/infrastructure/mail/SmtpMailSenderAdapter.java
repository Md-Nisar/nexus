package com.example.nexus.identity.infrastructure.mail;

import com.example.nexus.common.domain.LogMaskingUtil;
import com.example.nexus.identity.application.port.out.MailSenderPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

/**
 * SMTP-backed {@link MailSenderPort} active in all environments where
 * {@code spring.mail.host} is not {@code disabled}.
 *
 * <p>The raw verification token appears only in the email body — never in any log line (SEC-3).
 * Masked email addresses are used in DEBUG logs via {@link LogMaskingUtil}.
 */
@Component
@ConditionalOnMissingBean(LoggingMailSenderAdapter.class)
public class SmtpMailSenderAdapter implements MailSenderPort {

  private static final Logger log = LoggerFactory.getLogger(SmtpMailSenderAdapter.class);
  private static final String VERIFY_SUBJECT = "Verify your Nexus email address";
  private static final String EXISTS_SUBJECT = "You already have a Nexus account";
  private static final String RESET_SUBJECT = "Reset your Nexus password";

  private final JavaMailSender mailSender;
  private final String fromAddress;
  private final String frontendBaseUrl;

  public SmtpMailSenderAdapter(
      JavaMailSender mailSender,
      @Value("${nexus.mail.from-address}") String fromAddress,
      @Value("${nexus.frontend.base-url}") String frontendBaseUrl) {
    this.mailSender = mailSender;
    this.fromAddress = fromAddress;
    this.frontendBaseUrl = frontendBaseUrl;
  }

  @Override
  public void sendVerificationEmail(String toEmail, String rawToken) {
    String url = frontendBaseUrl + "/auth/verify-email?token=" + rawToken;
    SimpleMailMessage msg = new SimpleMailMessage();
    msg.setFrom(fromAddress);
    msg.setTo(toEmail);
    msg.setSubject(VERIFY_SUBJECT);
    msg.setText("Click the link below to verify your email address:\n\n"
        + url + "\n\nThis link expires in 24 hours.");
    mailSender.send(msg);
    log.debug("Verification email sent to {}", LogMaskingUtil.maskEmail(toEmail));
  }

  @Override
  public void sendAccountExistsEmail(String toEmail) {
    SimpleMailMessage msg = new SimpleMailMessage();
    msg.setFrom(fromAddress);
    msg.setTo(toEmail);
    msg.setSubject(EXISTS_SUBJECT);
    msg.setText("A Nexus account already exists for this email address. "
        + "If you forgot your password, please use the password-reset flow.");
    mailSender.send(msg);
    log.debug("Account-exists email sent to {}", LogMaskingUtil.maskEmail(toEmail));
  }

  @Override
  public void sendPasswordResetEmail(String toEmail, String rawToken) {
    String url = frontendBaseUrl + "/auth/reset-password?token=" + rawToken;
    SimpleMailMessage msg = new SimpleMailMessage();
    msg.setFrom(fromAddress);
    msg.setTo(toEmail);
    msg.setSubject(RESET_SUBJECT);
    msg.setText("Click the link below to reset your Nexus password:\n\n"
        + url + "\n\nThis link expires in 1 hour. If you did not request a reset, "
        + "you can safely ignore this email.");
    mailSender.send(msg);
    log.debug("Password-reset email sent to {}", LogMaskingUtil.maskEmail(toEmail));
  }
}
