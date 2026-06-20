package com.example.nexus.identity.application.port.out;

/**
 * Outbound port for dispatching transactional emails in the identity context.
 *
 * <p>Implementations: {@code SmtpMailSenderAdapter} (dev/prod with SMTP), {@code
 * LoggingMailSenderAdapter} (smoke / IT — active when {@code spring.mail.host=disabled}).
 */
public interface MailSenderPort {

  /**
   * Sends an email-verification link to the given address.
   *
   * @param toEmail  recipient's plaintext email address
   * @param rawToken 64-char hex verification token (included in the link body; must never appear
   *                 in any log statement — SEC-3)
   */
  void sendVerificationEmail(String toEmail, String rawToken);

  /**
   * Notifies the given address that an account already exists (anti-enumeration — REG-05).
   *
   * @param toEmail recipient's plaintext email address
   */
  void sendAccountExistsEmail(String toEmail);
}
