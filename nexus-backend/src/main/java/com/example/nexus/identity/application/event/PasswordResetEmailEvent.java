package com.example.nexus.identity.application.event;

import com.example.nexus.common.domain.LogMaskingUtil;
import java.util.UUID;

/**
 * Domain event published after a reset token is created, requesting that a password-reset
 * email be dispatched.
 *
 * <p>Consumed by {@code MailEventListener} via {@code @TransactionalEventListener(AFTER_COMMIT)}
 * to guarantee the email is only dispatched after the transaction commits.
 *
 * @param toEmail   the recipient's plaintext email address (decrypted just before publish)
 * @param rawToken  the 64-char hex reset token (never persisted in this form; must never
 *                  appear in any log statement — SEC-3)
 * @param userId    the requesting user's ID (for logging; not included in the email body)
 */
public record PasswordResetEmailEvent(String toEmail, String rawToken, UUID userId) {

  @Override
  public String toString() {
    return "PasswordResetEmailEvent[toEmail=" + LogMaskingUtil.maskEmail(toEmail)
        + ", rawToken=<redacted>, userId=" + userId + "]";
  }
}
