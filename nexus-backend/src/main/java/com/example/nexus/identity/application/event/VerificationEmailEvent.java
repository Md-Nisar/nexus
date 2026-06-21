package com.example.nexus.identity.application.event;

import com.example.nexus.common.domain.LogMaskingUtil;
import java.util.UUID;

/**
 * Domain event published after a user registers, requesting that a verification email be sent.
 *
 * <p>Consumed by {@code MailEventListener} via {@code @TransactionalEventListener(AFTER_COMMIT)}
 * to guarantee the email is only dispatched after the registration transaction commits.
 *
 * @param toEmail   the recipient's plaintext email address (decrypted just before publish)
 * @param rawToken  the unencoded verification token (never persisted in this form — the hash is
 *                  what is stored; must never appear in any log statement — SEC-3)
 * @param userId    the newly registered user's ID (for logging; not included in the email body)
 */
public record VerificationEmailEvent(String toEmail, String rawToken, UUID userId) {

  @Override
  public String toString() {
    return "VerificationEmailEvent[toEmail=" + LogMaskingUtil.maskEmail(toEmail)
        + ", rawToken=<redacted>, userId=" + userId + "]";
  }
}
