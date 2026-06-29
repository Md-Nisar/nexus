package com.example.nexus.common.domain;

/**
 * Thrown when a user account is locked due to repeated failed login attempts.
 * Maps to HTTP 423 Locked with a {@code Retry-After} header and error code {@code AUTH_LCK_001}.
 */
public class AccountLockedException extends DomainException {

  private final long retryAfterSeconds;

  public AccountLockedException(String code, String message, long retryAfterSeconds) {
    super(code, message);
    this.retryAfterSeconds = retryAfterSeconds;
  }

  public long retryAfterSeconds() {
    return retryAfterSeconds;
  }
}
