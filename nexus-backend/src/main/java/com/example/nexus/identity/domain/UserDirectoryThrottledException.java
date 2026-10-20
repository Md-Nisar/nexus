package com.example.nexus.identity.domain;

import com.example.nexus.common.domain.RateLimitException;

/**
 * A directory email lookup refused because the actor exceeded the per-actor lookup throttle
 * (US-019 NF-S5, design §4.5). Maps to 429 {@code USER_DIR_001} with {@code Retry-After}.
 *
 * <p>{@link #selfReported()} is {@code true}: {@code UserDirectoryService} emits at most one WARN
 * {@code IDENTITY_DIRECTORY_THROTTLED} per window, so the exception handler logs each rejection at
 * DEBUG (RC-63(c)). The message is a fixed literal and never names the email.
 */
public class UserDirectoryThrottledException extends RateLimitException {

  private static final String CODE = "USER_DIR_001";
  private static final String MESSAGE = "Too many directory lookups; try again later";

  public UserDirectoryThrottledException(long retryAfterSeconds) {
    super(CODE, MESSAGE, retryAfterSeconds);
  }

  @Override
  public boolean selfReported() {
    return true;
  }
}
