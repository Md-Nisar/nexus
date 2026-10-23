package com.example.nexus.identity.domain;

import com.example.nexus.common.domain.RateLimitException;

/**
 * A directory read refused because the actor exceeded the per-actor ceiling across all four
 * directory operations (US-019 RC-61.3, design §4.5). Maps to 429 {@code USER_DIR_002} with {@code
 * Retry-After}.
 *
 * <p>{@link #selfReported()} is {@code true}: {@code DirectoryAccessGuard} emits at most one WARN
 * per window, so the exception handler logs each rejection at DEBUG (RC-63(c)).
 */
public class UserDirectoryCeilingExceededException extends RateLimitException {

  private static final String CODE = "USER_DIR_002";
  private static final String MESSAGE = "Too many directory requests; try again later";

  public UserDirectoryCeilingExceededException(long retryAfterSeconds) {
    super(CODE, MESSAGE, retryAfterSeconds);
  }

  @Override
  public boolean selfReported() {
    return true;
  }
}
