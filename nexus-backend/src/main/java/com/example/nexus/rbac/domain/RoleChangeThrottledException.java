package com.example.nexus.rbac.domain;

import com.example.nexus.common.domain.RateLimitException;

/**
 * A role assign or revoke refused because the actor is throttled after repeated denials and the
 * request targets an admin-defining role or the actor themself (US-019 B7, design §9.3). Maps to
 * 429 {@code RBAC_011} with {@code Retry-After}. No audit row is written for it.
 *
 * <p>{@link #selfReported()} is {@code true}: the service's once-per-window WARN {@code
 * RBAC_DENIAL_THROTTLE_ENGAGED} already covers the episode, so the exception handler logs each
 * rejection at DEBUG and an attacker cannot turn a throttled storm into one WARN per request
 * (US-018 RC-33.1). The message is a fixed literal and names no role or target.
 */
public class RoleChangeThrottledException extends RateLimitException {

  private static final String CODE = "RBAC_011";
  private static final String MESSAGE = "Too many denied role changes; try again later";

  public RoleChangeThrottledException(long retryAfterSeconds) {
    super(CODE, MESSAGE, retryAfterSeconds);
  }

  @Override
  public boolean selfReported() {
    return true;
  }
}
