package com.example.nexus.common.domain;

/**
 * A refresh request rejected by one of the use-case-side refresh buckets (per-family or per-IP
 * failure; US-018 T-013). Maps to the same 429 and {@code Retry-After} as {@link
 * RateLimitException}, and to the same {@code RATE_001} code the filter-side buckets use, so
 * clients see one shape. It is a distinct type only so that {@code GlobalExceptionHandler} can
 * skip its per-request WARN: the use case emits its own single WARN per window, and an attacker
 * must not be able to turn a throttled storm into one log line per request.
 */
public class RefreshThrottledException extends RateLimitException {

  private static final String CODE = "RATE_001";
  private static final String MESSAGE = "Too many requests. Try again later.";

  public RefreshThrottledException(long retryAfterSeconds) {
    super(CODE, MESSAGE, retryAfterSeconds);
  }
}
