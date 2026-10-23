package com.example.nexus.common.domain;

/**
 * Thrown when a caller exceeds an allowed request rate. Maps to HTTP 429 Too Many Requests
 * with a {@code Retry-After} response header whose value is {@link #retryAfterSeconds()}.
 */
public class RateLimitException extends DomainException {

  private final long retryAfterSeconds;

  public RateLimitException(String code, String message, long retryAfterSeconds) {
    super(code, message);
    this.retryAfterSeconds = retryAfterSeconds;
  }

  public long retryAfterSeconds() {
    return retryAfterSeconds;
  }

  /**
   * Whether the thrower already emitted its own log line for this rejection, so the exception
   * handler logs at DEBUG instead of WARN.
   */
  public boolean selfReported() {
    return false;
  }
}
