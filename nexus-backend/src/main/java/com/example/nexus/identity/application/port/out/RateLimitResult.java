package com.example.nexus.identity.application.port.out;

/**
 * Result of a sliding-window rate-limit check performed by {@link RateLimitStore}.
 * Use the static factory methods rather than the canonical constructor.
 */
public record RateLimitResult(boolean allowed, long retryAfterSeconds) {

  /** Returns a result indicating the attempt is permitted. */
  public static RateLimitResult permit() {
    return new RateLimitResult(true, 0);
  }

  /**
   * Returns a result indicating the attempt is rejected for the given interval.
   *
   * @param retryAfterSeconds seconds until the sliding window resets
   */
  public static RateLimitResult reject(long retryAfterSeconds) {
    return new RateLimitResult(false, retryAfterSeconds);
  }
}
