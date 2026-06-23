package com.example.nexus.identity.application.port.out;

/**
 * Sliding-window rate-limit store. The default implementation is in-memory
 * ({@code InMemoryRateLimitStore}); a Redis-backed implementation can be activated via
 * {@code nexus.security.rate-limit.store-type=redis} without changing use-case code.
 */
public interface RateLimitStore {

  /**
   * Attempts to consume one slot for the given key in the specified sliding window.
   *
   * <p>Key format conventions:
   * <ul>
   *   <li>{@code "IP:{ip}"} — per-IP login throttle
   *   <li>{@code "USER:{emailHmac}"} — per-username login throttle (HMAC to avoid storing plaintext)
   *   <li>{@code "REFRESH_IP:{ip}"} — per-IP refresh throttle
   * </ul>
   *
   * @param key the rate-limit bucket identifier
   * @param windowSeconds the sliding window duration in seconds
   * @param maxAttempts the maximum number of allowed attempts within the window
   * @return a result indicating whether the attempt is permitted and, if not, when to retry
   */
  RateLimitResult tryConsume(String key, int windowSeconds, int maxAttempts);
}
