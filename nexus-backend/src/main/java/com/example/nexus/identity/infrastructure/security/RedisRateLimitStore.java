package com.example.nexus.identity.infrastructure.security;

import com.example.nexus.identity.application.port.out.RateLimitResult;
import com.example.nexus.identity.application.port.out.RateLimitStore;
import java.time.Clock;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

/**
 * Redis-backed sliding-window-log rate-limit store, shared across replicas (ADR 0016).
 *
 * <p>Activated via {@code nexus.security.rate-limit.store-type=redis}, replacing {@link
 * InMemoryRateLimitStore} without any change to caller code (T-6.1/T-6.3). The prune-count-add
 * sequence runs as a single Lua script ({@code scripts/sliding_window_rate_limit.lua}) so
 * concurrent requests cannot both observe a stale count and both be admitted.
 *
 * <p>Fails open on any Redis error: a non-critical infra outage must never block logins
 * platform-wide (ADR 0016 §D4/§7).
 */
@ConditionalOnProperty(name = "nexus.security.rate-limit.store-type", havingValue = "redis")
@Component
public class RedisRateLimitStore implements RateLimitStore {

  private static final Logger log = LoggerFactory.getLogger(RedisRateLimitStore.class);

  private static final DefaultRedisScript<List> SLIDING_WINDOW_SCRIPT = loadScript();

  private static DefaultRedisScript<List> loadScript() {
    DefaultRedisScript<List> script = new DefaultRedisScript<>();
    script.setResultType(List.class);
    script.setLocation(new ClassPathResource("scripts/sliding_window_rate_limit.lua"));
    script.afterPropertiesSet();
    return script;
  }

  private final StringRedisTemplate redisTemplate;
  private final Clock clock;
  private final String keyPrefix;

  public RedisRateLimitStore(
      StringRedisTemplate redisTemplate,
      Clock clock,
      @Value("${nexus.redis.key-prefix:nexus}") String keyPrefix) {
    this.redisTemplate = redisTemplate;
    this.clock = clock;
    this.keyPrefix = keyPrefix;
  }

  @Override
  @SuppressWarnings("unchecked")
  public RateLimitResult tryConsume(String key, int windowSeconds, int maxAttempts) {
    String redisKey = keyPrefix + ":identity:ratelimit:" + key;
    try {
      List<Long> result =
          redisTemplate.execute(
              SLIDING_WINDOW_SCRIPT,
              List.of(redisKey),
              String.valueOf(clock.millis()),
              String.valueOf(windowSeconds * 1000L),
              String.valueOf(maxAttempts));
      return result.get(0) == 1L
          ? RateLimitResult.permit()
          : RateLimitResult.reject(result.get(1));
    } catch (Exception e) {
      // Log only the bucket type (IP / USER / REFRESH_IP), never the raw key — the key embeds a
      // client IP or email HMAC, both PII per SECURITY.md §7, and must not reach application logs.
      String bucketType = key.contains(":") ? key.substring(0, key.indexOf(':')) : "UNKNOWN";
      log.warn("RATE_LIMIT_REDIS_UNAVAILABLE bucketType={}", bucketType, e);
      return RateLimitResult.permit(); // fail open — ADR 0016 §7
    }
  }
}
