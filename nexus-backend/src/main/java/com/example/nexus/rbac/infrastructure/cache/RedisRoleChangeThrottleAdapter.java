package com.example.nexus.rbac.infrastructure.cache;

import com.example.nexus.rbac.application.port.out.RoleChangeThrottlePort;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

/**
 * Redis-native {@link RoleChangeThrottlePort} (US-018 B8, design §10.8): the sliding window of
 * denials, the throttled-until marker and the suppressed-denial count all live in Redis under
 * {@code {keyPrefix}:rbac:throttle:{tenantId}:{actorUserId}} (see {@link RbacRedisKeys}), so the
 * throttle is shared by every replica. This closes RES-11, the per-JVM map of {@code
 * RateLimitRoleChangeThrottleAdapter}, which is used only for {@code
 * nexus.security.rate-limit.store-type=memory}.
 *
 * <p><b>Atomic.</b> Recording a denial prunes the window, counts, adds or crosses the bound, and
 * sets the marker in ONE Lua script, so two replicas cannot disagree about who is throttled. The
 * script reads Redis's own clock ({@code TIME}), not a replica's, so replica clock skew cannot move
 * the window. Same bound semantics as {@code InMemoryRateLimitStore}: the first {@code max-denials}
 * denials in a window are admitted, the next one crosses the bound and starts a throttle episode
 * lasting until the oldest counted denial leaves the window. Building keys inside a script is
 * legal only because Redis Cluster is rejected at startup (ADR-0016 D1).
 *
 * <p><b>Fails safe.</b> Per the port contract no method throws; on a Redis error the actor is
 * reported as not throttled (the throttle bounds cost and is not an authorization control, so an
 * outage must never permit or block anything the gate has not decided) and a WARN is logged without
 * identifiers.
 */
@Component
@ConditionalOnProperty(name = "nexus.security.rate-limit.store-type", havingValue = "redis")
public class RedisRoleChangeThrottleAdapter implements RoleChangeThrottlePort {

  private static final Logger log = LoggerFactory.getLogger(RedisRoleChangeThrottleAdapter.class);

  // KEYS[1] window (sorted set), KEYS[2] throttled-until marker, KEYS[3] suppressed count.
  // ARGV[1] window ms, ARGV[2] max denials, ARGV[3] unique member suffix.
  // Returns 1 when this denial starts a throttle episode, else 0.
  private static final RedisScript<Long> RECORD_DENIAL_SCRIPT = RedisScript.of("""
      local t = redis.call('TIME')
      local now = t[1] * 1000 + math.floor(t[2] / 1000)
      local window = tonumber(ARGV[1])
      local maxDenials = tonumber(ARGV[2])
      redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
      if redis.call('ZCARD', KEYS[1]) < maxDenials then
        redis.call('ZADD', KEYS[1], now, now .. '-' .. ARGV[3])
        redis.call('PEXPIRE', KEYS[1], window)
        return 0
      end
      local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
      local retryMs = math.max(1000, window - (now - tonumber(oldest[2])))
      local wasThrottled = redis.call('EXISTS', KEYS[2])
      redis.call('SET', KEYS[2], '1', 'PX', retryMs)
      if wasThrottled == 0 then
        redis.call('DEL', KEYS[3])
        return 1
      end
      return 0
      """, Long.class);

  // KEYS[1] suppressed count, KEYS[2] throttled-until marker. ARGV[1] fallback TTL ms.
  // The count lives as long as the throttle episode. Returns the count including this denial.
  private static final RedisScript<Long> RECORD_SUPPRESSED_SCRIPT = RedisScript.of("""
      local n = redis.call('INCR', KEYS[1])
      if n == 1 then
        local ttl = redis.call('PTTL', KEYS[2])
        if ttl < 1 then ttl = tonumber(ARGV[1]) end
        redis.call('PEXPIRE', KEYS[1], ttl)
      end
      return n
      """, Long.class);

  private final StringRedisTemplate redisTemplate;
  private final RbacRedisKeys keys;
  private final int maxDenials;
  private final long windowMillis;

  public RedisRoleChangeThrottleAdapter(
      StringRedisTemplate redisTemplate,
      @Value("${nexus.redis.key-prefix:nexus}") String keyPrefix,
      @Value("${nexus.rbac.denial-throttle.max-denials}") int maxDenials,
      @Value("${nexus.rbac.denial-throttle.window-seconds}") int windowSeconds) {
    this.redisTemplate = redisTemplate;
    this.keys = new RbacRedisKeys(keyPrefix);
    this.maxDenials = maxDenials;
    this.windowMillis = windowSeconds * 1000L;
  }

  @Override
  public boolean isThrottled(UUID tenantId, UUID actorUserId) {
    try {
      return Boolean.TRUE.equals(redisTemplate.hasKey(keys.throttleUntil(tenantId, actorUserId)));
    } catch (RuntimeException e) {
      log.warn("RBAC_THROTTLE_REDIS_UNAVAILABLE operation=isThrottled, failing safe (not throttled)", e);
      return false;
    }
  }

  @Override
  public boolean recordDenial(UUID tenantId, UUID actorUserId) {
    try {
      Long transition =
          redisTemplate.execute(
              RECORD_DENIAL_SCRIPT,
              List.of(
                  keys.throttle(tenantId, actorUserId),
                  keys.throttleUntil(tenantId, actorUserId),
                  keys.throttleSuppressed(tenantId, actorUserId)),
              String.valueOf(windowMillis),
              String.valueOf(maxDenials),
              UUID.randomUUID().toString());
      return Long.valueOf(1L).equals(transition);
    } catch (RuntimeException e) {
      log.warn("RBAC_THROTTLE_REDIS_UNAVAILABLE operation=recordDenial, failing safe (not throttled)", e);
      return false;
    }
  }

  @Override
  public int recordSuppressedDenial(UUID tenantId, UUID actorUserId) {
    try {
      Long count =
          redisTemplate.execute(
              RECORD_SUPPRESSED_SCRIPT,
              List.of(
                  keys.throttleSuppressed(tenantId, actorUserId),
                  keys.throttleUntil(tenantId, actorUserId)),
              String.valueOf(windowMillis));
      return count == null ? 0 : Math.toIntExact(Math.min(count, Integer.MAX_VALUE));
    } catch (RuntimeException e) {
      log.warn("RBAC_THROTTLE_REDIS_UNAVAILABLE operation=recordSuppressedDenial", e);
      return 0;
    }
  }
}
