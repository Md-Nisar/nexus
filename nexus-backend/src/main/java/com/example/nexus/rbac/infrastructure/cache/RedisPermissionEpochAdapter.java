package com.example.nexus.rbac.infrastructure.cache;

import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import com.example.nexus.rbac.infrastructure.cache.EpochRedisConfig.EpochTemplates;
import java.util.Collection;
import java.util.List;
import java.util.OptionalLong;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

/**
 * Redis store of the per-user permission epoch (US-018 A9, design §9.2). Key {@code
 * {keyPrefix}:rbac:epoch:{tenantId}:{userId}}, holding a millisecond value.
 *
 * <p>Reads use the dedicated 50 ms template and fail open: a failed, slow or unparseable read
 * returns empty, which the caller counts. Bumps use the dedicated bump template and throw on
 * failure.
 *
 * <p>The bump is one Lua script per call: for each key, {@code new = max(old + 1, Redis TIME in
 * ms)}, then {@code SET key new EX ttl}. The Redis server's clock is the same for every instance,
 * and the {@code max} keeps the value monotonic even after the key is lost. Multi-key scripts are
 * legal because ADR-0016 D1 allows only standalone or Sentinel.
 */
@Component
public class RedisPermissionEpochAdapter implements PermissionEpochPort {

  private static final Logger log = LoggerFactory.getLogger(RedisPermissionEpochAdapter.class);

  private static final RedisScript<Long> BUMP_SCRIPT = RedisScript.of("""
      local ttl = tonumber(ARGV[1])
      local time = redis.call('TIME')
      local nowMs = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
      for _, key in ipairs(KEYS) do
        local old = tonumber(redis.call('GET', key) or '0') or 0
        local new = math.max(old + 1, nowMs)
        redis.call('SET', key, string.format('%.0f', new), 'EX', ttl)
      end
      return #KEYS
      """, Long.class);

  private final EpochTemplates templates;
  private final String keyPrefix;
  private final String keyTtlSeconds;

  public RedisPermissionEpochAdapter(
      EpochTemplates templates,
      @Value("${nexus.redis.key-prefix:nexus}") String keyPrefix,
      @Value("${nexus.rbac.epoch.key-ttl-seconds}") long keyTtlSeconds) {
    this.templates = templates;
    this.keyPrefix = keyPrefix;
    this.keyTtlSeconds = Long.toString(keyTtlSeconds);
  }

  @Override
  public OptionalLong current(UUID tenantId, UUID userId) {
    try {
      String value = templates.read().opsForValue().get(key(tenantId, userId));
      return OptionalLong.of(value == null ? 0L : Long.parseLong(value));
    } catch (DataAccessException | NumberFormatException e) {
      // One line per failed request at DEBUG only; nexus.rbac.epoch.check{outcome=skipped_error}
      // is the signal.
      log.debug("permission epoch read failed exception={}", e.getClass().getSimpleName());
      return OptionalLong.empty();
    }
  }

  @Override
  public void bump(UUID tenantId, Collection<UUID> userIds) {
    List<String> keys = userIds.stream().map(userId -> key(tenantId, userId)).toList();
    templates.bump().execute(BUMP_SCRIPT, keys, keyTtlSeconds);
  }

  private String key(UUID tenantId, UUID userId) {
    return keyPrefix + ":rbac:epoch:" + tenantId + ":" + userId;
  }
}
