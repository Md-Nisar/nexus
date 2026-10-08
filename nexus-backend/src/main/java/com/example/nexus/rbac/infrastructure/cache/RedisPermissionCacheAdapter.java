package com.example.nexus.rbac.infrastructure.cache;

import com.example.nexus.rbac.application.RoleResolutionService;
import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

/**
 * Redis-backed roles/permissions cache (ADR 0016 D3/D4). Two Redis SETs per cache entry, sharing
 * a TTL, keyed by the permission epoch the entry was computed under (US-018 Decision 17): {@code
 * {keyPrefix}:rbac:permset:{tenantId}:{userId}:{epoch}} (permission names) and {@code
 * {keyPrefix}:rbac:roleset:{tenantId}:{userId}:{epoch}} (role names); {@link RbacRedisKeys} owns the
 * shapes. The role set is cached alongside permissions specifically so {@link
 * RoleResolutionService} can use it as a freshness fingerprint against a live role read — see that
 * class's Javadoc.
 *
 * <p>Eviction runs one Lua script per batch of {@value #EVICT_BATCH_SIZE} users: for each user it
 * reads the current epoch ({@code 0} when absent) and deletes both sets under it, so the entry the
 * next mint would read is the one removed. It never changes an epoch. Building a cache key inside
 * the script from the epoch it read is legal only because Redis Cluster is rejected at startup
 * (ADR-0016 D1, {@link EpochRedisConfig}); under Cluster those keys would not be declared.
 *
 * <p>Fails open on any Redis error, matching {@link
 * com.example.nexus.identity.infrastructure.security.RedisRateLimitStore}'s convention: the cache
 * is never authoritative, so an outage must only cost {@link RoleResolutionService} an extra DB
 * read, never block login. A failed eviction batch ends the eviction with one WARN; the remaining
 * entries expire with the TTL.
 */
@Component
public class RedisPermissionCacheAdapter implements PermissionCachePort {

  private static final Logger log = LoggerFactory.getLogger(RedisPermissionCacheAdapter.class);

  static final int EVICT_BATCH_SIZE = 500;

  // SADD requires at least one member; this marker preserves a "cached but empty" set (e.g. a
  // user with no roles, or a role with no permissions) so get() doesn't mistake it for a miss.
  private static final String EMPTY_MARKER = "__EMPTY__";

  // KEYS[i] = epoch key of user i; ARGV[2i-1] / ARGV[2i] = that user's roleset / permset stem.
  // The epoch is formatted as the bump script writes it and as Long.toString renders it.
  private static final RedisScript<Long> EVICT_SCRIPT = RedisScript.of("""
      for i, key in ipairs(KEYS) do
        local epoch = string.format('%.0f', tonumber(redis.call('GET', key) or '0') or 0)
        redis.call('DEL', ARGV[2 * i - 1] .. epoch, ARGV[2 * i] .. epoch)
      end
      return #KEYS
      """, Long.class);

  private final StringRedisTemplate redisTemplate;
  private final RbacRedisKeys keys;
  private final Duration ttl;

  public RedisPermissionCacheAdapter(
      StringRedisTemplate redisTemplate,
      @Value("${nexus.redis.key-prefix:nexus}") String keyPrefix,
      @Value("${nexus.rbac.permission-cache-ttl-seconds:900}") long ttlSeconds) {
    this.redisTemplate = redisTemplate;
    this.keys = new RbacRedisKeys(keyPrefix);
    this.ttl = Duration.ofSeconds(ttlSeconds);
  }

  @Override
  public Optional<ResolvedPermissions> get(UUID tenantId, UUID userId, long epoch) {
    try {
      String roleKey = keys.roleset(tenantId, userId, epoch);
      String permKey = keys.permset(tenantId, userId, epoch);
      // Both keys are written together (put) and expire together (shared TTL); either being
      // absent means the entry as a whole is a miss.
      Boolean roleKeyExists = redisTemplate.hasKey(roleKey);
      Boolean permKeyExists = redisTemplate.hasKey(permKey);
      if (!Boolean.TRUE.equals(roleKeyExists) || !Boolean.TRUE.equals(permKeyExists)) {
        return Optional.empty();
      }
      List<String> roles = readMembers(roleKey);
      List<String> permissions = readMembers(permKey);
      return Optional.of(new ResolvedPermissions(roles, permissions));
    } catch (Exception e) {
      log.warn("RBAC_PERMISSION_CACHE_UNAVAILABLE operation=get", e);
      return Optional.empty();
    }
  }

  @Override
  public void put(UUID tenantId, UUID userId, long epoch, ResolvedPermissions resolved) {
    try {
      writeSet(keys.roleset(tenantId, userId, epoch), resolved.roles());
      writeSet(keys.permset(tenantId, userId, epoch), resolved.permissions());
    } catch (Exception e) {
      log.warn("RBAC_PERMISSION_CACHE_UNAVAILABLE operation=put", e);
    }
  }

  @Override
  public void evict(UUID tenantId, UUID userId) {
    evict(tenantId, List.of(userId));
  }

  @Override
  public void evict(UUID tenantId, Collection<UUID> userIds) {
    List<UUID> users = List.copyOf(userIds);
    for (int from = 0; from < users.size(); from += EVICT_BATCH_SIZE) {
      List<UUID> batch = users.subList(from, Math.min(from + EVICT_BATCH_SIZE, users.size()));
      try {
        evictBatch(tenantId, batch);
      } catch (RuntimeException e) {
        // Fail open: the un-evicted entries expire with the TTL. No ids in the line.
        log.warn("RBAC_PERMISSION_CACHE_UNAVAILABLE operation=evict unevictedUsers={} exception={}",
            users.size() - from, e.getClass().getSimpleName());
        return;
      }
    }
  }

  private void evictBatch(UUID tenantId, List<UUID> batch) {
    List<String> epochKeys = new ArrayList<>(batch.size());
    Object[] stems = new Object[batch.size() * 2];
    for (int i = 0; i < batch.size(); i++) {
      UUID userId = batch.get(i);
      epochKeys.add(keys.epoch(tenantId, userId));
      stems[2 * i] = keys.rolesetStem(tenantId, userId);
      stems[2 * i + 1] = keys.permsetStem(tenantId, userId);
    }
    redisTemplate.execute(EVICT_SCRIPT, epochKeys, stems);
  }

  private List<String> readMembers(String key) {
    Set<String> members = redisTemplate.opsForSet().members(key);
    if (members == null) {
      return List.of();
    }
    return members.stream().filter(m -> !EMPTY_MARKER.equals(m)).sorted().toList();
  }

  private void writeSet(String key, List<String> values) {
    redisTemplate.delete(key);
    if (!values.isEmpty()) {
      redisTemplate.opsForSet().add(key, values.toArray(new String[0]));
    } else {
      redisTemplate.opsForSet().add(key, EMPTY_MARKER);
    }
    redisTemplate.expire(key, ttl);
  }
}
