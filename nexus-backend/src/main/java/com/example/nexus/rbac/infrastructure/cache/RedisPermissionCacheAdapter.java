package com.example.nexus.rbac.infrastructure.cache;

import com.example.nexus.rbac.application.RoleResolutionService;
import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/**
 * Redis-backed roles/permissions cache (ADR 0016 D3/D4). Two Redis SETs per cache entry, sharing
 * a TTL: {@code {keyPrefix}:rbac:permset:{tenantId}:{userId}} (permission names) and {@code
 * {keyPrefix}:rbac:roleset:{tenantId}:{userId}} (role names). The role set is cached alongside
 * permissions specifically so {@link RoleResolutionService} can use it as a freshness fingerprint
 * against a live role read — see that class's Javadoc.
 *
 * <p>Fails open on any Redis error, matching {@link
 * com.example.nexus.identity.infrastructure.security.RedisRateLimitStore}'s convention: the cache
 * is never authoritative, so an outage must only cost {@link RoleResolutionService} an extra DB
 * read, never block login.
 */
@Component
public class RedisPermissionCacheAdapter implements PermissionCachePort {

  private static final Logger log = LoggerFactory.getLogger(RedisPermissionCacheAdapter.class);

  // SADD requires at least one member; this marker preserves a "cached but empty" set (e.g. a
  // user with no roles, or a role with no permissions) so get() doesn't mistake it for a miss.
  private static final String EMPTY_MARKER = "__EMPTY__";

  private final StringRedisTemplate redisTemplate;
  private final String keyPrefix;
  private final Duration ttl;

  public RedisPermissionCacheAdapter(
      StringRedisTemplate redisTemplate,
      @Value("${nexus.redis.key-prefix:nexus}") String keyPrefix,
      @Value("${nexus.rbac.permission-cache-ttl-seconds:900}") long ttlSeconds) {
    this.redisTemplate = redisTemplate;
    this.keyPrefix = keyPrefix;
    this.ttl = Duration.ofSeconds(ttlSeconds);
  }

  @Override
  public Optional<ResolvedPermissions> get(UUID tenantId, UUID userId) {
    try {
      String roleKey = roleKey(tenantId, userId);
      String permKey = permKey(tenantId, userId);
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
  public void put(UUID tenantId, UUID userId, ResolvedPermissions resolved) {
    try {
      writeSet(roleKey(tenantId, userId), resolved.roles());
      writeSet(permKey(tenantId, userId), resolved.permissions());
    } catch (Exception e) {
      log.warn("RBAC_PERMISSION_CACHE_UNAVAILABLE operation=put", e);
    }
  }

  @Override
  public void evict(UUID tenantId, UUID userId) {
    try {
      redisTemplate.delete(roleKey(tenantId, userId));
      redisTemplate.delete(permKey(tenantId, userId));
    } catch (Exception e) {
      log.warn("RBAC_PERMISSION_CACHE_UNAVAILABLE operation=evict", e);
    }
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

  private String roleKey(UUID tenantId, UUID userId) {
    return keyPrefix + ":rbac:roleset:" + tenantId + ":" + userId;
  }

  private String permKey(UUID tenantId, UUID userId) {
    return keyPrefix + ":rbac:permset:" + tenantId + ":" + userId;
  }
}
