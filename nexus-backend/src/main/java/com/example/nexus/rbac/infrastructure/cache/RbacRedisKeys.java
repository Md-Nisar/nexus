package com.example.nexus.rbac.infrastructure.cache;

import java.util.UUID;

/**
 * The one definition of the RBAC Redis key shapes (ADR 0016 D3, US-018 design §9.2, §9.4), shared
 * by {@link RedisPermissionEpochAdapter}, {@link RedisPermissionCacheAdapter} and their Lua
 * scripts:
 *
 * <pre>{@code
 * {keyPrefix}:rbac:epoch:{tenantId}:{userId}
 * {keyPrefix}:rbac:roleset:{tenantId}:{userId}:{epoch}
 * {keyPrefix}:rbac:permset:{tenantId}:{userId}:{epoch}
 * }</pre>
 *
 * <p>A cache entry is keyed by the epoch it was computed under (Decision 17). The scripts receive
 * the cache-key stems from {@link #rolesetStem} and {@link #permsetStem} and append the epoch they
 * read from the epoch key, formatted as an integer exactly as {@link Long#toString(long)} would,
 * so the key a script deletes is the key {@link #roleset} and {@link #permset} build.
 */
final class RbacRedisKeys {

  private final String rbacPrefix;

  /**
   * @param keyPrefix {@code nexus.redis.key-prefix}
   */
  RbacRedisKeys(String keyPrefix) {
    this.rbacPrefix = keyPrefix + ":rbac:";
  }

  /** The user's permission-epoch key. */
  String epoch(UUID tenantId, UUID userId) {
    return rbacPrefix + "epoch:" + tenantId + ":" + userId;
  }

  /** The cached role-name set computed under {@code epoch}. */
  String roleset(UUID tenantId, UUID userId, long epoch) {
    return rolesetStem(tenantId, userId) + epoch;
  }

  /** The cached permission-name set computed under {@code epoch}. */
  String permset(UUID tenantId, UUID userId, long epoch) {
    return permsetStem(tenantId, userId) + epoch;
  }

  /** {@link #roleset} without the epoch; a script appends the epoch it read. */
  String rolesetStem(UUID tenantId, UUID userId) {
    return rbacPrefix + "roleset:" + tenantId + ":" + userId + ":";
  }

  /** {@link #permset} without the epoch; a script appends the epoch it read. */
  String permsetStem(UUID tenantId, UUID userId) {
    return rbacPrefix + "permset:" + tenantId + ":" + userId + ":";
  }
}
