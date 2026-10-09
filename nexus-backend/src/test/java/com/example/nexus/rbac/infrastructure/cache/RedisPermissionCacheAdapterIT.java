package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.rbac.domain.ResolvedPermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Integration tests for {@link RedisPermissionCacheAdapter} against a real Redis instance,
 * mirroring {@code RedisRateLimitStoreIT}'s container setup and fail-open coverage. Since US-018
 * T-010 every entry is keyed by the permission epoch it was computed under (Decision 17), and
 * eviction runs a script that deletes the entry under the user's current epoch; the raw-key
 * assertions below pin that shape independently of the adapter's own get/put.
 */
@Testcontainers
@Tag("IT")
class RedisPermissionCacheAdapterIT {

  private static final String KEY_PREFIX = "nexus-test";
  private static final long TTL_SECONDS = 900L;
  private static final long EPOCH = 42L;

  @Container
  private static final GenericContainer<?> REDIS =
      new GenericContainer<>(DockerImageName.parse("redis:7.4-alpine")).withExposedPorts(6379);

  private static LettuceConnectionFactory connectionFactory;
  private static StringRedisTemplate redisTemplate;

  @BeforeAll
  static void setUpRedis() {
    connectionFactory = new LettuceConnectionFactory(REDIS.getHost(), REDIS.getMappedPort(6379));
    connectionFactory.afterPropertiesSet();
    redisTemplate = new StringRedisTemplate(connectionFactory);
    redisTemplate.afterPropertiesSet();
  }

  @AfterAll
  static void tearDownRedis() {
    connectionFactory.destroy();
  }

  private RedisPermissionCacheAdapter newAdapter() {
    return new RedisPermissionCacheAdapter(redisTemplate, KEY_PREFIX, TTL_SECONDS);
  }

  @Test
  void should_returnEmpty_when_cacheMiss() {
    var adapter = newAdapter();

    Optional<ResolvedPermissions> result =
        adapter.get(UUID.randomUUID(), UUID.randomUUID(), EPOCH);

    assertThat(result).isEmpty();
  }

  @Test
  void should_returnCachedRolesAndPermissions_when_warmed() {
    var adapter = newAdapter();
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();

    adapter.put(tenantId, userId, EPOCH,
        new ResolvedPermissions(List.of("TENANT_ADMIN"), List.of("tenant:read", "tenant:write")));
    Optional<ResolvedPermissions> result = adapter.get(tenantId, userId, EPOCH);

    assertThat(result).isPresent();
    assertThat(result.get().roles()).containsExactly("TENANT_ADMIN");
    assertThat(result.get().permissions()).containsExactlyInAnyOrder("tenant:read", "tenant:write");
  }

  @Test
  void should_returnCachedEmptyResult_when_userHasNoRolesOrPermissions_ratherThanCacheMiss() {
    var adapter = newAdapter();
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();

    adapter.put(tenantId, userId, EPOCH, ResolvedPermissions.empty());
    Optional<ResolvedPermissions> result = adapter.get(tenantId, userId, EPOCH);

    assertThat(result).contains(ResolvedPermissions.empty());
  }

  @Test
  void should_removeEntry_when_evicted() {
    var adapter = newAdapter();
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    adapter.put(
        tenantId, userId, 0L, new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));

    adapter.evict(tenantId, userId);

    assertThat(adapter.get(tenantId, userId, 0L)).isEmpty();
  }

  @Test
  void should_isolateDistinctTenantsAndUsers() {
    var adapter = newAdapter();
    UUID tenantA = UUID.randomUUID();
    UUID tenantB = UUID.randomUUID();
    UUID userId = UUID.randomUUID();

    adapter.put(tenantA, userId, EPOCH, new ResolvedPermissions(List.of(), List.of("tenant:read")));
    adapter.put(tenantB, userId, EPOCH, new ResolvedPermissions(List.of(), List.of("tenant:write")));

    assertThat(adapter.get(tenantA, userId, EPOCH).orElseThrow().permissions())
        .containsExactly("tenant:read");
    assertThat(adapter.get(tenantB, userId, EPOCH).orElseThrow().permissions())
        .containsExactly("tenant:write");
  }

  @Test
  void should_failOpen_when_redisUnavailable() {
    LettuceConnectionFactory brokenFactory = new LettuceConnectionFactory("localhost", 1);
    brokenFactory.afterPropertiesSet();
    StringRedisTemplate brokenTemplate = new StringRedisTemplate(brokenFactory);
    brokenTemplate.afterPropertiesSet();
    var adapter = new RedisPermissionCacheAdapter(brokenTemplate, KEY_PREFIX, TTL_SECONDS);

    try {
      Optional<ResolvedPermissions> result =
          adapter.get(UUID.randomUUID(), UUID.randomUUID(), EPOCH);
      assertThat(result).as("must fail open per ADR 0016 D4/§7").isEmpty();

      // put()/evict() must also swallow the error rather than propagate
      adapter.put(UUID.randomUUID(), UUID.randomUUID(), EPOCH,
          new ResolvedPermissions(List.of(), List.of("tenant:read")));
      adapter.evict(UUID.randomUUID(), UUID.randomUUID());
      adapter.evict(UUID.randomUUID(), List.of(UUID.randomUUID(), UUID.randomUUID()));
    } finally {
      brokenFactory.destroy();
    }
  }

  // ── US-018 T-010: epoch-keyed entries and eviction under the current epoch ──

  @Test
  void should_storeEntryUnderEpochKeys_when_put() {
    var adapter = newAdapter();
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();

    adapter.put(tenantId, userId, EPOCH,
        new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));

    assertThat(redisTemplate.opsForSet().members(roleKey(tenantId, userId, EPOCH)))
        .containsExactly("MEMBER");
    assertThat(redisTemplate.opsForSet().members(permKey(tenantId, userId, EPOCH)))
        .containsExactly("user:read");
    assertThat(redisTemplate.getExpire(permKey(tenantId, userId, EPOCH)))
        .isBetween(TTL_SECONDS - 5, TTL_SECONDS);
    assertThat(adapter.get(tenantId, userId, EPOCH + 1))
        .as("the same user under another epoch is a miss")
        .isEmpty();
  }

  @Test
  void should_evictEntryUnderCurrentEpoch_when_evict() {
    var adapter = newAdapter();
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    redisTemplate.opsForValue().set(epochKey(tenantId, userId), Long.toString(EPOCH));
    adapter.put(tenantId, userId, EPOCH,
        new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));

    adapter.evict(tenantId, userId);

    assertThat(redisTemplate.hasKey(roleKey(tenantId, userId, EPOCH))).isFalse();
    assertThat(redisTemplate.hasKey(permKey(tenantId, userId, EPOCH))).isFalse();
    assertThat(redisTemplate.opsForValue().get(epochKey(tenantId, userId)))
        .as("eviction never changes the epoch")
        .isEqualTo(Long.toString(EPOCH));
  }

  @Test
  void should_evictEntryUnderEpochZero_when_noEpochKey() {
    var adapter = newAdapter();
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    adapter.put(tenantId, userId, 0L,
        new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));

    adapter.evict(tenantId, List.of(userId));

    assertThat(redisTemplate.hasKey(roleKey(tenantId, userId, 0L))).isFalse();
    assertThat(redisTemplate.hasKey(permKey(tenantId, userId, 0L))).isFalse();
    assertThat(redisTemplate.hasKey(epochKey(tenantId, userId)))
        .as("eviction never creates an epoch key")
        .isFalse();
  }

  @Test
  void should_leaveOtherTenantsEntry_when_evictingSameUserIdInOneTenant() {
    var adapter = newAdapter();
    UUID tenantA = UUID.randomUUID();
    UUID tenantB = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    ResolvedPermissions entry = new ResolvedPermissions(List.of("MEMBER"), List.of("user:read"));
    adapter.put(tenantA, userId, 0L, entry);
    adapter.put(tenantB, userId, 0L, entry);

    adapter.evict(tenantA, List.of(userId));

    assertThat(adapter.get(tenantA, userId, 0L)).isEmpty();
    assertThat(adapter.get(tenantB, userId, 0L)).contains(entry);
  }

  @Test
  void should_leaveOtherUsersEntries_when_evictingOneUser() {
    var adapter = newAdapter();
    UUID tenantId = UUID.randomUUID();
    UUID evicted = UUID.randomUUID();
    UUID bystander = UUID.randomUUID();
    ResolvedPermissions entry = new ResolvedPermissions(List.of("MEMBER"), List.of("user:read"));
    adapter.put(tenantId, evicted, 0L, entry);
    adapter.put(tenantId, bystander, 0L, entry);

    adapter.evict(tenantId, evicted);

    assertThat(adapter.get(tenantId, evicted, 0L)).isEmpty();
    assertThat(adapter.get(tenantId, bystander, 0L)).contains(entry);
  }

  @Test
  void should_evictEveryHolder_when_evictingMoreThanOneBatch() {
    var adapter = newAdapter();
    UUID tenantId = UUID.randomUUID();
    List<UUID> holders = new ArrayList<>();
    ResolvedPermissions entry = new ResolvedPermissions(List.of("MEMBER"), List.of("user:read"));
    for (int i = 0; i < 501; i++) {
      UUID holder = UUID.randomUUID();
      holders.add(holder);
      adapter.put(tenantId, holder, 0L, entry);
    }

    adapter.evict(tenantId, holders);

    assertThat(holders)
        .allSatisfy(holder -> assertThat(redisTemplate.hasKey(permKey(tenantId, holder, 0L)))
            .isFalse());
  }

  private static String roleKey(UUID tenantId, UUID userId, long epoch) {
    return KEY_PREFIX + ":rbac:roleset:" + tenantId + ":" + userId + ":" + epoch;
  }

  private static String permKey(UUID tenantId, UUID userId, long epoch) {
    return KEY_PREFIX + ":rbac:permset:" + tenantId + ":" + userId + ":" + epoch;
  }

  private static String epochKey(UUID tenantId, UUID userId) {
    return KEY_PREFIX + ":rbac:epoch:" + tenantId + ":" + userId;
  }
}
