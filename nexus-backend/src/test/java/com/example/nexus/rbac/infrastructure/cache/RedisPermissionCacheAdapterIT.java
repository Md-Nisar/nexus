package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.rbac.domain.ResolvedPermissions;
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
 * mirroring {@code RedisRateLimitStoreIT}'s container setup and fail-open coverage.
 */
@Testcontainers
@Tag("IT")
class RedisPermissionCacheAdapterIT {

  private static final String KEY_PREFIX = "nexus-test";
  private static final long TTL_SECONDS = 900L;

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

    Optional<ResolvedPermissions> result = adapter.get(UUID.randomUUID(), UUID.randomUUID());

    assertThat(result).isEmpty();
  }

  @Test
  void should_returnCachedRolesAndPermissions_when_warmed() {
    var adapter = newAdapter();
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();

    adapter.put(tenantId, userId,
        new ResolvedPermissions(List.of("TENANT_ADMIN"), List.of("tenant:read", "tenant:write")));
    Optional<ResolvedPermissions> result = adapter.get(tenantId, userId);

    assertThat(result).isPresent();
    assertThat(result.get().roles()).containsExactly("TENANT_ADMIN");
    assertThat(result.get().permissions()).containsExactlyInAnyOrder("tenant:read", "tenant:write");
  }

  @Test
  void should_returnCachedEmptyResult_when_userHasNoRolesOrPermissions_ratherThanCacheMiss() {
    var adapter = newAdapter();
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();

    adapter.put(tenantId, userId, ResolvedPermissions.empty());
    Optional<ResolvedPermissions> result = adapter.get(tenantId, userId);

    assertThat(result).contains(ResolvedPermissions.empty());
  }

  @Test
  void should_removeEntry_when_evicted() {
    var adapter = newAdapter();
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    adapter.put(tenantId, userId, new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));

    adapter.evict(tenantId, userId);

    assertThat(adapter.get(tenantId, userId)).isEmpty();
  }

  @Test
  void should_isolateDistinctTenantsAndUsers() {
    var adapter = newAdapter();
    UUID tenantA = UUID.randomUUID();
    UUID tenantB = UUID.randomUUID();
    UUID userId = UUID.randomUUID();

    adapter.put(tenantA, userId, new ResolvedPermissions(List.of(), List.of("tenant:read")));
    adapter.put(tenantB, userId, new ResolvedPermissions(List.of(), List.of("tenant:write")));

    assertThat(adapter.get(tenantA, userId).orElseThrow().permissions())
        .containsExactly("tenant:read");
    assertThat(adapter.get(tenantB, userId).orElseThrow().permissions())
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
      Optional<ResolvedPermissions> result = adapter.get(UUID.randomUUID(), UUID.randomUUID());
      assertThat(result).as("must fail open per ADR 0016 D4/§7").isEmpty();

      // put()/evict() must also swallow the error rather than propagate
      adapter.put(UUID.randomUUID(), UUID.randomUUID(),
          new ResolvedPermissions(List.of(), List.of("tenant:read")));
      adapter.evict(UUID.randomUUID(), UUID.randomUUID());
    } finally {
      brokenFactory.destroy();
    }
  }
}
