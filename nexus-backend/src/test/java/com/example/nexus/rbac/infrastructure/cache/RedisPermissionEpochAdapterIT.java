package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.rbac.infrastructure.cache.EpochRedisConfig.EpochTemplates;
import io.lettuce.core.resource.ClientResources;
import io.lettuce.core.resource.DefaultClientResources;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.data.redis.autoconfigure.DataRedisConnectionDetails;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Integration tests for {@link RedisPermissionEpochAdapter} against a real Redis (US-018 T-009,
 * design §9.2, §9.5): the monotonic bump script, the key TTL, the key shape, and the 50 ms bound on
 * the read template against a paused server.
 */
@Testcontainers
@Tag("IT")
class RedisPermissionEpochAdapterIT {

  private static final String KEY_PREFIX = "nexus-test";
  private static final long KEY_TTL_SECONDS = 960L;
  private static final DockerImageName REDIS_IMAGE = DockerImageName.parse("redis:7.4-alpine");

  @Container
  private static final GenericContainer<?> REDIS =
      new GenericContainer<>(REDIS_IMAGE).withExposedPorts(6379);

  private static ClientResources clientResources;
  private static EpochTemplates templates;

  @BeforeAll
  static void setUpRedis() {
    clientResources = DefaultClientResources.create();
    templates = templatesFor(REDIS);
    awaitReady(templates);
  }

  @AfterAll
  static void tearDownRedis() {
    templates.destroy();
    clientResources.shutdown();
  }

  private static EpochTemplates templatesFor(GenericContainer<?> redis) {
    DataRedisConnectionDetails details = new DataRedisConnectionDetails() {
      @Override
      public Standalone getStandalone() {
        return Standalone.of(redis.getHost(), redis.getMappedPort(6379));
      }
    };
    LettuceConnectionFactory main = new LettuceConnectionFactory(
        new RedisStandaloneConfiguration(redis.getHost(), redis.getMappedPort(6379)));
    return new EpochTemplates(
        EpochRedisConfig.dedicatedFactory(details, main, clientResources, Duration.ofMillis(50)),
        EpochRedisConfig.dedicatedFactory(details, main, clientResources, Duration.ofMillis(500)));
  }

  /** The first connection is opened off-thread, so wait for it before using the templates. */
  private static void awaitReady(EpochTemplates epochTemplates) {
    long deadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
    while (!(epochTemplates.readReady() && epochTemplates.bumpReady())) {
      if (System.nanoTime() > deadline) {
        throw new AssertionError("epoch templates not ready within 15 s");
      }
      try {
        Thread.sleep(25);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new AssertionError("interrupted while waiting for epoch templates", e);
      }
    }
  }

  private static RedisPermissionEpochAdapter adapter(EpochTemplates epochTemplates) {
    return new RedisPermissionEpochAdapter(epochTemplates, KEY_PREFIX, KEY_TTL_SECONDS);
  }

  private static String key(UUID tenantId, UUID userId) {
    return KEY_PREFIX + ":rbac:epoch:" + tenantId + ":" + userId;
  }

  private static long redisTimeMillis() {
    return templates.read()
        .execute((RedisCallback<Long>) connection -> connection.serverCommands().time());
  }

  @Test
  void should_returnZero_when_keyAbsent() {
    OptionalLong current = adapter(templates).current(UUID.randomUUID(), UUID.randomUUID());

    assertThat(current).hasValue(0L);
  }

  @Test
  void should_setRedisTimeMillis_when_firstBump() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    long before = redisTimeMillis();

    adapter(templates).bump(tenantId, List.of(userId));

    long epoch = adapter(templates).current(tenantId, userId).orElseThrow();
    assertThat(epoch).isBetween(before, redisTimeMillis());
  }

  @Test
  void should_incrementByOne_when_storedEpochAheadOfRedisTime() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    String farFuture = Long.toString(redisTimeMillis() + 3_600_000L);
    templates.read().opsForValue().set(key(tenantId, userId), farFuture);

    adapter(templates).bump(tenantId, List.of(userId));

    assertThat(adapter(templates).current(tenantId, userId))
        .hasValue(Long.parseLong(farFuture) + 1);
  }

  @Test
  void should_stayMonotonicAcrossKeyDeletion() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    RedisPermissionEpochAdapter adapter = adapter(templates);
    adapter.bump(tenantId, List.of(userId));
    long first = adapter.current(tenantId, userId).orElseThrow();
    templates.read().delete(key(tenantId, userId));
    long beforeSecond = redisTimeMillis();

    adapter.bump(tenantId, List.of(userId));

    long second = adapter.current(tenantId, userId).orElseThrow();
    assertThat(second).isGreaterThanOrEqualTo(beforeSecond).isGreaterThan(first);
  }

  @Test
  void should_setTtlToKeyTtlSeconds_when_bumped() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();

    adapter(templates).bump(tenantId, List.of(userId));

    Long ttl = templates.read().getExpire(key(tenantId, userId));
    assertThat(ttl).isBetween(KEY_TTL_SECONDS - 5, KEY_TTL_SECONDS);
  }

  @Test
  void should_useTenantScopedKeyWithConfiguredPrefix() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();

    adapter(templates).bump(tenantId, List.of(userId));

    assertThat(templates.read().hasKey(key(tenantId, userId))).isTrue();
    assertThat(adapter(templates).current(UUID.randomUUID(), userId)).hasValue(0L);
  }

  @Test
  void should_bumpEveryUser_when_collectionGiven() {
    UUID tenantId = UUID.randomUUID();
    List<UUID> users = List.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID());

    adapter(templates).bump(tenantId, users);

    for (UUID userId : users) {
      assertThat(adapter(templates).current(tenantId, userId).orElseThrow()).isPositive();
    }
  }

  @Test
  void should_returnEmptyWithinReadBound_when_containerPaused() {
    try (GenericContainer<?> paused = new GenericContainer<>(REDIS_IMAGE).withExposedPorts(6379)) {
      paused.start();
      EpochTemplates pausedTemplates = templatesFor(paused);
      awaitReady(pausedTemplates);
      try {
        RedisPermissionEpochAdapter adapter = adapter(pausedTemplates);
        UUID tenantId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        // Establish the connection first, so the measured call is a command timeout.
        assertThat(adapter.current(tenantId, userId)).hasValue(0L);
        paused.getDockerClient().pauseContainerCmd(paused.getContainerId()).exec();
        try {
          long start = System.nanoTime();

          OptionalLong current = adapter.current(tenantId, userId);

          long elapsedMs = (System.nanoTime() - start) / 1_000_000;
          assertThat(current).isEmpty();
          assertThat(elapsedMs).isLessThan(150L);
        } finally {
          paused.getDockerClient().unpauseContainerCmd(paused.getContainerId()).exec();
        }
      } finally {
        pausedTemplates.destroy();
      }
    }
  }

  @Test
  void should_neverBlockRequestThreads_when_startedAgainstPausedRedisThenRecover()
      throws Exception {
    int callers = 50;
    long readBoundMs = 50;
    try (GenericContainer<?> paused = new GenericContainer<>(REDIS_IMAGE).withExposedPorts(6379)) {
      paused.start();
      paused.getDockerClient().pauseContainerCmd(paused.getContainerId()).exec();
      boolean unpaused = false;
      EpochTemplates pausedTemplates = templatesFor(paused);
      ExecutorService callersPool = Executors.newFixedThreadPool(callers);
      try {
        RedisPermissionEpochAdapter adapter = adapter(pausedTemplates);
        UUID tenantId = UUID.randomUUID();
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Long>> latencies = new ArrayList<>();
        for (int i = 0; i < callers; i++) {
          latencies.add(callersPool.submit(() -> {
            go.await();
            long start = System.nanoTime();
            OptionalLong current = adapter.current(tenantId, UUID.randomUUID());
            long elapsedMs = (System.nanoTime() - start) / 1_000_000;
            assertThat(current).isEmpty();
            return elapsedMs;
          }));
        }

        go.countDown();
        long maxMs = 0;
        for (Future<Long> latency : latencies) {
          maxMs = Math.max(maxMs, latency.get(10, TimeUnit.SECONDS));
        }

        assertThat(maxMs).isLessThan(2 * readBoundMs);
        paused.getDockerClient().unpauseContainerCmd(paused.getContainerId()).exec();
        unpaused = true;
        awaitReady(pausedTemplates);
        assertThat(adapter.current(tenantId, UUID.randomUUID())).hasValue(0L);
      } finally {
        if (!unpaused) {
          paused.getDockerClient().unpauseContainerCmd(paused.getContainerId()).exec();
        }
        callersPool.shutdownNow();
        pausedTemplates.destroy();
      }
    }
  }
}
