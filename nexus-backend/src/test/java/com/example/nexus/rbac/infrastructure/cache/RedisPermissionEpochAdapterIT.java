package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import com.example.nexus.rbac.application.port.out.EpochUnparseableException;
import com.example.nexus.rbac.infrastructure.cache.EpochRedisConfig.EpochTemplates;
import io.lettuce.core.resource.ClientResources;
import io.lettuce.core.resource.DefaultClientResources;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.data.redis.autoconfigure.DataRedisConnectionDetails;
import org.springframework.dao.DataAccessException;
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
 * the read template against a paused server. T-010 (design §9.4): the same script deletes each
 * bumped user's permission-cache entry under the epoch it replaces ({@code 0} when there was none),
 * and a full 500-user batch fits the bump timeout.
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
  void should_probeTrue_when_redisAnswers() {
    assertThat(adapter(templates).probe()).isTrue();
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

  @ParameterizedTest
  @ValueSource(strings = {
    "not-a-number", "abc", "9223372036854775808", "-1", "", "nan", "-nan", "inf", "-inf", "0x10",
    "+5", "1e3", " 7", "9007199254740991", "9007199254740992", "9223372036854775807",
    "00000000000000001"
  })
  void should_throwUnparseable_when_storedValueIsNotAnEpoch(String stored) {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    templates.read().opsForValue().set(key(tenantId, userId), stored);

    assertThatThrownBy(() -> adapter(templates).current(tenantId, userId))
        .isInstanceOf(EpochUnparseableException.class);
  }

  @Test
  void should_returnWrittenEpochOfEveryUser_when_bumped() {
    UUID tenantId = UUID.randomUUID();
    List<UUID> users = List.of(UUID.randomUUID(), UUID.randomUUID());
    long before = redisTimeMillis();

    Map<UUID, Long> written = adapter(templates).bump(tenantId, users);

    assertThat(written).containsOnlyKeys(users);
    for (UUID userId : users) {
      assertThat(written.get(userId))
          .isBetween(before, redisTimeMillis())
          .isEqualTo(adapter(templates).current(tenantId, userId).orElseThrow());
    }
  }

  @Test
  void should_returnOldPlusOne_when_storedEpochAheadOfRedisTime() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    long farFuture = redisTimeMillis() + 3_600_000L;
    templates.read().opsForValue().set(key(tenantId, userId), Long.toString(farFuture));

    Map<UUID, Long> written = adapter(templates).bump(tenantId, List.of(userId));

    assertThat(written).containsEntry(userId, farFuture + 1);
  }

  @Test
  void should_returnEmptyMap_when_bumpGivenNoUsers() {
    assertThat(adapter(templates).bump(UUID.randomUUID(), List.of())).isEmpty();
  }

  @Test
  void should_recoverToRedisTime_when_storedValueAboveLongRange() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    templates.read().opsForValue().set(key(tenantId, userId), "9223372036854775808");
    long before = redisTimeMillis();

    adapter(templates).bump(tenantId, List.of(userId));

    assertThat(adapter(templates).current(tenantId, userId).orElseThrow())
        .isBetween(before, redisTimeMillis());
  }

  @Test
  void should_returnStoredValue_when_epochIsCeiling() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    templates.read().opsForValue().set(
        key(tenantId, userId), Long.toString(RedisPermissionEpochAdapter.MAX_EPOCH));

    OptionalLong current = adapter(templates).current(tenantId, userId);

    assertThat(current).hasValue(RedisPermissionEpochAdapter.MAX_EPOCH);
  }

  /** L-1: a valid epoch is only ever raised, never lowered, and a corrupt one never survives. */
  @ParameterizedTest
  @ValueSource(strings = {
    "nan", "-nan", "inf", "-inf", "-1", "abc", "0x10", "1e3", "+5", "9007199254740991",
    "9007199254740992", "9007199254740993", "9223372036854775807", "9223372036854775808"
  })
  void should_replaceWithRedisTime_when_storedValueOutsideValidRange(String stored) {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    templates.read().opsForValue().set(key(tenantId, userId), stored);
    long before = redisTimeMillis();

    Map<UUID, Long> written = adapter(templates).bump(tenantId, List.of(userId));

    assertThat(written.get(userId)).isBetween(before, redisTimeMillis());
    assertThat(adapter(templates).current(tenantId, userId))
        .hasValue(written.get(userId));
  }

  @Test
  void should_neverWriteNan_when_anyCorruptValueBumpedInOneBatch() {
    UUID tenantId = UUID.randomUUID();
    List<UUID> users = List.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID());
    templates.read().opsForValue().set(key(tenantId, users.get(0)), "nan");
    templates.read().opsForValue().set(key(tenantId, users.get(1)), "inf");

    Map<UUID, Long> written = adapter(templates).bump(tenantId, users);

    assertThat(written).containsOnlyKeys(users);
    for (UUID userId : users) {
      assertThat(templates.read().opsForValue().get(key(tenantId, userId)))
          .matches("[0-9]{1,16}");
    }
  }

  @Test
  void should_incrementByOne_when_storedValueIsLargestValidBelowCeiling() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    long stored = RedisPermissionEpochAdapter.MAX_EPOCH - 1;
    templates.read().opsForValue().set(key(tenantId, userId), Long.toString(stored));

    Map<UUID, Long> written = adapter(templates).bump(tenantId, List.of(userId));

    assertThat(written).containsEntry(userId, stored + 1);
  }

  /** The Lua rule and parse() agree on a 16-digit zero-padded value: valid, read and raised. */
  @Test
  void should_readAndRaiseByOne_when_storedValueIsZeroPaddedTo16Digits() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    long ahead = redisTimeMillis() + 3_600_000L;
    templates.read().opsForValue().set(key(tenantId, userId), String.format("%016d", ahead));

    OptionalLong read = adapter(templates).current(tenantId, userId);
    Map<UUID, Long> written = adapter(templates).bump(tenantId, List.of(userId));

    assertThat(read).hasValue(ahead);
    assertThat(written).containsEntry(userId, ahead + 1);
  }

  /** A stored 0 is a valid epoch (not corrupt): read as 0, the bump writes Redis TIME. */
  @Test
  void should_readZeroAndBumpToRedisTime_when_storedValueIsZero() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    templates.read().opsForValue().set(key(tenantId, userId), "0");
    long before = redisTimeMillis();

    OptionalLong read = adapter(templates).current(tenantId, userId);
    Map<UUID, Long> written = adapter(templates).bump(tenantId, List.of(userId));

    assertThat(read).hasValue(0L);
    assertThat(written.get(userId)).isBetween(before, redisTimeMillis());
  }

  @Test
  void should_neverLowerOrExceedCeiling_when_storedValueIsCeiling() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    templates.read().opsForValue().set(
        key(tenantId, userId), Long.toString(RedisPermissionEpochAdapter.MAX_EPOCH));

    Map<UUID, Long> written = adapter(templates).bump(tenantId, List.of(userId));

    assertThat(written).containsEntry(userId, RedisPermissionEpochAdapter.MAX_EPOCH);
    assertThat(adapter(templates).current(tenantId, userId))
        .hasValue(RedisPermissionEpochAdapter.MAX_EPOCH);
  }

  @Test
  void should_acceptMixedValidAndCorruptUsers_when_resultParsedPerUser() {
    UUID tenantId = UUID.randomUUID();
    UUID valid = UUID.randomUUID();
    UUID corrupt = UUID.randomUUID();
    long stored = redisTimeMillis() + 3_600_000L;
    templates.read().opsForValue().set(key(tenantId, valid), Long.toString(stored));
    templates.read().opsForValue().set(key(tenantId, corrupt), "nan");

    Map<UUID, Long> written = adapter(templates).bump(tenantId, List.of(corrupt, valid));

    assertThat(written).containsEntry(valid, stored + 1);
    assertThat(written.get(corrupt)).isPositive();
  }

  @Test
  void should_recoverToRedisTime_when_unparseableValueBumped() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    templates.read().opsForValue().set(key(tenantId, userId), "not-a-number");
    long before = redisTimeMillis();

    adapter(templates).bump(tenantId, List.of(userId));

    assertThat(adapter(templates).current(tenantId, userId).orElseThrow())
        .isGreaterThanOrEqualTo(before);
  }

  @Test
  void should_refreshTtl_when_bumpedAgain() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    adapter(templates).bump(tenantId, List.of(userId));
    templates.read().expire(key(tenantId, userId), Duration.ofSeconds(10));

    adapter(templates).bump(tenantId, List.of(userId));

    assertThat(templates.read().getExpire(key(tenantId, userId)))
        .isBetween(KEY_TTL_SECONDS - 5, KEY_TTL_SECONDS);
  }

  @Test
  void should_createNoKey_when_bumpGivenNoUsers() {
    UUID tenantId = UUID.randomUUID();

    adapter(templates).bump(tenantId, List.of());

    assertThat(templates.read().keys(KEY_PREFIX + ":rbac:epoch:" + tenantId + ":*")).isEmpty();
  }

  @Test
  void should_loseNoIncrement_when_bumpedConcurrently() throws Exception {
    int threads = 8;
    int bumpsPerThread = 5;
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    // Far ahead of Redis time, so every bump is old + 1 and a lost update shows as a short total.
    long start = redisTimeMillis() + 3_600_000L;
    templates.read().opsForValue().set(key(tenantId, userId), Long.toString(start));
    RedisPermissionEpochAdapter adapter = adapter(templates);
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      CountDownLatch go = new CountDownLatch(1);
      List<Future<?>> bumps = new ArrayList<>();
      for (int t = 0; t < threads; t++) {
        bumps.add(pool.submit(() -> {
          go.await();
          for (int i = 0; i < bumpsPerThread; i++) {
            adapter.bump(tenantId, List.of(userId));
          }
          return null;
        }));
      }

      go.countDown();
      for (Future<?> bump : bumps) {
        bump.get(10, TimeUnit.SECONDS);
      }

      assertThat(adapter.current(tenantId, userId)).hasValue(start + (long) threads * bumpsPerThread);
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void should_throwDataAccessExceptionWithoutHanging_when_bumpAgainstPausedRedis() {
    try (GenericContainer<?> paused = new GenericContainer<>(REDIS_IMAGE).withExposedPorts(6379)) {
      paused.start();
      EpochTemplates pausedTemplates = templatesFor(paused);
      awaitReady(pausedTemplates);
      try {
        RedisPermissionEpochAdapter adapter = adapter(pausedTemplates);
        paused.getDockerClient().pauseContainerCmd(paused.getContainerId()).exec();
        try {
          // The bound is 500 ms; the 5 s ceiling only turns an unbounded wait into a failure.
          assertThatThrownBy(() -> assertTimeoutPreemptively(Duration.ofSeconds(5),
              () -> adapter.bump(UUID.randomUUID(), List.of(UUID.randomUUID()))))
              .isInstanceOf(DataAccessException.class);
        } finally {
          paused.getDockerClient().unpauseContainerCmd(paused.getContainerId()).exec();
        }
      } finally {
        pausedTemplates.destroy();
      }
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

  // ── US-018 T-010: the bump deletes the cache entry under the replaced epoch ──

  @Test
  void should_deleteCacheEntryUnderOldEpoch_when_bumped() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    RedisPermissionEpochAdapter adapter = adapter(templates);
    adapter.bump(tenantId, List.of(userId));
    long old = adapter.current(tenantId, userId).orElseThrow();
    writeCacheEntry(tenantId, userId, old);

    adapter.bump(tenantId, List.of(userId));

    assertThat(templates.read().hasKey(cacheKey("roleset", tenantId, userId, old))).isFalse();
    assertThat(templates.read().hasKey(cacheKey("permset", tenantId, userId, old))).isFalse();
    assertThat(adapter.current(tenantId, userId).orElseThrow()).isGreaterThan(old);
  }

  @Test
  void should_deleteCacheEntryUnderEpochZero_when_firstBump() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    writeCacheEntry(tenantId, userId, 0L);

    adapter(templates).bump(tenantId, List.of(userId));

    assertThat(templates.read().hasKey(cacheKey("roleset", tenantId, userId, 0L))).isFalse();
    assertThat(templates.read().hasKey(cacheKey("permset", tenantId, userId, 0L))).isFalse();
  }

  @Test
  void should_leaveEntriesOfUnbumpedUsers_when_batchBumped() {
    UUID tenantId = UUID.randomUUID();
    List<UUID> bumped = List.of(UUID.randomUUID(), UUID.randomUUID());
    UUID bystander = UUID.randomUUID();
    bumped.forEach(userId -> writeCacheEntry(tenantId, userId, 0L));
    writeCacheEntry(tenantId, bystander, 0L);

    adapter(templates).bump(tenantId, bumped);

    assertThat(bumped).allSatisfy(userId -> assertThat(
        templates.read().hasKey(cacheKey("permset", tenantId, userId, 0L))).isFalse());
    assertThat(templates.read().hasKey(cacheKey("roleset", tenantId, bystander, 0L))).isTrue();
    assertThat(templates.read().hasKey(cacheKey("permset", tenantId, bystander, 0L))).isTrue();
    assertThat(templates.read().hasKey(key(tenantId, bystander))).isFalse();
  }

  /**
   * The script formats the old epoch itself (%.0f); at 16 digits a wrong format (exponent form)
   * would make the DEL miss the key Java built with Long.toString.
   */
  @Test
  void should_deleteCacheEntryUnderSixteenDigitEpoch_when_bumped() {
    UUID tenantId = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    long old = RedisPermissionEpochAdapter.MAX_EPOCH - 1;
    templates.read().opsForValue().set(key(tenantId, userId), Long.toString(old));
    writeCacheEntry(tenantId, userId, old);

    adapter(templates).bump(tenantId, List.of(userId));

    assertThat(templates.read().hasKey(cacheKey("roleset", tenantId, userId, old))).isFalse();
    assertThat(templates.read().hasKey(cacheKey("permset", tenantId, userId, old))).isFalse();
  }

  /** Tenant isolation of the script: the same user id bumped in tenant A touches nothing of B. */
  @Test
  void should_leaveOtherTenantsEpochAndCacheEntry_when_sameUserIdBumped() {
    UUID tenantA = UUID.randomUUID();
    UUID tenantB = UUID.randomUUID();
    UUID userId = UUID.randomUUID();
    writeCacheEntry(tenantA, userId, 0L);
    writeCacheEntry(tenantB, userId, 0L);

    adapter(templates).bump(tenantA, List.of(userId));

    assertThat(templates.read().hasKey(cacheKey("permset", tenantA, userId, 0L))).isFalse();
    assertThat(templates.read().hasKey(cacheKey("permset", tenantB, userId, 0L))).isTrue();
    assertThat(templates.read().hasKey(cacheKey("roleset", tenantB, userId, 0L))).isTrue();
    assertThat(templates.read().hasKey(key(tenantB, userId))).isFalse();
  }

  @Test
  void should_bump500UsersWithinBumpTimeout_when_fullBatch() {
    UUID tenantId = UUID.randomUUID();
    List<UUID> users = new ArrayList<>();
    for (int i = 0; i < 500; i++) {
      UUID userId = UUID.randomUUID();
      users.add(userId);
      writeCacheEntry(tenantId, userId, 0L);
    }
    RedisPermissionEpochAdapter adapter = adapter(templates);

    // The bump template's 500 ms command timeout would throw if one full batch exceeded it.
    adapter.bump(tenantId, users);

    assertThat(users).allSatisfy(userId -> {
      assertThat(adapter.current(tenantId, userId).orElseThrow()).isPositive();
      assertThat(templates.read().hasKey(cacheKey("permset", tenantId, userId, 0L))).isFalse();
    });
  }

  private static void writeCacheEntry(UUID tenantId, UUID userId, long epoch) {
    templates.bump().opsForSet().add(cacheKey("roleset", tenantId, userId, epoch), "MEMBER");
    templates.bump().opsForSet().add(cacheKey("permset", tenantId, userId, epoch), "user:read");
  }

  private static String cacheKey(String set, UUID tenantId, UUID userId, long epoch) {
    return KEY_PREFIX + ":rbac:" + set + ":" + tenantId + ":" + userId + ":" + epoch;
  }
}
