package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.identity.application.port.out.RateLimitResult;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Integration tests for {@link RedisRateLimitStore} against a real Redis instance (ADR 0016),
 * mirroring {@link InMemoryRateLimitStoreTest}'s coverage so behavioral parity between the two
 * {@code RateLimitStore} adapters is verified — same sliding-window-log semantics, same
 * Retry-After contract, same atomicity guarantee under concurrent load.
 */
@Testcontainers
class RedisRateLimitStoreIT {

  private static final int WINDOW = 60;
  private static final int MAX = 3;
  private static final String KEY_PREFIX = "nexus-test";

  @Container
  private static final GenericContainer<?> REDIS =
      new GenericContainer<>(DockerImageName.parse("redis:7.4-alpine")).withExposedPorts(6379);

  private static LettuceConnectionFactory connectionFactory;
  private static StringRedisTemplate redisTemplate;

  @BeforeAll
  static void setUpRedis() {
    connectionFactory =
        new LettuceConnectionFactory(REDIS.getHost(), REDIS.getMappedPort(6379));
    connectionFactory.afterPropertiesSet();
    redisTemplate = new StringRedisTemplate(connectionFactory);
    redisTemplate.afterPropertiesSet();
  }

  @AfterAll
  static void tearDownRedis() {
    connectionFactory.destroy();
  }

  private RedisRateLimitStore newStore() {
    return new RedisRateLimitStore(redisTemplate, Clock.systemUTC(), KEY_PREFIX);
  }

  @Test
  void should_allowFirstAttempts_when_underMaxInWindow() {
    var store = newStore();
    String key = "user:" + UUID.randomUUID();

    for (int i = 0; i < MAX - 1; i++) {
      RateLimitResult r = store.tryConsume(key, WINDOW, MAX);
      assertThat(r.allowed()).as("attempt %d should be permitted", i + 1).isTrue();
      assertThat(r.retryAfterSeconds()).isZero();
    }
  }

  @Test
  void should_rejectAtMaxAttempt_and_returnPositiveRetryAfter() {
    var store = newStore();
    String key = "user:" + UUID.randomUUID();

    for (int i = 0; i < MAX; i++) {
      store.tryConsume(key, WINDOW, MAX);
    }
    RateLimitResult overflow = store.tryConsume(key, WINDOW, MAX);

    assertThat(overflow.allowed()).isFalse();
    assertThat(overflow.retryAfterSeconds()).isGreaterThan(0).isLessThanOrEqualTo(WINDOW);
  }

  @Test
  void should_isolate_distinct_keys() {
    var store = newStore();
    String keyA = "user:" + UUID.randomUUID();
    String keyB = "user:" + UUID.randomUUID();

    for (int i = 0; i < MAX; i++) {
      store.tryConsume(keyA, WINDOW, MAX);
    }
    RateLimitResult blockedA = store.tryConsume(keyA, WINDOW, MAX);
    RateLimitResult freshB = store.tryConsume(keyB, WINDOW, MAX);

    assertThat(blockedA.allowed()).isFalse();
    assertThat(freshB.allowed()).as("distinct key must have an independent counter").isTrue();
  }

  @Test
  void should_notExceedMaxAttempts_under_concurrent_load() throws Exception {
    var store = newStore();
    String key = "shared:" + UUID.randomUUID();
    int threads = 50;
    CyclicBarrier barrier = new CyclicBarrier(threads);

    ExecutorService pool = Executors.newFixedThreadPool(threads);
    List<Future<RateLimitResult>> futures = new ArrayList<>();

    for (int i = 0; i < threads; i++) {
      futures.add(
          pool.submit(
              () -> {
                barrier.await();
                return store.tryConsume(key, WINDOW, MAX);
              }));
    }
    pool.shutdown();

    long allowed =
        futures.stream()
            .map(
                f -> {
                  try {
                    return f.get();
                  } catch (Exception e) {
                    throw new RuntimeException(e);
                  }
                })
            .filter(RateLimitResult::allowed)
            .count();

    assertThat(allowed)
        .as(
            "exactly maxAttempts=%d threads should be allowed under concurrent load"
                + " (Lua-script atomicity)",
            MAX)
        .isEqualTo(MAX);
  }

  @Test
  void should_failOpen_when_redisUnavailable() {
    // Loopback port with nothing listening — connection is refused immediately, simulating an
    // unreachable Redis instance without slow timeout behavior in the test.
    LettuceConnectionFactory brokenFactory = new LettuceConnectionFactory("localhost", 1);
    brokenFactory.afterPropertiesSet();
    StringRedisTemplate brokenTemplate = new StringRedisTemplate(brokenFactory);
    brokenTemplate.afterPropertiesSet();
    var store = new RedisRateLimitStore(brokenTemplate, Clock.systemUTC(), KEY_PREFIX);

    try {
      RateLimitResult result = store.tryConsume("down:" + UUID.randomUUID(), WINDOW, MAX);
      assertThat(result.allowed()).as("must fail open per ADR 0016 D4/§7").isTrue();
    } finally {
      brokenFactory.destroy();
    }
  }
}
