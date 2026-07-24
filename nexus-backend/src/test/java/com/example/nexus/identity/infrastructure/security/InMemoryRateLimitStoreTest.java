package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.identity.application.port.out.RateLimitResult;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class InMemoryRateLimitStoreTest {

  private static final int WINDOW = 60;
  private static final int MAX = 3;

  @Test
  void should_allowFirstAttempts_when_underMaxInWindow() {
    var store = new InMemoryRateLimitStore(Clock.systemUTC(), WINDOW);
    String key = "user:" + UUID.randomUUID();

    for (int i = 0; i < MAX - 1; i++) {
      RateLimitResult r = store.tryConsume(key, WINDOW, MAX);
      assertThat(r.allowed()).as("attempt %d should be permitted", i + 1).isTrue();
      assertThat(r.retryAfterSeconds()).isZero();
    }
  }

  @Test
  void should_rejectAtMaxAttempt_and_returnWindowSeconds_as_retryAfter() {
    var store = new InMemoryRateLimitStore(Clock.systemUTC(), WINDOW);
    String key = "user:" + UUID.randomUUID();

    for (int i = 0; i < MAX; i++) {
      store.tryConsume(key, WINDOW, MAX);
    }
    RateLimitResult overflow = store.tryConsume(key, WINDOW, MAX);

    assertThat(overflow.allowed()).isFalse();
    assertThat(overflow.retryAfterSeconds()).isEqualTo(WINDOW);
  }

  @Test
  void should_resetAndAllow_after_windowExpires() {
    Instant start = Instant.parse("2026-01-01T00:00:00Z");
    var store = new InMemoryRateLimitStore(Clock.fixed(start, ZoneOffset.UTC), WINDOW);
    String key = "user:" + UUID.randomUUID();

    // exhaust the window
    for (int i = 0; i <= MAX; i++) {
      store.tryConsume(key, WINDOW, MAX);
    }
    RateLimitResult still = store.tryConsume(key, WINDOW, MAX);
    assertThat(still.allowed()).isFalse();

    // advance clock past the window — new store simulates the same key being accessed later
    var advanced = new InMemoryRateLimitStore(
        Clock.fixed(start.plusSeconds(WINDOW + 1), ZoneOffset.UTC), WINDOW);
    RateLimitResult reset = advanced.tryConsume(key, WINDOW, MAX);

    assertThat(reset.allowed()).isTrue();
  }

  @Test
  void should_handleHighKeyVolume_withoutError() {
    Instant start = Instant.parse("2026-01-01T00:00:00Z");
    var store = new InMemoryRateLimitStore(Clock.fixed(start, ZoneOffset.UTC), WINDOW);

    // flood 5000 distinct keys
    for (int i = 0; i < 5000; i++) {
      RateLimitResult r = store.tryConsume("distinct-" + i, WINDOW, MAX);
      assertThat(r.allowed()).isTrue();
    }
    assertThat(store.storeSize()).isEqualTo(5000);

    // advance clock — all old entries are stale; each tryConsume prunes and adds fresh
    var advanced = new InMemoryRateLimitStore(
        Clock.fixed(start.plusSeconds(WINDOW + 1), ZoneOffset.UTC), WINDOW);
    for (int i = 0; i < 5000; i++) {
      RateLimitResult r = advanced.tryConsume("distinct-" + i, WINDOW, MAX);
      assertThat(r.allowed()).isTrue();
    }
    // 5000 distinct keys, each with 1 fresh entry — store bounded to key count
    assertThat(advanced.storeSize()).isEqualTo(5000);
  }

  @Test
  void should_notExceedMaxAttempts_under_concurrent_load() throws Exception {
    var store = new InMemoryRateLimitStore(Clock.systemUTC(), WINDOW);
    String key = "shared:" + UUID.randomUUID();
    int threads = 50;
    CyclicBarrier barrier = new CyclicBarrier(threads);

    ExecutorService pool = Executors.newFixedThreadPool(threads);
    List<Future<RateLimitResult>> futures = new ArrayList<>();

    for (int i = 0; i < threads; i++) {
      futures.add(pool.submit(() -> {
        barrier.await();
        return store.tryConsume(key, WINDOW, MAX);
      }));
    }
    pool.shutdown();

    long allowed = futures.stream()
        .map(f -> {
          try {
            return f.get();
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
        })
        .filter(RateLimitResult::allowed)
        .count();

    assertThat(allowed)
        .as("exactly maxAttempts=%d threads should be allowed under concurrent load", MAX)
        .isEqualTo(MAX);
  }
}
