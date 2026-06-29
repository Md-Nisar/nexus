package com.example.nexus.identity.infrastructure.security;

import com.example.nexus.identity.application.port.out.RateLimitResult;
import com.example.nexus.identity.application.port.out.RateLimitStore;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Per-JVM sliding-window rate-limit store backed by a {@link ConcurrentHashMap}.
 *
 * <p>Thread-safety: all mutations go through a single {@link ConcurrentHashMap#compute} call per
 * key, which is atomic. No {@code synchronized} blocks required (T-6.2).
 *
 * <p>A background eviction thread runs every {@code windowSeconds} to prune entries that have
 * not been accessed since their window expired. This bounds heap growth under distributed
 * single-visit attacks (e.g. many distinct source IPs, each sending exactly one request).
 *
 * <p>Known limitation: counters are per-JVM and not shared across replicas. Multi-replica
 * deployments should switch to {@code nexus.security.rate-limit.store-type=redis} (T-6.1/T-6.3).
 */
@ConditionalOnProperty(
    name = "nexus.security.rate-limit.store-type",
    havingValue = "memory",
    matchIfMissing = true)
@Component
public class InMemoryRateLimitStore implements RateLimitStore {

  private final ConcurrentHashMap<String, Deque<Instant>> store = new ConcurrentHashMap<>();
  private final Clock clock;
  private final int evictionWindowSeconds;

  // Created lazily in @PostConstruct so unit tests that construct directly get no background thread.
  private ScheduledExecutorService evictionScheduler;

  public InMemoryRateLimitStore(
      Clock clock,
      @Value("${nexus.security.rate-limit.ip-window-seconds}") int windowSeconds) {
    this.clock = clock;
    this.evictionWindowSeconds = windowSeconds;
  }

  @PostConstruct
  void startEviction() {
    evictionScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread t = new Thread(r, "rate-limit-evict");
      t.setDaemon(true);
      return t;
    });
    evictionScheduler.scheduleAtFixedRate(
        this::evictExpiredEntries,
        evictionWindowSeconds, evictionWindowSeconds, TimeUnit.SECONDS);
  }

  @PreDestroy
  void stopEviction() {
    if (evictionScheduler != null) {
      evictionScheduler.shutdownNow();
    }
  }

  @Override
  public RateLimitResult tryConsume(String key, int windowSeconds, int maxAttempts) {
    Instant now = clock.instant();
    Instant windowStart = now.minusSeconds(windowSeconds);
    boolean[] rejected = {false};
    long[] retryAfter = {windowSeconds};

    store.compute(key, (k, deque) -> {
      if (deque == null) {
        deque = new ArrayDeque<>();
      }
      deque.removeIf(t -> t.isBefore(windowStart)); // prune expired entries
      if (deque.size() >= maxAttempts) {
        rejected[0] = true;
        // Retry-After = time until the oldest tracked request expires (not the full window).
        Instant oldest = deque.peekFirst();
        if (oldest != null) {
          retryAfter[0] = Math.max(1, oldest.getEpochSecond() + windowSeconds - now.getEpochSecond());
        }
      } else {
        deque.addLast(now);
      }
      return deque.isEmpty() ? null : deque; // evict empty deque — bounds memory (T-6.2)
    });

    return rejected[0]
        ? RateLimitResult.reject(retryAfter[0])
        : RateLimitResult.permit();
  }

  /** Removes all entries whose entire sliding window has expired. */
  private void evictExpiredEntries() {
    Instant cutoff = clock.instant().minusSeconds(evictionWindowSeconds);
    store.forEach((key, deque) ->
        store.computeIfPresent(key, (k, d) -> {
          d.removeIf(t -> t.isBefore(cutoff));
          return d.isEmpty() ? null : d;
        }));
  }

  /** Returns the number of tracked keys. Package-visible for testing only. */
  int storeSize() {
    return store.size();
  }
}
