package com.example.nexus.identity.infrastructure.security;

import com.example.nexus.identity.application.port.out.RateLimitResult;
import com.example.nexus.identity.application.port.out.RateLimitStore;
import com.example.nexus.rbac.application.port.out.RoleChangeThrottlePort;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * {@code identity.infrastructure} implementation of the {@code rbac}-declared {@link
 * RoleChangeThrottlePort} (03-design.md §4.8, D14/RC-10). Delegates the actual counting to the
 * shipped {@link RateLimitStore}, keeping the dependency direction {@code identity -> rbac} —
 * the same arrangement already established for {@code RbacAuditPort} and {@code
 * UserDirectoryPort} — so {@code HexagonalArchitectureTest.rbac_must_not_depend_on_identity}
 * stays green.
 *
 * <p><b>A-2 — why this adapter owns its own "throttled-until" map.</b> {@link RateLimitStore}
 * exposes only {@link RateLimitStore#tryConsume}, a consume-and-report operation with no
 * non-destructive read. {@link #isThrottled} is specified as a pure query, so implementing it as
 * a {@code tryConsume} call would consume a slot on <b>every</b> role-change request rather than
 * only on denials, corrupting the count. Instead: {@link #recordDenial} calls {@code tryConsume};
 * when the store reports the bound crossed, this adapter records {@code now + retryAfterSeconds}
 * for that key in a local map. {@link #isThrottled} only ever compares {@code now} against that
 * map — it <b>never</b> calls {@code tryConsume}. {@link RateLimitStore} and both its
 * implementations are unchanged by this story.
 *
 * <p><b>Per-JVM caveat (A-2).</b> Only the <i>counting</i> in {@link #recordDenial} delegates to
 * {@link RateLimitStore}, which may be Redis-backed via {@code
 * nexus.security.rate-limit.store-type=redis}. The throttled-until transition map above is local
 * to this adapter instance. Consequently the throttle does <b>not</b> become cluster-wide under
 * the Redis-backed store: each replica tracks its own transition state, even though the
 * underlying denial count is shared. This is accepted collateral (RES-11), not a defect.
 *
 * <p>Bounded map: evicted on read (an expired entry is removed the moment {@link #isThrottled}
 * observes it) and by a periodic background sweep for keys that are never read again, following
 * {@link InMemoryRateLimitStore}'s own eviction pattern.
 *
 * <p>Both methods MUST fail safe and MUST NEVER throw: any exception from the store, the clock or
 * the map is swallowed and treated as "not throttled" — the throttle bounds cost, it is not an
 * authorization control, and an unavailable throttle must never block the gate's own authoritative
 * decision.
 *
 * <p>Deliberately a plain {@code @Component}, not gated by {@code @ConditionalOnProperty}: unlike
 * {@link InMemoryRateLimitStore}/{@code RedisRateLimitStore} (interchangeable alternatives), this
 * is the single implementation of an {@code rbac} port; a missing bean would break construction of
 * any consumer of {@link RoleChangeThrottlePort}.
 */
@Component
public class RateLimitRoleChangeThrottleAdapter implements RoleChangeThrottlePort {

  private static final Logger log = LoggerFactory.getLogger(RateLimitRoleChangeThrottleAdapter.class);
  private static final String KEY_PREFIX = "RBAC_DENY:";

  private final ConcurrentHashMap<String, Instant> throttledUntil = new ConcurrentHashMap<>();
  private final RateLimitStore rateLimitStore;
  private final Clock clock;
  private final int maxDenials;
  private final int windowSeconds;

  // Created lazily in @PostConstruct so unit tests that construct directly get no background thread.
  private ScheduledExecutorService evictionScheduler;

  public RateLimitRoleChangeThrottleAdapter(
      RateLimitStore rateLimitStore,
      Clock clock,
      @Value("${nexus.rbac.denial-throttle.max-denials}") int maxDenials,
      @Value("${nexus.rbac.denial-throttle.window-seconds}") int windowSeconds) {
    this.rateLimitStore = rateLimitStore;
    this.clock = clock;
    this.maxDenials = maxDenials;
    this.windowSeconds = windowSeconds;
  }

  @PostConstruct
  void startEviction() {
    evictionScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread t = new Thread(r, "rbac-throttle-evict");
      t.setDaemon(true);
      return t;
    });
    evictionScheduler.scheduleAtFixedRate(
        this::sweepExpiredEntries, windowSeconds, windowSeconds, TimeUnit.SECONDS);
  }

  @PreDestroy
  void stopEviction() {
    if (evictionScheduler != null) {
      evictionScheduler.shutdownNow();
    }
  }

  @Override
  public boolean isThrottled(UUID tenantId, UUID actorUserId) {
    try {
      String key = key(tenantId, actorUserId);
      Instant now = clock.instant();
      boolean[] throttled = {false};
      throttledUntil.computeIfPresent(key, (k, until) -> {
        if (now.isBefore(until)) {
          throttled[0] = true;
          return until;
        }
        return null; // window has passed - evict on read
      });
      return throttled[0];
    } catch (RuntimeException e) {
      log.warn("rbac denial-throttle isThrottled check failed, failing safe (not throttled)", e);
      return false;
    }
  }

  @Override
  public boolean recordDenial(UUID tenantId, UUID actorUserId) {
    try {
      String key = key(tenantId, actorUserId);
      RateLimitResult result = rateLimitStore.tryConsume(key, windowSeconds, maxDenials);
      if (result.allowed()) {
        return false;
      }

      Instant now = clock.instant();
      Instant newUntil = now.plusSeconds(result.retryAfterSeconds());
      boolean[] isTransition = {false};
      throttledUntil.compute(key, (k, existingUntil) -> {
        boolean alreadyThrottled = existingUntil != null && now.isBefore(existingUntil);
        isTransition[0] = !alreadyThrottled;
        return newUntil;
      });
      return isTransition[0];
    } catch (RuntimeException e) {
      log.warn("rbac denial-throttle recordDenial failed, failing safe (not throttled)", e);
      return false;
    }
  }

  /** Removes every throttled-until entry whose window has already passed. */
  private void sweepExpiredEntries() {
    Instant now = clock.instant();
    throttledUntil.forEach((key, until) ->
        throttledUntil.computeIfPresent(key, (k, u) -> u.isAfter(now) ? u : null));
  }

  private static String key(UUID tenantId, UUID actorUserId) {
    return KEY_PREFIX + tenantId + ":" + actorUserId;
  }

  /** Returns the number of tracked throttled-until entries. Package-visible for testing only. */
  int mapSize() {
    return throttledUntil.size();
  }
}
