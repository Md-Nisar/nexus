package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.application.port.out.RateLimitResult;
import com.example.nexus.identity.application.port.out.RateLimitStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class RateLimitRoleChangeThrottleAdapterTest {

  private static final int MAX_DENIALS = 3;
  private static final int WINDOW_SECONDS = 60;
  private static final UUID TENANT_ID = UUID.randomUUID();
  private static final UUID ACTOR_USER_ID = UUID.randomUUID();
  private static final String EXPECTED_KEY = "RBAC_DENY:" + TENANT_ID + ":" + ACTOR_USER_ID;

  private RateLimitStore rateLimitStore;
  private MutableClock clock;
  private RateLimitRoleChangeThrottleAdapter adapter;

  @BeforeEach
  void setUp() {
    rateLimitStore = mock(RateLimitStore.class);
    clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
    adapter = new RateLimitRoleChangeThrottleAdapter(rateLimitStore, clock, MAX_DENIALS, WINDOW_SECONDS);
  }

  @Test
  void should_returnFalse_when_actorHasNoDenials() {
    assertThat(adapter.isThrottled(TENANT_ID, ACTOR_USER_ID)).isFalse();
    verify(rateLimitStore, never()).tryConsume(any(), anyInt(), anyInt());
  }

  @Test
  void should_returnTrue_when_recordDenialCalledAfterMaxDenialsExhausted() {
    // Matches InMemoryRateLimitStore's own real behavior (see
    // InMemoryRateLimitStoreTest.should_rejectAtMaxAttempt_and_returnWindowSeconds_as_retryAfter):
    // maxAttempts calls are permitted, the (maxAttempts+1)th is rejected.
    when(rateLimitStore.tryConsume(eq(EXPECTED_KEY), eq(WINDOW_SECONDS), eq(MAX_DENIALS)))
        .thenReturn(
            RateLimitResult.permit(),
            RateLimitResult.permit(),
            RateLimitResult.permit(),
            RateLimitResult.reject(WINDOW_SECONDS));

    for (int i = 0; i < MAX_DENIALS; i++) {
      assertThat(adapter.recordDenial(TENANT_ID, ACTOR_USER_ID))
          .as("denial %d of %d should not yet be the transition", i + 1, MAX_DENIALS)
          .isFalse();
    }
    assertThat(adapter.recordDenial(TENANT_ID, ACTOR_USER_ID))
        .as("the denial that exhausts max-denials is the transition")
        .isTrue();
  }

  @Test
  void should_returnFalse_when_recordDenialCalledAgainWhileAlreadyThrottled() {
    when(rateLimitStore.tryConsume(eq(EXPECTED_KEY), eq(WINDOW_SECONDS), eq(MAX_DENIALS)))
        .thenReturn(
            RateLimitResult.permit(),
            RateLimitResult.permit(),
            RateLimitResult.permit(),
            RateLimitResult.reject(WINDOW_SECONDS),
            RateLimitResult.reject(WINDOW_SECONDS - 5));

    for (int i = 0; i < MAX_DENIALS; i++) {
      adapter.recordDenial(TENANT_ID, ACTOR_USER_ID);
    }
    assertThat(adapter.recordDenial(TENANT_ID, ACTOR_USER_ID)).isTrue(); // the transition
    assertThat(adapter.recordDenial(TENANT_ID, ACTOR_USER_ID))
        .as("a denial recorded while already throttled is not a new transition")
        .isFalse();
  }

  @Test
  void should_returnTrue_when_isThrottledCalledWithinWindowAfterTransition() {
    when(rateLimitStore.tryConsume(eq(EXPECTED_KEY), eq(WINDOW_SECONDS), eq(MAX_DENIALS)))
        .thenReturn(RateLimitResult.reject(WINDOW_SECONDS));

    adapter.recordDenial(TENANT_ID, ACTOR_USER_ID);

    assertThat(adapter.isThrottled(TENANT_ID, ACTOR_USER_ID)).isTrue();
  }

  @Test
  void should_returnFalse_when_clockAdvancedPastThrottledUntil() {
    when(rateLimitStore.tryConsume(eq(EXPECTED_KEY), eq(WINDOW_SECONDS), eq(MAX_DENIALS)))
        .thenReturn(RateLimitResult.reject(10));

    adapter.recordDenial(TENANT_ID, ACTOR_USER_ID);
    assertThat(adapter.isThrottled(TENANT_ID, ACTOR_USER_ID)).isTrue();

    clock.advance(Duration.ofSeconds(11));

    assertThat(adapter.isThrottled(TENANT_ID, ACTOR_USER_ID))
        .as("throttle must self-clear once the throttled-until instant has passed")
        .isFalse();
  }

  @Test
  void should_evictExpiredEntry_when_isThrottledCalledAfterWindowExpires() {
    when(rateLimitStore.tryConsume(eq(EXPECTED_KEY), eq(WINDOW_SECONDS), eq(MAX_DENIALS)))
        .thenReturn(RateLimitResult.reject(10));

    adapter.recordDenial(TENANT_ID, ACTOR_USER_ID);
    assertThat(adapter.mapSize()).isEqualTo(1);

    clock.advance(Duration.ofSeconds(11));
    adapter.isThrottled(TENANT_ID, ACTOR_USER_ID);

    assertThat(adapter.mapSize())
        .as("an expired throttled-until entry must be evicted on read, not merely ignored")
        .isZero();
  }

  @Test
  void should_returnFalseAndNotThrow_when_rateLimitStoreThrowsOnRecordDenial() {
    when(rateLimitStore.tryConsume(anyString(), anyInt(), anyInt()))
        .thenThrow(new IllegalStateException("store unavailable"));

    assertThatCode(() -> adapter.recordDenial(TENANT_ID, ACTOR_USER_ID)).doesNotThrowAnyException();
    assertThat(adapter.recordDenial(TENANT_ID, ACTOR_USER_ID)).isFalse();
    assertThat(adapter.isThrottled(TENANT_ID, ACTOR_USER_ID))
        .as("a store failure must never leave the actor throttled")
        .isFalse();
  }

  @Test
  void should_returnFalseAndNotThrow_when_clockThrowsOnIsThrottled() {
    Clock throwingClock = mock(Clock.class);
    when(throwingClock.instant()).thenThrow(new IllegalStateException("clock unavailable"));
    RateLimitRoleChangeThrottleAdapter faultyAdapter =
        new RateLimitRoleChangeThrottleAdapter(rateLimitStore, throwingClock, MAX_DENIALS, WINDOW_SECONDS);

    assertThatCode(() -> faultyAdapter.isThrottled(TENANT_ID, ACTOR_USER_ID))
        .doesNotThrowAnyException();
    assertThat(faultyAdapter.isThrottled(TENANT_ID, ACTOR_USER_ID)).isFalse();
    verify(rateLimitStore, never()).tryConsume(any(), anyInt(), anyInt());
  }

  @Test
  void should_useExactKeyFormat_when_recordingDenial() {
    when(rateLimitStore.tryConsume(anyString(), anyInt(), anyInt())).thenReturn(RateLimitResult.permit());

    adapter.recordDenial(TENANT_ID, ACTOR_USER_ID);

    verify(rateLimitStore).tryConsume(eq(EXPECTED_KEY), eq(WINDOW_SECONDS), eq(MAX_DENIALS));
  }

  @Test
  void should_neverCallTryConsume_when_isThrottledInvoked() {
    when(rateLimitStore.tryConsume(eq(EXPECTED_KEY), eq(WINDOW_SECONDS), eq(MAX_DENIALS)))
        .thenReturn(RateLimitResult.reject(WINDOW_SECONDS));
    adapter.recordDenial(TENANT_ID, ACTOR_USER_ID);

    adapter.isThrottled(TENANT_ID, ACTOR_USER_ID);
    adapter.isThrottled(TENANT_ID, ACTOR_USER_ID);
    adapter.isThrottled(TENANT_ID, ACTOR_USER_ID);

    verify(rateLimitStore, times(1)).tryConsume(any(), anyInt(), anyInt());
  }

  /**
   * Concurrent access (Phase 8 test-validate gap): every other test in this class drives {@link
   * RateLimitStore} via a Mockito mock returning a pre-programmed, strictly sequential answer
   * sequence, which cannot prove anything about what happens when two threads race the SAME
   * actor's denial through {@link RateLimitRoleChangeThrottleAdapter#recordDenial} at once. A-3
   * requires the {@code RBAC_DENIAL_THROTTLE_ENGAGED} WARN to fire <b>exactly once</b> per
   * transition into the throttled state — the service layer relies on {@code recordDenial}'s
   * {@code boolean} return to make that guarantee, so it must hold under real concurrency, not
   * just under the {@link java.util.concurrent.ConcurrentHashMap#compute} call's documented
   * atomicity. Uses the real, thread-safe {@link InMemoryRateLimitStore} (constructed directly,
   * no Spring context) rather than a mock, because a mock cannot exhibit a genuine race.
   */
  @Test
  void should_returnTrueExactlyOnce_when_manyThreadsRaceTheSameActorsDenialPastMaxDenials()
      throws InterruptedException {
    InMemoryRateLimitStore realStore = new InMemoryRateLimitStore(clock, WINDOW_SECONDS);
    RateLimitRoleChangeThrottleAdapter racingAdapter =
        new RateLimitRoleChangeThrottleAdapter(realStore, clock, MAX_DENIALS, WINDOW_SECONDS);
    int threadCount = 20;
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    CountDownLatch ready = new CountDownLatch(threadCount);
    CountDownLatch go = new CountDownLatch(1);
    Callable<Boolean> raceOneDenial =
        () -> {
          ready.countDown();
          go.await();
          return racingAdapter.recordDenial(TENANT_ID, ACTOR_USER_ID);
        };

    try {
      // submit() (not invokeAll(), which blocks the calling thread until every task completes)
      // so all threadCount tasks are in flight and queued behind `go` before it is released.
      List<Future<Boolean>> futures =
          java.util.stream.IntStream.range(0, threadCount)
              .mapToObj(i -> executor.submit(raceOneDenial))
              .collect(Collectors.toList());
      assertThat(ready.await(5, TimeUnit.SECONDS))
          .as("all %d threads must reach the barrier before it is released", threadCount)
          .isTrue();
      go.countDown();
      long transitions = futures.stream().filter(RateLimitRoleChangeThrottleAdapterTest::resultOf).count();

      assertThat(transitions)
          .as("exactly one of %d racing threads must observe the transition into throttled,"
              + " however many of them recordDenial as a plain (non-transition) denial",
              threadCount)
          .isEqualTo(1);
    } finally {
      executor.shutdownNow();
    }
  }

  private static boolean resultOf(Future<Boolean> future) {
    try {
      return future.get();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** Deterministic, advanceable {@link Clock} test double — {@code Clock.fixed} cannot be advanced in place. */
  private static final class MutableClock extends Clock {
    private Instant instant;

    MutableClock(Instant start) {
      this.instant = start;
    }

    void advance(Duration duration) {
      instant = instant.plus(duration);
    }

    @Override
    public ZoneId getZone() {
      return ZoneId.of("UTC");
    }

    @Override
    public Clock withZone(ZoneId zone) {
      throw new UnsupportedOperationException("not needed by this test");
    }

    @Override
    public Instant instant() {
      return instant;
    }
  }
}
