package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.rbac.application.EpochReplayQueue.Batch;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link EpochReplayQueue} (US-018 T-012, design §9.3). */
@Tag("UnitTest")
class EpochReplayQueueTest {

  private static final UUID TENANT = UUID.fromString("00000000-0000-7000-8000-0000000000aa");
  private static final UUID OTHER_TENANT = UUID.fromString("00000000-0000-7000-8000-0000000000ab");
  private static final UUID USER = UUID.fromString("00000000-0000-7000-8000-0000000000bb");
  private static final Instant T = Instant.parse("2026-10-08T10:00:00Z");
  private static final Instant NEVER_EXPIRED = Instant.MIN;

  @Test
  void should_keepOldestFailedAt_when_sameUserEnqueuedAgain() {
    EpochReplayQueue queue = new EpochReplayQueue(10);
    queue.offer(TENANT, List.of(USER), T);
    queue.offer(TENANT, List.of(USER), T.plusSeconds(5));

    Batch batch = queue.poll(500, NEVER_EXPIRED).orElseThrow();

    assertThat(batch.entries()).singleElement()
        .satisfies(entry -> assertThat(entry.oldestFailedAt()).isEqualTo(T));
  }

  @Test
  void should_keepNewestFailedAt_when_sameUserEnqueuedAgain() {
    EpochReplayQueue queue = new EpochReplayQueue(10);
    queue.offer(TENANT, List.of(USER), T);
    queue.offer(TENANT, List.of(USER), T.plusSeconds(900));

    Batch batch = queue.poll(500, NEVER_EXPIRED).orElseThrow();

    assertThat(batch.entries()).singleElement()
        .satisfies(entry -> assertThat(entry.newestFailedAt()).isEqualTo(T.plusSeconds(900)));
  }

  @Test
  void should_replayCoalescedUser_when_newestLostBumpIsStillInsideTtl() {
    EpochReplayQueue queue = new EpochReplayQueue(10);
    queue.offer(TENANT, List.of(USER), T);
    queue.offer(TENANT, List.of(USER), T.plusSeconds(900));

    // Polled at T+960 with a 960 s TTL the cutoff is T: the oldest bump is expired, the newest
    // (T+900, a token minted then lives to T+1800) is not.
    Batch batch = queue.poll(500, T).orElseThrow();

    assertThat(batch.userIds()).containsExactly(USER);
  }

  @Test
  void should_dropCoalescedUser_when_newestLostBumpIsAlsoExpired() {
    EpochReplayQueue queue = new EpochReplayQueue(10);
    queue.offer(TENANT, List.of(USER), T);
    queue.offer(TENANT, List.of(USER), T.plusSeconds(5));

    assertThat(queue.poll(500, T.plusSeconds(5))).isEmpty();
  }

  @Test
  void should_keepBothTimestamps_when_batchRequeued() {
    EpochReplayQueue queue = new EpochReplayQueue(10);
    queue.offer(TENANT, List.of(USER), T);
    queue.offer(TENANT, List.of(USER), T.plusSeconds(7));
    Batch batch = queue.poll(500, NEVER_EXPIRED).orElseThrow();

    queue.requeue(batch);

    assertThat(queue.poll(500, NEVER_EXPIRED).orElseThrow().entries()).singleElement()
        .satisfies(entry -> {
          assertThat(entry.oldestFailedAt()).isEqualTo(T);
          assertThat(entry.newestFailedAt()).isEqualTo(T.plusSeconds(7));
        });
  }

  @Test
  void should_mergeTimestamps_when_batchRequeuedOverNewerOffer() {
    EpochReplayQueue queue = new EpochReplayQueue(10);
    queue.offer(TENANT, List.of(USER), T);
    Batch batch = queue.poll(500, NEVER_EXPIRED).orElseThrow();
    queue.offer(TENANT, List.of(USER), T.plusSeconds(9));

    queue.requeue(batch);

    assertThat(queue.poll(500, NEVER_EXPIRED).orElseThrow().entries()).singleElement()
        .satisfies(entry -> {
          assertThat(entry.oldestFailedAt()).isEqualTo(T);
          assertThat(entry.newestFailedAt()).isEqualTo(T.plusSeconds(9));
        });
  }

  @Test
  void should_keepOldestFailedAt_when_olderFailureArrivesLater() {
    EpochReplayQueue queue = new EpochReplayQueue(10);
    queue.offer(TENANT, List.of(USER), T.plusSeconds(5));
    queue.offer(TENANT, List.of(USER), T);

    assertThat(queue.poll(500, NEVER_EXPIRED).orElseThrow().oldestFailedAt()).isEqualTo(T);
  }

  @Test
  void should_countDistinctUsers_when_coalescing() {
    EpochReplayQueue queue = new EpochReplayQueue(10);
    queue.offer(TENANT, List.of(USER), T);
    queue.offer(TENANT, List.of(USER), T);
    queue.offer(OTHER_TENANT, List.of(USER), T);

    assertThat(queue.size()).isEqualTo(2);
  }

  @Test
  void should_acceptExactlyCapacity_when_offered() {
    EpochReplayQueue queue = new EpochReplayQueue(3);

    int dropped = queue.offer(TENANT, users(3), T);

    assertThat(dropped).isZero();
    assertThat(queue.size()).isEqualTo(3);
  }

  @Test
  void should_dropNewestAndReportCount_when_overCapacity() {
    EpochReplayQueue queue = new EpochReplayQueue(3);
    List<UUID> users = users(5);

    int dropped = queue.offer(TENANT, users, T);

    assertThat(dropped).isEqualTo(2);
    assertThat(queue.size()).isEqualTo(3);
    assertThat(queue.poll(500, NEVER_EXPIRED).orElseThrow().userIds())
        .containsExactlyElementsOf(users.subList(0, 3));
  }

  @Test
  void should_notDropAndNotGrow_when_fullQueueGetsAnAlreadyQueuedUser() {
    EpochReplayQueue queue = new EpochReplayQueue(1);
    queue.offer(TENANT, List.of(USER), T);

    int dropped = queue.offer(TENANT, List.of(USER), T.plusSeconds(1));

    assertThat(dropped).isZero();
    assertThat(queue.size()).isEqualTo(1);
  }

  @Test
  void should_dropAll_when_queueFull() {
    EpochReplayQueue queue = new EpochReplayQueue(1);
    queue.offer(TENANT, List.of(USER), T);

    assertThat(queue.offer(TENANT, users(4), T)).isEqualTo(4);
  }

  @Test
  void should_pollAtMostMaxPerBatch_and_leaveTheRest() {
    EpochReplayQueue queue = new EpochReplayQueue(2000);
    queue.offer(TENANT, users(1001), T);

    assertThat(queue.poll(500, NEVER_EXPIRED).orElseThrow().userIds()).hasSize(500);
    assertThat(queue.size()).isEqualTo(501);
  }

  @Test
  void should_neverMixTenantsInOneBatch() {
    EpochReplayQueue queue = new EpochReplayQueue(10);
    queue.offer(TENANT, List.of(USER), T);
    queue.offer(OTHER_TENANT, List.of(USER), T);

    Batch first = queue.poll(500, NEVER_EXPIRED).orElseThrow();
    Batch second = queue.poll(500, NEVER_EXPIRED).orElseThrow();

    assertThat(List.of(first.tenantId(), second.tenantId()))
        .containsExactlyInAnyOrder(TENANT, OTHER_TENANT);
    assertThat(queue.isEmpty()).isTrue();
  }

  @Test
  void should_returnEmpty_when_queueEmpty() {
    assertThat(new EpochReplayQueue(10).poll(500, NEVER_EXPIRED)).isEmpty();
  }

  @Test
  void should_dropEntriesAtOrBeforeCutoff_when_polling() {
    EpochReplayQueue queue = new EpochReplayQueue(10);
    UUID expired = UUID.randomUUID();
    UUID boundary = UUID.randomUUID();
    UUID live = UUID.randomUUID();
    queue.offer(TENANT, List.of(expired), T.minusSeconds(1));
    queue.offer(TENANT, List.of(boundary), T);
    queue.offer(TENANT, List.of(live), T.plusSeconds(1));

    Batch batch = queue.poll(500, T).orElseThrow();

    assertThat(batch.userIds()).containsExactly(live);
    assertThat(queue.isEmpty()).isTrue();
  }

  @Test
  void should_returnEmptyAndEmptyTheQueue_when_everyEntryExpired() {
    EpochReplayQueue queue = new EpochReplayQueue(10);
    queue.offer(TENANT, users(3), T);
    queue.offer(OTHER_TENANT, users(3), T);

    assertThat(queue.poll(500, T.plusSeconds(1))).isEmpty();
    assertThat(queue.isEmpty()).isTrue();
  }

  @Test
  void should_restoreWithOriginalFailedAt_when_batchRequeued() {
    EpochReplayQueue queue = new EpochReplayQueue(10);
    queue.offer(TENANT, List.of(USER), T);
    Batch batch = queue.poll(500, NEVER_EXPIRED).orElseThrow();
    queue.offer(TENANT, List.of(USER), T.plusSeconds(9));

    queue.requeue(batch);

    assertThat(queue.size()).isEqualTo(1);
    assertThat(queue.poll(500, NEVER_EXPIRED).orElseThrow().oldestFailedAt()).isEqualTo(T);
  }

  @Test
  void should_neverLoseRequeuedEntries_when_queueRefilledMeanwhile() {
    EpochReplayQueue queue = new EpochReplayQueue(2);
    queue.offer(TENANT, users(2), T);
    Batch batch = queue.poll(500, NEVER_EXPIRED).orElseThrow();
    queue.offer(TENANT, users(2), T.plusSeconds(1));

    queue.requeue(batch);

    assertThat(queue.size()).isEqualTo(4);
  }

  @Test
  void should_rejectNonPositiveCapacity() {
    assertThatThrownBy(() -> new EpochReplayQueue(0)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void should_keepOldestAndStayBounded_when_enqueuedConcurrently() throws Exception {
    EpochReplayQueue queue = new EpochReplayQueue(100);
    List<UUID> users = users(100);
    int threads = 8;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CountDownLatch start = new CountDownLatch(1);
    try {
      for (int t = 0; t < threads; t++) {
        Instant failedAt = T.plusSeconds(t);
        pool.submit(() -> {
          start.await();
          queue.offer(TENANT, users, failedAt);
          return null;
        });
      }
      start.countDown();
    } finally {
      pool.shutdown();
      assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
    }

    List<Batch> batches = new ArrayList<>();
    queue.poll(500, NEVER_EXPIRED).ifPresent(batches::add);
    assertThat(batches).singleElement().satisfies(batch -> {
      assertThat(batch.entries()).hasSize(100);
      assertThat(batch.entries()).allSatisfy(entry -> assertThat(entry.oldestFailedAt()).isEqualTo(T));
    });
  }

  /** Offering nobody for a new tenant must not leave a phantom tenant for poll to trip on. */
  @Test
  void should_stayEmpty_when_offeredNoUsersForNewTenant() {
    EpochReplayQueue queue = new EpochReplayQueue(10);

    int dropped = queue.offer(TENANT, List.of(), T);

    assertThat(dropped).isZero();
    assertThat(queue.isEmpty()).isTrue();
    assertThat(queue.poll(500, NEVER_EXPIRED)).isEmpty();
  }

  /**
   * Drain vs offer: request threads offer while the scheduler polls and requeues some batches (a
   * failed replay) and keeps others (a replayed one). Nothing is lost or duplicated whatever the
   * interleaving: replayed users plus what is still queued are exactly the users offered.
   */
  @Test
  void should_loseNoUser_when_offeredWhileDrainerPollsAndRequeues() throws Exception {
    EpochReplayQueue queue = new EpochReplayQueue(100_000);
    int producers = 4;
    List<UUID> all = users(producers * 500);
    java.util.Set<UUID> replayed = java.util.concurrent.ConcurrentHashMap.newKeySet();
    java.util.concurrent.atomic.AtomicBoolean producing =
        new java.util.concurrent.atomic.AtomicBoolean(true);
    ExecutorService pool = Executors.newFixedThreadPool(producers + 1);
    CountDownLatch start = new CountDownLatch(1);
    List<java.util.concurrent.Future<?>> work = new ArrayList<>();
    for (int p = 0; p < producers; p++) {
      List<UUID> mine = all.subList(p * 500, (p + 1) * 500);
      work.add(pool.submit(() -> {
        start.await();
        for (UUID user : mine) {
          queue.offer(TENANT, List.of(user), T);
        }
        return null;
      }));
    }
    java.util.concurrent.Future<?> drainer = pool.submit(() -> {
      start.await();
      int polls = 0;
      while (producing.get() || !queue.isEmpty()) {
        Batch batch = queue.poll(7, NEVER_EXPIRED).orElse(null);
        if (batch == null) {
          continue;
        }
        if (polls++ % 2 == 0) {
          queue.requeue(batch);
        } else {
          replayed.addAll(batch.userIds());
        }
      }
      return null;
    });
    start.countDown();
    for (java.util.concurrent.Future<?> f : work) {
      f.get(60, TimeUnit.SECONDS);
    }
    producing.set(false);
    drainer.get(60, TimeUnit.SECONDS);
    pool.shutdownNow();

    assertThat(replayed).containsExactlyInAnyOrderElementsOf(all);
    assertThat(queue.size()).isZero();
  }

  // --- L-2 (pre-PR review): a tenant over its share overflows itself, not the others ---

  @Test
  void should_dropOnlyTheOverflowingTenantsUsers_when_oneTenantExceedsItsShare() {
    EpochReplayQueue queue = new EpochReplayQueue(10, 3);

    int droppedOfFirst = queue.offer(TENANT, users(5), T);
    int droppedOfSecond = queue.offer(OTHER_TENANT, users(2), T);

    assertThat(droppedOfFirst).isEqualTo(2);
    assertThat(droppedOfSecond).isZero();
    assertThat(queue.size()).isEqualTo(5);
  }

  @Test
  void should_coalesceWithoutUsingShare_when_queuedUserOfFullTenantFailsAgain() {
    EpochReplayQueue queue = new EpochReplayQueue(10, 1);
    queue.offer(TENANT, List.of(USER), T);

    assertThat(queue.offer(TENANT, List.of(USER), T.plusSeconds(1))).isZero();
    assertThat(queue.size()).isEqualTo(1);
  }

  @Test
  void should_stillBoundTheTotal_when_tenantSharesAddUpToMore() {
    EpochReplayQueue queue = new EpochReplayQueue(4, 3);

    queue.offer(TENANT, users(3), T);
    int dropped = queue.offer(OTHER_TENANT, users(3), T);

    assertThat(dropped).isEqualTo(2);
    assertThat(queue.size()).isEqualTo(4);
  }

  @Test
  void should_rejectNonPositiveTenantShare() {
    assertThatThrownBy(() -> new EpochReplayQueue(10, 0))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private static List<UUID> users(int count) {
    return IntStream.range(0, count).mapToObj(i -> UUID.randomUUID()).toList();
  }
}
