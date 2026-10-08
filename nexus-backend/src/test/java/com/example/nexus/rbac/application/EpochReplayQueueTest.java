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
        .satisfies(entry -> assertThat(entry.failedAt()).isEqualTo(T));
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
      assertThat(batch.entries()).allSatisfy(entry -> assertThat(entry.failedAt()).isEqualTo(T));
    });
  }

  private static List<UUID> users(int count) {
    return IntStream.range(0, count).mapToObj(i -> UUID.randomUUID()).toList();
  }
}
