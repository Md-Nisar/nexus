package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.rbac.application.RoleReplayQueue.Entry;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link RoleReplayQueue} (US-018 M7 part 2 review, M-2). */
@Tag("UnitTest")
class RoleReplayQueueTest {

  private static final UUID TENANT = UUID.fromString("00000000-0000-7000-8000-0000000000aa");
  private static final UUID OTHER_TENANT = UUID.fromString("00000000-0000-7000-8000-0000000000ab");
  private static final UUID ROLE = UUID.fromString("00000000-0000-7000-8000-0000000000c1");
  private static final UUID OTHER_ROLE = UUID.fromString("00000000-0000-7000-8000-0000000000c2");
  private static final Instant T = Instant.parse("2026-10-08T10:00:00Z");
  private static final Instant NEVER_EXPIRED = Instant.MIN;

  @Test
  void should_rejectCapacityBelowOne_when_constructed() {
    assertThatThrownBy(() -> new RoleReplayQueue(0)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void should_beEmpty_when_new() {
    RoleReplayQueue queue = new RoleReplayQueue(2);

    assertThat(queue.isEmpty()).isTrue();
    assertThat(queue.poll(NEVER_EXPIRED)).isEmpty();
  }

  @Test
  void should_coalesceToOneSlot_when_sameRoleOfferedAgain() {
    RoleReplayQueue queue = new RoleReplayQueue(2);

    assertThat(queue.offer(TENANT, ROLE, T)).isTrue();
    assertThat(queue.offer(TENANT, ROLE, T.plusSeconds(5))).isTrue();

    assertThat(queue.size()).isEqualTo(1);
  }

  @Test
  void should_keepOldestAndNewestFailedAt_when_sameRoleOfferedAgain() {
    RoleReplayQueue queue = new RoleReplayQueue(2);
    queue.offer(TENANT, ROLE, T);
    queue.offer(TENANT, ROLE, T.plusSeconds(900));

    Entry entry = queue.poll(NEVER_EXPIRED).orElseThrow();

    assertThat(entry.oldestFailedAt()).isEqualTo(T);
    assertThat(entry.newestFailedAt()).isEqualTo(T.plusSeconds(900));
  }

  @Test
  void should_keepRolesOfDifferentTenantsApart_when_roleIdsEqual() {
    RoleReplayQueue queue = new RoleReplayQueue(2);
    queue.offer(TENANT, ROLE, T);
    queue.offer(OTHER_TENANT, ROLE, T);

    assertThat(queue.size()).isEqualTo(2);
  }

  @Test
  void should_refuseNewRole_when_full() {
    RoleReplayQueue queue = new RoleReplayQueue(1);
    queue.offer(TENANT, ROLE, T);

    assertThat(queue.offer(TENANT, OTHER_ROLE, T)).isFalse();
    assertThat(queue.size()).isEqualTo(1);
  }

  @Test
  void should_acceptRepeat_when_fullButRoleAlreadyQueued() {
    RoleReplayQueue queue = new RoleReplayQueue(1);
    queue.offer(TENANT, ROLE, T);

    assertThat(queue.offer(TENANT, ROLE, T.plusSeconds(1))).isTrue();
  }

  @Test
  void should_pollInInsertionOrder_when_severalQueued() {
    RoleReplayQueue queue = new RoleReplayQueue(3);
    queue.offer(TENANT, ROLE, T);
    queue.offer(TENANT, OTHER_ROLE, T);

    assertThat(queue.poll(NEVER_EXPIRED).orElseThrow().roleId()).isEqualTo(ROLE);
    assertThat(queue.poll(NEVER_EXPIRED).orElseThrow().roleId()).isEqualTo(OTHER_ROLE);
    assertThat(queue.isEmpty()).isTrue();
  }

  @Test
  void should_discardEntry_when_newestFailureAtOrBeforeExpiry() {
    RoleReplayQueue queue = new RoleReplayQueue(3);
    queue.offer(TENANT, ROLE, T);

    assertThat(queue.poll(T)).isEmpty();
    assertThat(queue.isEmpty()).isTrue();
  }

  @Test
  void should_returnEntry_when_newestFailureOneNanoAfterExpiry() {
    RoleReplayQueue queue = new RoleReplayQueue(3);
    queue.offer(TENANT, ROLE, T);

    assertThat(queue.poll(T.minusNanos(1))).isPresent();
  }

  @Test
  void should_skipExpiredAndReturnLive_when_expiredEntryIsFirst() {
    RoleReplayQueue queue = new RoleReplayQueue(3);
    queue.offer(TENANT, ROLE, T);
    queue.offer(TENANT, OTHER_ROLE, T.plusSeconds(10));

    Entry entry = queue.poll(T).orElseThrow();

    assertThat(entry.roleId()).isEqualTo(OTHER_ROLE);
    assertThat(queue.isEmpty()).isTrue();
  }

  @Test
  void should_keepOriginalTimesAndIgnoreCapacity_when_requeued() {
    RoleReplayQueue queue = new RoleReplayQueue(1);
    queue.offer(TENANT, ROLE, T);
    Entry polled = queue.poll(NEVER_EXPIRED).orElseThrow();
    queue.offer(TENANT, OTHER_ROLE, T.plusSeconds(1));

    queue.requeue(polled);

    assertThat(queue.size()).isEqualTo(2);
    queue.poll(NEVER_EXPIRED);
    assertThat(queue.poll(NEVER_EXPIRED).orElseThrow().oldestFailedAt()).isEqualTo(T);
  }

  @Test
  void should_mergeTimes_when_requeuedRoleWasOfferedMeanwhile() {
    RoleReplayQueue queue = new RoleReplayQueue(2);
    queue.offer(TENANT, ROLE, T);
    Entry polled = queue.poll(NEVER_EXPIRED).orElseThrow();
    queue.offer(TENANT, ROLE, T.plusSeconds(30));

    queue.requeue(polled);

    Entry entry = queue.poll(NEVER_EXPIRED).orElseThrow();
    assertThat(queue.size()).isZero();
    assertThat(entry.oldestFailedAt()).isEqualTo(T);
    assertThat(entry.newestFailedAt()).isEqualTo(T.plusSeconds(30));
  }

  /** Request threads offering the same capacity-bound set concurrently never overshoot it. */
  @Test
  void should_neverExceedCapacityAndKeepOldest_when_offeredConcurrently() throws Exception {
    RoleReplayQueue queue = new RoleReplayQueue(50);
    List<UUID> roles = IntStream.range(0, 200).mapToObj(i -> UUID.randomUUID()).toList();
    int threads = 8;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CountDownLatch start = new CountDownLatch(1);
    try {
      for (int t = 0; t < threads; t++) {
        Instant failedAt = T.plusSeconds(t);
        pool.submit(() -> {
          start.await();
          for (UUID role : roles) {
            queue.offer(TENANT, role, failedAt);
          }
          return null;
        });
      }
      start.countDown();
    } finally {
      pool.shutdown();
      assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
    }

    assertThat(queue.size()).isEqualTo(50);
    for (int i = 0; i < 50; i++) {
      Entry entry = queue.poll(NEVER_EXPIRED).orElseThrow();
      assertThat(entry.oldestFailedAt()).isEqualTo(T);
      assertThat(entry.newestFailedAt()).isEqualTo(T.plusSeconds(threads - 1));
    }
    assertThat(queue.isEmpty()).isTrue();
  }

  @Test
  void should_returnEmptyAndEmptyTheQueue_when_everyRoleExpired() {
    RoleReplayQueue queue = new RoleReplayQueue(3);
    queue.offer(TENANT, ROLE, T);
    queue.offer(OTHER_TENANT, OTHER_ROLE, T.plusSeconds(1));

    assertThat(queue.poll(T.plusSeconds(1))).isEmpty();
    assertThat(queue.isEmpty()).isTrue();
  }

  // --- L-2 (pre-PR review): borrow beyond the share while the queue is under half full ---

  @Test
  void should_letATenantBorrowUntilHalfFull_then_refuseOnlyThatTenant() {
    RoleReplayQueue queue = new RoleReplayQueue(4, 1);

    assertThat(queue.offer(TENANT, ROLE, T)).isTrue();
    assertThat(queue.offer(TENANT, OTHER_ROLE, T)).isTrue();
    assertThat(queue.offer(TENANT, UUID.randomUUID(), T)).isFalse();
    assertThat(queue.offer(OTHER_TENANT, UUID.randomUUID(), T)).isTrue();
    assertThat(queue.size()).isEqualTo(3);
  }

  @Test
  void should_coalesceWithoutUsingShare_when_queuedRoleOfFullTenantFailsAgain() {
    RoleReplayQueue queue = new RoleReplayQueue(10, 1);
    queue.offer(TENANT, ROLE, T);

    assertThat(queue.offer(TENANT, ROLE, T.plusSeconds(1))).isTrue();
    assertThat(queue.size()).isEqualTo(1);
  }

  @Test
  void should_rejectNonPositiveTenantShare() {
    assertThatThrownBy(() -> new RoleReplayQueue(10, 0))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
