package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.rbac.application.RoleReplayQueue.Entry;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Unit tests verifying exponential backoff preservation across coalesced merges
 * in {@link RoleReplayQueue} ([OR-2.1-07]).
 */
@Tag("UnitTest")
class RoleReplayQueueBackoffTest {

  private static final UUID TENANT = UUID.fromString("00000000-0000-7000-8000-0000000000aa");
  private static final UUID ROLE = UUID.fromString("00000000-0000-7000-8000-0000000000c1");
  private static final Instant T = Instant.parse("2026-10-08T10:00:00Z");
  private static final Instant NEVER_EXPIRED = Instant.MIN;

  @Test
  void should_preserve_exponential_backoff_across_merges() {
    RoleReplayQueue queue = new RoleReplayQueue(5);

    // Initial failure at T
    queue.offer(TENANT, ROLE, T);

    // Poll at T (initial attempt, 0 previous attempts)
    Entry first = queue.poll(T, NEVER_EXPIRED).orElseThrow();
    assertThat(first.attempts()).isZero();

    // Replay attempt fails at T -> requeued with attempt recorded at T
    queue.requeue(first, T);

    // A subsequent failure is offered at T+1 (merging failure timestamps)
    queue.offer(TENANT, ROLE, T.plusSeconds(1));

    // At T+1, exponential backoff (2^1 = 2s from attempt at T) has NOT elapsed
    // Polling at T+1 must NOT poll the role (preserving backoff delay)
    assertThat(queue.poll(T.plusSeconds(1), NEVER_EXPIRED)).isEmpty();

    // At T+3, backoff (>= 2s) has elapsed: role is now eligible for retry
    Entry second = queue.poll(T.plusSeconds(3), NEVER_EXPIRED).orElseThrow();
    assertThat(second.attempts()).isEqualTo(1);
    assertThat(second.newestFailedAt()).isEqualTo(T.plusSeconds(1));

    // Second replay attempt fails at T+3 -> backoff doubles (2^2 = 4s)
    queue.requeue(second, T.plusSeconds(3));

    // Further failure merges at T+4
    queue.offer(TENANT, ROLE, T.plusSeconds(4));

    // At T+5 (only 2s since attempt at T+3, needed 4s): must NOT be eligible
    assertThat(queue.poll(T.plusSeconds(5), NEVER_EXPIRED)).isEmpty();

    // At T+7 (4s since attempt at T+3): eligible!
    Entry third = queue.poll(T.plusSeconds(7), NEVER_EXPIRED).orElseThrow();
    assertThat(third.attempts()).isEqualTo(2);
    assertThat(third.newestFailedAt()).isEqualTo(T.plusSeconds(4));
  }
}
