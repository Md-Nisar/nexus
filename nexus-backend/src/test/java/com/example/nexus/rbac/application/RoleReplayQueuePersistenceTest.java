package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.rbac.application.RoleReplayQueue.Entry;
import com.example.nexus.rbac.application.RoleReplayQueue.RoleReplayStore;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Unit tests verifying persistence and recovery of unreplayed role entries across pod restarts
 * (OR-15).
 */
@Tag("UnitTest")
class RoleReplayQueuePersistenceTest {

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-0000000000aa");
  private static final UUID ROLE_1 = UUID.fromString("00000000-0000-7000-8000-0000000000b1");
  private static final UUID ROLE_2 = UUID.fromString("00000000-0000-7000-8000-0000000000b2");
  private static final Instant T0 = Instant.parse("2026-10-27T10:00:00Z");

  @Test
  void should_recover_unreplayed_roles_after_restart() {
    // Simulated persistent WAL backing store
    InMemoryRoleReplayStore walStore = new InMemoryRoleReplayStore();

    // Pod 1 instance of RoleReplayQueue
    RoleReplayQueue pod1Queue =
        new RoleReplayQueue(10, 10, Duration.ofHours(1), walStore);

    pod1Queue.offer(TENANT_ID, ROLE_1, T0);
    pod1Queue.offer(TENANT_ID, ROLE_2, T0.plusSeconds(30));

    assertThat(pod1Queue.size()).isEqualTo(2);
    assertThat(walStore.persistedEntries()).hasSize(2);

    // Simulate pod termination and replacement (Pod 2 restart) with the same WAL store
    RoleReplayQueue pod2Queue =
        new RoleReplayQueue(10, 10, Duration.ofHours(1), walStore);

    // Pod 2 recovers the exact un-replayed roles from the store
    assertThat(pod2Queue.size()).isEqualTo(2);

    // Polling from Pod 2 removes entries from queue and persistent store
    Entry polled1 = pod2Queue.poll(Instant.MAX, Instant.MIN).orElseThrow();
    assertThat(polled1.roleId()).isEqualTo(ROLE_1);
    assertThat(walStore.persistedEntries()).hasSize(1);

    Entry polled2 = pod2Queue.poll(Instant.MAX, Instant.MIN).orElseThrow();
    assertThat(polled2.roleId()).isEqualTo(ROLE_2);
    assertThat(walStore.persistedEntries()).isEmpty();

    assertThat(pod2Queue.isEmpty()).isTrue();
  }

  private static class InMemoryRoleReplayStore implements RoleReplayStore {
    private final Map<UUID, Entry> entries = new LinkedHashMap<>();

    @Override
    public void save(
        UUID tenantId, UUID roleId, Instant oldestFailedAt, Instant newestFailedAt) {
      entries.put(roleId, new Entry(tenantId, roleId, oldestFailedAt, newestFailedAt));
    }

    @Override
    public void remove(UUID tenantId, UUID roleId) {
      entries.remove(roleId);
    }

    @Override
    public List<Entry> loadAll() {
      return new ArrayList<>(entries.values());
    }

    Map<UUID, Entry> persistedEntries() {
      return entries;
    }
  }
}
