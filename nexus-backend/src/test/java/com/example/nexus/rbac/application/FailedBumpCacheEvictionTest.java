package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.application.port.out.UserRoleQueryPort;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.dao.QueryTimeoutException;

/**
 * Two instances sharing one Redis (pre-PR security re-review RR-M1). Instance A commits a detach
 * and its bump is refused (Redis at {@code maxmemory} under {@code noeviction}: writes refused,
 * reads and {@code DEL} served). Instance B then mints for a holder: it reads the unchanged epoch,
 * so the cached permission set under that epoch is the only thing that could still carry the
 * detached permission.
 */
@Tag("UnitTest")
class FailedBumpCacheEvictionTest {

  private static final UUID TENANT = UUID.fromString("00000000-0000-7000-8000-0000000000aa");
  private static final UUID USER = UUID.fromString("00000000-0000-7000-8000-0000000000bb");
  private static final long EPOCH = Instant.parse("2026-10-08T09:59:00Z").toEpochMilli();

  private final Map<String, ResolvedPermissions> cacheEntries = new HashMap<>();
  private UserRoleQueryPort database;
  private RoleResolutionService instanceB;
  private PermissionFreshnessService instanceA;

  /** The shared cache: eviction drops the entries under the user's current epoch. */
  private PermissionCachePort sharedCache(boolean evictionWorks) {
    return new PermissionCachePort() {
      @Override
      public java.util.Optional<ResolvedPermissions> get(UUID tenantId, UUID userId, long epoch) {
        return java.util.Optional.ofNullable(cacheEntries.get(key(tenantId, userId, epoch)));
      }

      @Override
      public void put(UUID tenantId, UUID userId, long epoch, ResolvedPermissions resolved) {
        cacheEntries.put(key(tenantId, userId, epoch), resolved);
      }

      @Override
      public void evict(UUID tenantId, UUID userId) {
        evict(tenantId, List.of(userId));
      }

      @Override
      public void evict(UUID tenantId, Collection<UUID> userIds) {
        if (evictionWorks) {
          userIds.forEach(id -> cacheEntries.remove(key(tenantId, id, EPOCH)));
        }
      }
    };
  }

  private static String key(UUID tenantId, UUID userId, long epoch) {
    return tenantId + ":" + userId + ":" + epoch;
  }

  private void wire(boolean evictionWorks) {
    PermissionCachePort cache = sharedCache(evictionWorks);
    database = mock(UserRoleQueryPort.class);
    when(database.findActiveRoleNames(USER, TENANT)).thenReturn(List.of("EDITOR"));
    when(database.findActivePermissionNames(USER, TENANT))
        .thenReturn(List.of("doc:read", "doc:write"));
    instanceB = new RoleResolutionService(database, cache);

    PermissionEpochPort redis = mock(PermissionEpochPort.class);
    when(redis.current(TENANT, USER)).thenReturn(OptionalLong.of(EPOCH));
    doThrow(new QueryTimeoutException("OOM command not allowed")).when(redis)
        .bump(any(), anyCollection());
    instanceA = new PermissionFreshnessService(
        redis, mock(UserRoleAssignmentPort.class), cache, new SimpleMeterRegistry(),
        Clock.fixed(Instant.parse("2026-10-08T10:00:00Z"), ZoneOffset.UTC),
        Duration.ofMinutes(15), 3, Duration.ofSeconds(10), Duration.ofSeconds(60), 960, 100_000,
        1000, 10);
  }

  @BeforeEach
  void setUp() {
    cacheEntries.clear();
  }

  @Test
  void should_resolveFromTheDatabaseOnTheOtherInstance_when_aDetachBumpIsRefused() {
    wire(true);
    // B has the holder's set cached under the current epoch before the detach.
    assertThat(instanceB.resolve(USER, TENANT, EPOCH).permissions())
        .containsExactlyInAnyOrder("doc:read", "doc:write");
    // The detach commits: the database no longer grants doc:write.
    when(database.findActivePermissionNames(USER, TENANT)).thenReturn(List.of("doc:read"));

    // A's post-commit bump is refused.
    instanceA.invalidateHolders(TENANT, List.of(USER), "detach");

    // B mints for the holder at the unchanged epoch and must not read the old set.
    assertThat(instanceB.resolve(USER, TENANT, EPOCH).permissions()).containsExactly("doc:read");
  }

  @Test
  void should_showTheHole_when_theCachedSetIsNotEvicted() {
    wire(false);
    instanceB.resolve(USER, TENANT, EPOCH);
    when(database.findActivePermissionNames(USER, TENANT)).thenReturn(List.of("doc:read"));

    instanceA.invalidateHolders(TENANT, List.of(USER), "detach");

    // Control: without the eviction the detached permission is re-minted from the cache. This is
    // why the other test passes.
    assertThat(instanceB.resolve(USER, TENANT, EPOCH).permissions())
        .contains("doc:write");
  }
}
