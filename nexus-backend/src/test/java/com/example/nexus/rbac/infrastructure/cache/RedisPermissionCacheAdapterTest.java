package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;

/**
 * Unit coverage for {@link RedisPermissionCacheAdapter}'s detection/serialization logic, its
 * epoch-keyed entries (US-018 Decision 17), the batched eviction and fail-open behavior, in
 * isolation from a real Redis instance (mocked {@link StringRedisTemplate} stack). Live-Redis
 * round-trip coverage, including the eviction script itself, lives in {@link
 * RedisPermissionCacheAdapterIT}.
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class RedisPermissionCacheAdapterTest {

  private static final String KEY_PREFIX = "nexus-test";
  private static final long TTL_SECONDS = 900L;
  private static final long EPOCH = 1_796_000_000_000L;
  private static final UUID TENANT_ID = UUID.randomUUID();
  private static final UUID USER_ID = UUID.randomUUID();
  private static final String ROLE_KEY =
      KEY_PREFIX + ":rbac:roleset:" + TENANT_ID + ":" + USER_ID + ":" + EPOCH;
  private static final String PERM_KEY =
      KEY_PREFIX + ":rbac:permset:" + TENANT_ID + ":" + USER_ID + ":" + EPOCH;
  private static final String EPOCH_KEY = KEY_PREFIX + ":rbac:epoch:" + TENANT_ID + ":" + USER_ID;

  @Mock private StringRedisTemplate redisTemplate;
  @Mock private SetOperations<String, String> setOperations;

  private RedisPermissionCacheAdapter adapter;

  @BeforeEach
  void setUp() {
    adapter = new RedisPermissionCacheAdapter(redisTemplate, KEY_PREFIX, TTL_SECONDS);
  }

  @Test
  void should_returnEmpty_when_bothKeysAbsent() {
    when(redisTemplate.hasKey(any())).thenReturn(false);

    Optional<ResolvedPermissions> result = adapter.get(TENANT_ID, USER_ID, EPOCH);

    assertThat(result).isEmpty();
  }

  @Test
  void should_returnEmpty_when_onlyRoleKeyPresent() {
    when(redisTemplate.hasKey(eq(ROLE_KEY))).thenReturn(true);
    when(redisTemplate.hasKey(eq(PERM_KEY))).thenReturn(false);

    Optional<ResolvedPermissions> result = adapter.get(TENANT_ID, USER_ID, EPOCH);

    assertThat(result).as("a partial entry must be treated as a full miss").isEmpty();
  }

  @Test
  void should_returnRolesAndPermissions_when_bothKeysPresent() {
    when(redisTemplate.hasKey(any())).thenReturn(true);
    when(redisTemplate.opsForSet()).thenReturn(setOperations);
    when(setOperations.members(ROLE_KEY)).thenReturn(Set.of("TENANT_ADMIN"));
    when(setOperations.members(PERM_KEY)).thenReturn(Set.of("tenant:write", "tenant:read"));

    Optional<ResolvedPermissions> result = adapter.get(TENANT_ID, USER_ID, EPOCH);

    assertThat(result).contains(
        new ResolvedPermissions(List.of("TENANT_ADMIN"), List.of("tenant:read", "tenant:write")));
  }

  @Test
  void should_filterOutEmptyMarker_when_present() {
    when(redisTemplate.hasKey(any())).thenReturn(true);
    when(redisTemplate.opsForSet()).thenReturn(setOperations);
    when(setOperations.members(ROLE_KEY)).thenReturn(Set.of("__EMPTY__"));
    when(setOperations.members(PERM_KEY)).thenReturn(Set.of("__EMPTY__"));

    Optional<ResolvedPermissions> result = adapter.get(TENANT_ID, USER_ID, EPOCH);

    assertThat(result).contains(ResolvedPermissions.empty());
  }

  @Test
  void should_returnEmptyLists_when_membersNull() {
    when(redisTemplate.hasKey(any())).thenReturn(true);
    when(redisTemplate.opsForSet()).thenReturn(setOperations);
    when(setOperations.members(any())).thenReturn(null);

    Optional<ResolvedPermissions> result = adapter.get(TENANT_ID, USER_ID, EPOCH);

    assertThat(result).contains(ResolvedPermissions.empty());
  }

  @Test
  void should_failOpen_when_getThrows() {
    when(redisTemplate.hasKey(any())).thenThrow(new RuntimeException("connection refused"));

    Optional<ResolvedPermissions> result = adapter.get(TENANT_ID, USER_ID, EPOCH);

    assertThat(result).isEmpty();
  }

  @Test
  void should_writeBothSetsAndSetTtl_when_puttingNonEmptyResult() {
    when(redisTemplate.opsForSet()).thenReturn(setOperations);

    adapter.put(TENANT_ID, USER_ID, EPOCH,
        new ResolvedPermissions(List.of("TENANT_ADMIN"), List.of("tenant:read", "tenant:write")));

    verify(setOperations).add(eq(ROLE_KEY), eq("TENANT_ADMIN"));
    verify(setOperations).add(eq(PERM_KEY), eq("tenant:read"), eq("tenant:write"));
    verify(redisTemplate).expire(eq(ROLE_KEY), eq(Duration.ofSeconds(TTL_SECONDS)));
    verify(redisTemplate).expire(eq(PERM_KEY), eq(Duration.ofSeconds(TTL_SECONDS)));
  }

  @Test
  void should_addEmptyMarker_when_puttingEmptyResult() {
    when(redisTemplate.opsForSet()).thenReturn(setOperations);

    adapter.put(TENANT_ID, USER_ID, EPOCH, ResolvedPermissions.empty());

    verify(setOperations).add(eq(ROLE_KEY), eq("__EMPTY__"));
    verify(setOperations).add(eq(PERM_KEY), eq("__EMPTY__"));
  }

  @Test
  void should_deleteBothKeysBeforeWriting_when_putting() {
    when(redisTemplate.opsForSet()).thenReturn(setOperations);

    adapter.put(TENANT_ID, USER_ID, EPOCH, new ResolvedPermissions(List.of(), List.of("user:read")));

    verify(redisTemplate).delete(ROLE_KEY);
    verify(redisTemplate).delete(PERM_KEY);
  }

  @Test
  void should_notThrow_when_putThrows() {
    when(redisTemplate.opsForSet()).thenThrow(new RuntimeException("connection refused"));

    assertThatCode(() -> adapter.put(TENANT_ID, USER_ID, EPOCH,
        new ResolvedPermissions(List.of(), List.of("user:read"))))
        .doesNotThrowAnyException();
  }

  // --- US-018 Decision 17: the entry is keyed by the epoch it was computed under ---

  @Test
  void should_useEpochInBothKeys_when_putAndGet() {
    when(redisTemplate.opsForSet()).thenReturn(setOperations);
    when(redisTemplate.hasKey(anyString()))
        .thenAnswer(invocation -> List.of(ROLE_KEY, PERM_KEY).contains(invocation.getArgument(0)));
    when(setOperations.members(ROLE_KEY)).thenReturn(Set.of("MEMBER"));
    when(setOperations.members(PERM_KEY)).thenReturn(Set.of("user:read"));

    adapter.put(TENANT_ID, USER_ID, EPOCH,
        new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));
    Optional<ResolvedPermissions> result = adapter.get(TENANT_ID, USER_ID, EPOCH);

    verify(setOperations).add(eq(ROLE_KEY), eq("MEMBER"));
    verify(setOperations).add(eq(PERM_KEY), eq("user:read"));
    assertThat(result).contains(new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));
  }

  @Test
  void should_returnEmpty_when_getUnderDifferentEpoch() {
    when(redisTemplate.hasKey(anyString()))
        .thenAnswer(invocation -> List.of(ROLE_KEY, PERM_KEY).contains(invocation.getArgument(0)));

    Optional<ResolvedPermissions> result = adapter.get(TENANT_ID, USER_ID, EPOCH + 1);

    assertThat(result).as("an entry cached under epoch E is a miss under any other epoch").isEmpty();
  }

  // --- eviction: one script per batch of 500, evicting under each user's current epoch ---

  @Test
  void should_evictUnderCurrentEpochWithScript_when_evictingOneUser() {
    adapter.evict(TENANT_ID, USER_ID);

    ArgumentCaptor<List<String>> keys = keysCaptor();
    ArgumentCaptor<Object[]> args = ArgumentCaptor.forClass(Object[].class);
    verify(redisTemplate).execute(any(RedisScript.class), keys.capture(), args.capture());
    assertThat(keys.getValue()).containsExactly(EPOCH_KEY);
    assertThat(args.getValue()).containsExactly(
        KEY_PREFIX + ":rbac:roleset:" + TENANT_ID + ":" + USER_ID + ":",
        KEY_PREFIX + ":rbac:permset:" + TENANT_ID + ":" + USER_ID + ":");
  }

  @Test
  void should_evictInBatchesOf500_when_evictingHolders() {
    List<UUID> holders = users(1001);

    adapter.evict(TENANT_ID, holders);

    ArgumentCaptor<List<String>> keys = keysCaptor();
    ArgumentCaptor<Object[]> args = ArgumentCaptor.forClass(Object[].class);
    verify(redisTemplate, times(3)).execute(any(RedisScript.class), keys.capture(), args.capture());
    assertThat(keys.getAllValues()).extracting(List::size).containsExactly(500, 500, 1);
    assertThat(args.getAllValues()).extracting(a -> a.length).containsExactly(1000, 1000, 2);
    assertThat(keys.getAllValues().get(2))
        .containsExactly(KEY_PREFIX + ":rbac:epoch:" + TENANT_ID + ":" + holders.get(1000));
  }

  @Test
  void should_notCallRedis_when_evictingNoHolders() {
    adapter.evict(TENANT_ID, List.of());

    verify(redisTemplate, times(0)).execute(any(RedisScript.class), anyList(), any(Object[].class));
  }

  @Test
  void should_stopEvictingAndWarnOnce_when_evictBatchFails() {
    when(redisTemplate.execute(any(RedisScript.class), anyList(), any(Object[].class)))
        .thenReturn(500L)
        .thenThrow(new QueryTimeoutException("timeout"));
    ListAppender<ILoggingEvent> appender = startLogCapture();
    try {
      assertThatCode(() -> adapter.evict(TENANT_ID, users(1001))).doesNotThrowAnyException();
    } finally {
      stopLogCapture(appender);
    }

    verify(redisTemplate, times(2)).execute(any(RedisScript.class), anyList(), any(Object[].class));
    assertThat(appender.list).singleElement().satisfies(event -> {
      assertThat(event.getLevel()).isEqualTo(Level.WARN);
      assertThat(event.getFormattedMessage())
          .contains("RBAC_PERMISSION_CACHE_UNAVAILABLE")
          .contains("operation=evict")
          .contains("unevictedUsers=501")
          .doesNotContain(TENANT_ID.toString());
    });
  }

  @Test
  void should_notThrow_when_evictThrows() {
    when(redisTemplate.execute(any(RedisScript.class), anyList(), any(Object[].class)))
        .thenThrow(new RuntimeException("connection refused"));

    assertThatCode(() -> adapter.evict(TENANT_ID, USER_ID)).doesNotThrowAnyException();
  }

  private static List<UUID> users(int count) {
    return IntStream.range(0, count).mapToObj(i -> UUID.randomUUID()).toList();
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static ArgumentCaptor<List<String>> keysCaptor() {
    return (ArgumentCaptor) ArgumentCaptor.forClass(List.class);
  }

  private static ListAppender<ILoggingEvent> startLogCapture() {
    Logger logger = (Logger) LoggerFactory.getLogger(RedisPermissionCacheAdapter.class);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void stopLogCapture(ListAppender<ILoggingEvent> appender) {
    ((Logger) LoggerFactory.getLogger(RedisPermissionCacheAdapter.class)).detachAppender(appender);
    appender.stop();
  }
}
