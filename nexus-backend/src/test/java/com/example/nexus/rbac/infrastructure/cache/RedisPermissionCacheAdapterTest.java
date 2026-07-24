package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.domain.ResolvedPermissions;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Unit coverage for {@link RedisPermissionCacheAdapter}'s detection/serialization logic and
 * fail-open behavior, in isolation from a real Redis instance (mocked {@link StringRedisTemplate}
 * stack). Live-Redis round-trip coverage lives in {@link RedisPermissionCacheAdapterIT}.
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class RedisPermissionCacheAdapterTest {

  private static final String KEY_PREFIX = "nexus-test";
  private static final long TTL_SECONDS = 900L;
  private static final UUID TENANT_ID = UUID.randomUUID();
  private static final UUID USER_ID = UUID.randomUUID();
  private static final String ROLE_KEY =
      KEY_PREFIX + ":rbac:roleset:" + TENANT_ID + ":" + USER_ID;
  private static final String PERM_KEY =
      KEY_PREFIX + ":rbac:permset:" + TENANT_ID + ":" + USER_ID;

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

    Optional<ResolvedPermissions> result = adapter.get(TENANT_ID, USER_ID);

    assertThat(result).isEmpty();
  }

  @Test
  void should_returnEmpty_when_onlyRoleKeyPresent() {
    when(redisTemplate.hasKey(eq(ROLE_KEY))).thenReturn(true);
    when(redisTemplate.hasKey(eq(PERM_KEY))).thenReturn(false);

    Optional<ResolvedPermissions> result = adapter.get(TENANT_ID, USER_ID);

    assertThat(result).as("a partial entry must be treated as a full miss").isEmpty();
  }

  @Test
  void should_returnRolesAndPermissions_when_bothKeysPresent() {
    when(redisTemplate.hasKey(any())).thenReturn(true);
    when(redisTemplate.opsForSet()).thenReturn(setOperations);
    when(setOperations.members(ROLE_KEY)).thenReturn(Set.of("TENANT_ADMIN"));
    when(setOperations.members(PERM_KEY)).thenReturn(Set.of("tenant:write", "tenant:read"));

    Optional<ResolvedPermissions> result = adapter.get(TENANT_ID, USER_ID);

    assertThat(result).contains(
        new ResolvedPermissions(List.of("TENANT_ADMIN"), List.of("tenant:read", "tenant:write")));
  }

  @Test
  void should_filterOutEmptyMarker_when_present() {
    when(redisTemplate.hasKey(any())).thenReturn(true);
    when(redisTemplate.opsForSet()).thenReturn(setOperations);
    when(setOperations.members(ROLE_KEY)).thenReturn(Set.of("__EMPTY__"));
    when(setOperations.members(PERM_KEY)).thenReturn(Set.of("__EMPTY__"));

    Optional<ResolvedPermissions> result = adapter.get(TENANT_ID, USER_ID);

    assertThat(result).contains(ResolvedPermissions.empty());
  }

  @Test
  void should_returnEmptyLists_when_membersNull() {
    when(redisTemplate.hasKey(any())).thenReturn(true);
    when(redisTemplate.opsForSet()).thenReturn(setOperations);
    when(setOperations.members(any())).thenReturn(null);

    Optional<ResolvedPermissions> result = adapter.get(TENANT_ID, USER_ID);

    assertThat(result).contains(ResolvedPermissions.empty());
  }

  @Test
  void should_failOpen_when_getThrows() {
    when(redisTemplate.hasKey(any())).thenThrow(new RuntimeException("connection refused"));

    Optional<ResolvedPermissions> result = adapter.get(TENANT_ID, USER_ID);

    assertThat(result).isEmpty();
  }

  @Test
  void should_writeBothSetsAndSetTtl_when_puttingNonEmptyResult() {
    when(redisTemplate.opsForSet()).thenReturn(setOperations);

    adapter.put(TENANT_ID, USER_ID,
        new ResolvedPermissions(List.of("TENANT_ADMIN"), List.of("tenant:read", "tenant:write")));

    verify(setOperations).add(eq(ROLE_KEY), eq("TENANT_ADMIN"));
    verify(setOperations).add(eq(PERM_KEY), eq("tenant:read"), eq("tenant:write"));
    verify(redisTemplate).expire(eq(ROLE_KEY), eq(Duration.ofSeconds(TTL_SECONDS)));
    verify(redisTemplate).expire(eq(PERM_KEY), eq(Duration.ofSeconds(TTL_SECONDS)));
  }

  @Test
  void should_addEmptyMarker_when_puttingEmptyResult() {
    when(redisTemplate.opsForSet()).thenReturn(setOperations);

    adapter.put(TENANT_ID, USER_ID, ResolvedPermissions.empty());

    verify(setOperations).add(eq(ROLE_KEY), eq("__EMPTY__"));
    verify(setOperations).add(eq(PERM_KEY), eq("__EMPTY__"));
  }

  @Test
  void should_deleteBothKeysBeforeWriting_when_putting() {
    when(redisTemplate.opsForSet()).thenReturn(setOperations);

    adapter.put(TENANT_ID, USER_ID, new ResolvedPermissions(List.of(), List.of("user:read")));

    verify(redisTemplate).delete(ROLE_KEY);
    verify(redisTemplate).delete(PERM_KEY);
  }

  @Test
  void should_notThrow_when_putThrows() {
    when(redisTemplate.opsForSet()).thenThrow(new RuntimeException("connection refused"));

    assertThatCode(() -> adapter.put(TENANT_ID, USER_ID,
        new ResolvedPermissions(List.of(), List.of("user:read"))))
        .doesNotThrowAnyException();
  }

  @Test
  void should_deleteBothKeys_when_evicted() {
    adapter.evict(TENANT_ID, USER_ID);

    verify(redisTemplate).delete(ROLE_KEY);
    verify(redisTemplate).delete(PERM_KEY);
  }

  @Test
  void should_notThrow_when_evictThrows() {
    when(redisTemplate.delete((String) any())).thenThrow(new RuntimeException("connection refused"));

    assertThatCode(() -> adapter.evict(TENANT_ID, USER_ID)).doesNotThrowAnyException();
  }
}
