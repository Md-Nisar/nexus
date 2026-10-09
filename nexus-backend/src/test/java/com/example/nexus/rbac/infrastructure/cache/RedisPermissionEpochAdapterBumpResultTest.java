package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.infrastructure.cache.EpochRedisConfig.EpochTemplates;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.dao.InvalidDataAccessResourceUsageException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;

/**
 * L-1: the script has already applied the whole batch when Java reads its result, so one value
 * that does not parse must never fail the batch (a failed batch is replayed, and a replay of an
 * applied batch bumps every user again).
 */
@Tag("UnitTest")
class RedisPermissionEpochAdapterBumpResultTest {

  private static final UUID TENANT = UUID.fromString("00000000-0000-7000-8000-0000000000aa");
  private static final UUID FIRST = UUID.fromString("00000000-0000-7000-8000-0000000000b1");
  private static final UUID SECOND = UUID.fromString("00000000-0000-7000-8000-0000000000b2");

  private final EpochTemplates templates = mock(EpochTemplates.class);
  private final StringRedisTemplate bump = mock(StringRedisTemplate.class);
  private final RedisPermissionEpochAdapter adapter =
      new RedisPermissionEpochAdapter(templates, "nexus-test", 960L);

  private void scriptReturns(List<String> result) {
    when(templates.bumpReady()).thenReturn(true);
    when(templates.bump()).thenReturn(bump);
    when(bump.execute(any(RedisScript.class), anyList(), any(Object[].class))).thenReturn(result);
  }

  @Test
  void should_omitOnlyTheUnparseableUser_when_oneResultValueIsNotAnEpoch() {
    scriptReturns(List.of("nan", "1760000000000"));

    Map<UUID, Long> written = adapter.bump(TENANT, List.of(FIRST, SECOND));

    assertThat(written).containsOnlyKeys(SECOND).containsEntry(SECOND, 1_760_000_000_000L);
  }

  @Test
  void should_omitUser_when_resultValueAboveCeiling() {
    scriptReturns(List.of("9223372036854775807", "5"));

    Map<UUID, Long> written = adapter.bump(TENANT, List.of(FIRST, SECOND));

    assertThat(written).containsOnlyKeys(SECOND);
  }

  @Test
  void should_throw_when_resultSizeDiffersFromBatch() {
    scriptReturns(List.of("5"));

    assertThatThrownBy(() -> adapter.bump(TENANT, List.of(FIRST, SECOND)))
        .isInstanceOf(InvalidDataAccessResourceUsageException.class);
  }
}
