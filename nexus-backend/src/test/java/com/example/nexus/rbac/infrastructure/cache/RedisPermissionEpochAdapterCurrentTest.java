package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.application.port.out.EpochUnparseableException;
import com.example.nexus.rbac.infrastructure.cache.EpochRedisConfig.EpochTemplates;
import io.lettuce.core.RedisCommandTimeoutException;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

/**
 * Unit tests verifying that {@link RedisPermissionEpochAdapter#current(UUID, UUID)} catches any
 * driver or Spring RuntimeException and safely returns empty to drive the degraded state machine (OR-06).
 */
@Tag("UnitTest")
class RedisPermissionEpochAdapterCurrentTest {

  private static final UUID TENANT_ID = UUID.randomUUID();
  private static final UUID USER_ID = UUID.randomUUID();

  private final EpochTemplates templates = mock(EpochTemplates.class);
  private final StringRedisTemplate readTemplate = mock(StringRedisTemplate.class);
  @SuppressWarnings("unchecked")
  private final ValueOperations<String, String> valueOperations = mock(ValueOperations.class);

  private final RedisPermissionEpochAdapter adapter =
      new RedisPermissionEpochAdapter(templates, "nexus-test", 960L);

  @BeforeEach
  void setUp() {
    when(templates.readReady()).thenReturn(true);
    when(templates.read()).thenReturn(readTemplate);
    when(readTemplate.opsForValue()).thenReturn(valueOperations);
  }

  @Test
  void should_returnEmpty_when_readNotReady() {
    when(templates.readReady()).thenReturn(false);

    assertThat(adapter.current(TENANT_ID, USER_ID)).isEmpty();
  }

  @Test
  void should_returnEmpty_when_readThrowsDataAccessException() {
    when(valueOperations.get(anyString())).thenThrow(new QueryTimeoutException("Redis query timeout"));

    assertThat(adapter.current(TENANT_ID, USER_ID)).isEmpty();
  }

  @Test
  void should_returnEmpty_when_readThrowsLettuceDriverException() {
    when(valueOperations.get(anyString())).thenThrow(new RedisCommandTimeoutException("Lettuce timeout"));

    assertThat(adapter.current(TENANT_ID, USER_ID)).isEmpty();
  }

  @Test
  void should_returnEmpty_when_readThrowsUnexpectedRuntimeException() {
    when(valueOperations.get(anyString())).thenThrow(new IllegalStateException("Connection pool closed"));

    assertThat(adapter.current(TENANT_ID, USER_ID)).isEmpty();
  }

  @Test
  void should_returnZero_when_valueIsNull() {
    when(valueOperations.get(anyString())).thenReturn(null);

    assertThat(adapter.current(TENANT_ID, USER_ID)).hasValue(0L);
  }

  @Test
  void should_returnParsedEpoch_when_valueIsValidNumericString() {
    when(valueOperations.get(anyString())).thenReturn("1729900000000");

    assertThat(adapter.current(TENANT_ID, USER_ID)).hasValue(1729900000000L);
  }

  @Test
  void should_throwEpochUnparseableException_when_valueIsCorruptedNonDigit() {
    when(valueOperations.get(anyString())).thenReturn("corrupted-not-numeric");

    assertThatThrownBy(() -> adapter.current(TENANT_ID, USER_ID))
        .isInstanceOf(EpochUnparseableException.class);
  }
}
