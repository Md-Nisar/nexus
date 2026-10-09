package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.infrastructure.cache.EpochRedisConfig.EpochTemplates;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

/** The probe answers {@code false} for any failure, so the scheduler tick never dies (N-3). */
@Tag("UnitTest")
class RedisPermissionEpochAdapterProbeTest {

  private final EpochTemplates templates = mock(EpochTemplates.class);
  private final StringRedisTemplate read = mock(StringRedisTemplate.class);
  private final RedisPermissionEpochAdapter adapter =
      new RedisPermissionEpochAdapter(templates, "nexus-test", 960L);

  @Test
  void should_returnFalse_when_probeThrowsUnexpectedRuntimeException() {
    when(templates.readReady()).thenReturn(true);
    when(templates.read()).thenReturn(read);
    when(read.execute(any(RedisCallback.class))).thenThrow(new IllegalStateException("closed"));

    assertThat(adapter.probe()).isFalse();
  }

  @Test
  void should_returnTrue_when_probeAnswers() {
    when(templates.readReady()).thenReturn(true);
    when(templates.read()).thenReturn(read);
    when(read.execute(any(RedisCallback.class))).thenReturn("PONG");

    assertThat(adapter.probe()).isTrue();
  }
}
