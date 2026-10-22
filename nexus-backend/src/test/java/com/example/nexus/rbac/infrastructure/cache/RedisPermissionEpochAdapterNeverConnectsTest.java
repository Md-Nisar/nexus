package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.infrastructure.cache.EpochRedisConfig.EpochTemplates;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;

/**
 * Deterministic form of the H-1 rule (design §9.5): while a template's connection has not been
 * opened off-thread, the adapter never touches that template, so no request thread can open the
 * first connection. The wall-clock bounds in {@link RedisPermissionEpochAdapterNotReadyTest}
 * depend on JVM warm-up; this one does not.
 */
@Tag("UnitTest")
class RedisPermissionEpochAdapterNeverConnectsTest {

  private final EpochTemplates templates = mock(EpochTemplates.class);
  private final RedisPermissionEpochAdapter adapter =
      new RedisPermissionEpochAdapter(templates, "nexus-test", 960L);

  @Test
  void should_notTouchReadTemplate_when_currentCalledBeforeReadConnectionReady() {
    when(templates.readReady()).thenReturn(false);

    assertThat(adapter.current(UUID.randomUUID(), UUID.randomUUID())).isEmpty();

    verify(templates, never()).read();
  }

  @Test
  void should_notTouchReadTemplate_when_probeCalledBeforeReadConnectionReady() {
    when(templates.readReady()).thenReturn(false);

    assertThat(adapter.probe()).isFalse();

    verify(templates, never()).read();
  }

  @Test
  void should_notTouchBumpTemplate_when_bumpCalledBeforeBumpConnectionReady() {
    when(templates.bumpReady()).thenReturn(false);

    assertThatThrownBy(() -> adapter.bump(UUID.randomUUID(), List.of(UUID.randomUUID())))
        .isInstanceOf(RedisConnectionFailureException.class);

    verify(templates, never()).bump();
  }

  @Test
  void should_notUseReadTemplate_when_onlyBumpConnectionIsReady() {
    when(templates.readReady()).thenReturn(false);
    when(templates.bumpReady()).thenReturn(true);

    assertThat(adapter.current(UUID.randomUUID(), UUID.randomUUID())).isEmpty();

    verify(templates, never()).read();
  }
}
