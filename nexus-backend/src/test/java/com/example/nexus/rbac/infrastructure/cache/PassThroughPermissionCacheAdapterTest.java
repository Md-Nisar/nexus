package com.example.nexus.rbac.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.rbac.domain.ResolvedPermissions;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

@Tag("UnitTest")
class PassThroughPermissionCacheAdapterTest {

  private final UUID tenantId = UUID.randomUUID();
  private final UUID userId = UUID.randomUUID();

  @Test
  void should_neverReturnACachedSet_when_aSetWasPutUnderTheSameEpoch() {
    PassThroughPermissionCacheAdapter adapter =
        new PassThroughPermissionCacheAdapter(new MockEnvironment());

    adapter.put(tenantId, userId, 3L, new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));

    assertThat(adapter.get(tenantId, userId, 3L)).isEmpty();
  }

  @Test
  void should_acceptEvictions_when_nothingIsCached() {
    PassThroughPermissionCacheAdapter adapter =
        new PassThroughPermissionCacheAdapter(new MockEnvironment());

    adapter.evict(tenantId, userId);
    adapter.evict(tenantId, List.of(userId));

    assertThat(adapter.get(tenantId, userId, 0L)).isEmpty();
  }

  @Test
  void should_refuseToStart_when_prodProfileIsActive() {
    MockEnvironment prod = new MockEnvironment();
    prod.setActiveProfiles("prod");

    assertThatThrownBy(() -> new PassThroughPermissionCacheAdapter(prod).refuseUnderProd())
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("nexus.rbac.permission-cache.bypass");
  }
}
