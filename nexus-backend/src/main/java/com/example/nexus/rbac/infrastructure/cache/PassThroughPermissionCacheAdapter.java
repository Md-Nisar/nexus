package com.example.nexus.rbac.infrastructure.cache;

import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

/**
 * Benchmark bypass for the B6 decision (US-018 T-023, design §10.6): replaces {@link
 * RedisPermissionCacheAdapter} when {@value #BYPASS_PROPERTY} is {@code true}, so the same build
 * can run the refresh benchmark with the permission cache on and off. It never stores and never
 * returns a cached set, so every mint reads MySQL, which is the source of truth either way.
 *
 * <p><b>Test-only.</b> The property is {@code false} by default and the bean refuses to start under
 * the {@code prod} profile, so a stray setting cannot silently remove the cache from production.
 * The class is kept only while the cache is kept; if the benchmark's rule removes the cache, it is
 * deleted together with {@link PermissionCachePort} and {@link RedisPermissionCacheAdapter}.
 */
@Component
@ConditionalOnProperty(name = PassThroughPermissionCacheAdapter.BYPASS_PROPERTY, havingValue = "true")
public class PassThroughPermissionCacheAdapter implements PermissionCachePort {

  static final String BYPASS_PROPERTY = "nexus.rbac.permission-cache.bypass";

  public PassThroughPermissionCacheAdapter(Environment environment) {
    if (environment.acceptsProfiles(Profiles.of("prod"))) {
      throw new IllegalStateException(
          BYPASS_PROPERTY + " is a benchmark-only switch and must not be set under the prod profile");
    }
  }

  @Override
  public Optional<ResolvedPermissions> get(UUID tenantId, UUID userId, long epoch) {
    return Optional.empty();
  }

  @Override
  public void put(UUID tenantId, UUID userId, long epoch, ResolvedPermissions resolved) {
    // Deliberately stores nothing.
  }

  @Override
  public void evict(UUID tenantId, UUID userId) {
    // Nothing is cached, so there is nothing to evict.
  }

  @Override
  public void evict(UUID tenantId, Collection<UUID> userIds) {
    // Nothing is cached, so there is nothing to evict.
  }
}
