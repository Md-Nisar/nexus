package com.example.nexus.rbac.application.port.out;

import com.example.nexus.rbac.domain.ResolvedPermissions;
import java.util.Optional;
import java.util.UUID;

/**
 * Cache-aside port for a user's resolved roles/permissions (ADR 0016 D3/D4).
 *
 * <p>The cached payload includes {@code roles} alongside {@code permissions} — not merely as a
 * convenience, but because {@link com.example.nexus.rbac.application.RoleResolutionService} uses
 * the cached role set as a freshness fingerprint: role names are always re-read live (a cheap
 * indexed join, run only at login/refresh, never per API request), and a cache hit whose {@code
 * roles} no longer match the live read is treated as stale and recomputed. This closes the gap
 * where a role assignment made after a cache warm would otherwise go unnoticed until the 15-min
 * TTL expires or US-012 wires up write-path eviction (US-010 AC6 — token refresh must reflect a
 * role change on the very next refresh, not just eventually).
 *
 * <p>The cache is never authoritative: a miss or adapter failure must always fall back to a DB
 * read (fail open), MySQL remains the source of truth.
 */
public interface PermissionCachePort {

  /** Returns the cached roles/permissions for this tenant+user, or empty on a miss. */
  Optional<ResolvedPermissions> get(UUID tenantId, UUID userId);

  /** Warms the cache with a freshly-resolved result (TTL applied by the adapter). */
  void put(UUID tenantId, UUID userId, ResolvedPermissions resolved);

  /**
   * Invalidates the cached entry for this tenant+user. Unused until US-012 (role
   * assignment/revocation) — implemented now per ADR 0016's already-fixed port contract to avoid
   * a breaking interface change later.
   */
  void evict(UUID tenantId, UUID userId);
}
