package com.example.nexus.rbac.application.port.out;

import com.example.nexus.rbac.domain.ResolvedPermissions;
import java.util.Collection;
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
 * TTL expires (US-010 AC6 — token refresh must reflect a role change on the very next refresh,
 * not just eventually).
 *
 * <p><b>Entries are keyed by permission epoch</b> (US-018 Decision 17, design §9.4): an entry is
 * written and read under the epoch the minter read <i>before</i> resolving permissions. A detach
 * bumps every holder's epoch, so a stale set written back by a mint that raced the detach lands
 * under the old epoch, and every later mint misses it.
 *
 * <p>The cache is never authoritative: a miss or adapter failure must always fall back to a DB
 * read (fail open), MySQL remains the source of truth.
 */
public interface PermissionCachePort {

  /** Returns the roles/permissions cached for this tenant+user under {@code epoch}, or empty. */
  Optional<ResolvedPermissions> get(UUID tenantId, UUID userId, long epoch);

  /** Caches a freshly-resolved result under {@code epoch} (TTL applied by the adapter). */
  void put(UUID tenantId, UUID userId, long epoch, ResolvedPermissions resolved);

  /** Evicts this tenant+user's entry under the user's current epoch. Never changes the epoch. */
  void evict(UUID tenantId, UUID userId);

  /**
   * Evicts the entry of every given user under that user's current epoch, in batches. Never
   * changes an epoch: attach and assign only add permissions, so they evict without bumping
   * (Decision 15). Fails open; a failed batch ends the eviction.
   */
  void evict(UUID tenantId, Collection<UUID> userIds);
}
