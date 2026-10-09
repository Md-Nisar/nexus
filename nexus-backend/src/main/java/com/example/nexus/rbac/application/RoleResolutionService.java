package com.example.nexus.rbac.application;

import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.application.port.out.UserRoleQueryPort;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Resolves a user's active, tenant-scoped roles and permissions (US-010) — the single source
 * consulted at JWT-mint time (login/refresh) and never per protected-API-request (ADR 0013 D1;
 * enforcement in US-011 reads the JWT's own {@code permissions[]} claim, not this service).
 *
 * <p>Role names are always re-derived from the DB (a cheap single indexed join) — never taken
 * from the cache. That live role read doubles as a freshness fingerprint for the cached
 * permission set (ADR 0016 D3/D4): a cache hit whose cached {@code roles} no longer match the
 * live-read role set is treated as stale and recomputed from the DB immediately, rather than
 * waiting out the 15-min TTL. This guarantees a role assignment/revocation is reflected on the very
 * next resolution — login or refresh — with zero lag (US-010 AC6), while still caching the common
 * case (role set unchanged between calls).
 *
 * <p>A role's own permission set changing without any role (re-)assignment is not visible to that
 * fingerprint. It is covered by the permission epoch instead (US-018 Decision 17, design §9.4):
 * the cache entry is read and written under the epoch the minter read <i>before</i> calling this
 * service, and a detach bumps every holder's epoch, so a stale set written back by a mint that
 * raced the detach sits under the old epoch and is never read again. An attach evicts every
 * holder's entry without a bump (Decision 15). Only an out-of-band change (SQL or a migration)
 * still waits out the TTL.
 */
@Service
@Transactional(readOnly = true)
public class RoleResolutionService {

  private final UserRoleQueryPort userRoleQueryPort;
  private final PermissionCachePort permissionCachePort;

  public RoleResolutionService(
      UserRoleQueryPort userRoleQueryPort, PermissionCachePort permissionCachePort) {
    this.userRoleQueryPort = userRoleQueryPort;
    this.permissionCachePort = permissionCachePort;
  }

  /**
   * Resolves the active roles and deduplicated union of permissions for {@code userId} within
   * {@code tenantId}. {@code tenantId} must be sourced by the caller exclusively from the
   * authenticated user's own {@code tenant_id} (never a default/bootstrap sentinel) — this
   * service performs no tenant resolution or fallback of its own (US-010 AC9).
   *
   * @param epoch the permission epoch the caller read before this call (MC-7a); the cache entry is
   *     read and written under it
   * @throws NullPointerException if either identifier is null — fails closed rather than
   *     resolving against an unscoped/default tenant
   */
  public ResolvedPermissions resolve(UUID userId, UUID tenantId, long epoch) {
    Objects.requireNonNull(userId, "userId must not be null");
    Objects.requireNonNull(tenantId, "tenantId must not be null");

    List<String> liveRoles = userRoleQueryPort.findActiveRoleNames(userId, tenantId);

    Optional<ResolvedPermissions> cached = permissionCachePort.get(tenantId, userId, epoch);
    if (cached.isPresent() && sameRoles(cached.get().roles(), liveRoles)) {
      return cached.get();
    }

    List<String> livePermissions = userRoleQueryPort.findActivePermissionNames(userId, tenantId);
    ResolvedPermissions resolved = new ResolvedPermissions(liveRoles, livePermissions);
    permissionCachePort.put(tenantId, userId, epoch, resolved);
    return resolved;
  }

  /**
   * Resolves like {@link #resolve} but reads the database only: nothing is read from or written to
   * the permission cache. For a mint whose epoch the store did not confirm (L-3): the cache key
   * under such an epoch is one no bump deletes, so a set cached there could outlive a detach.
   *
   * @throws NullPointerException if either identifier is null
   */
  public ResolvedPermissions resolveUncached(UUID userId, UUID tenantId) {
    Objects.requireNonNull(userId, "userId must not be null");
    Objects.requireNonNull(tenantId, "tenantId must not be null");
    return new ResolvedPermissions(
        userRoleQueryPort.findActiveRoleNames(userId, tenantId),
        userRoleQueryPort.findActivePermissionNames(userId, tenantId));
  }

  /** Order-independent comparison — both inputs are deduplicated by {@link ResolvedPermissions}. */
  private boolean sameRoles(List<String> cachedRoles, List<String> liveRoles) {
    Set<String> cachedSet = new HashSet<>(cachedRoles);
    Set<String> liveSet = new HashSet<>(liveRoles);
    return cachedSet.equals(liveSet);
  }
}
