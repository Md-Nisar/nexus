package com.example.nexus.rbac.application.port.out;

import com.example.nexus.rbac.domain.PermissionViaRole;
import com.example.nexus.rbac.domain.RoleRef;
import java.util.List;
import java.util.UUID;

/**
 * Read port over a user's active (non-revoked) role/permission assignments.
 *
 * <p>Implementations live in {@code rbac.infrastructure.persistence} — the domain and
 * application layers depend only on this interface (hexagonal architecture, ADR-0002).
 */
public interface UserRoleQueryPort {

  /** Names of all active roles assigned to a user within a tenant. */
  List<String> findActiveRoleNames(UUID userId, UUID tenantId);

  /**
   * US-019 B4 — the live roles a user actively holds within a tenant, ordered by name then id.
   * Soft-deleted roles and revoked assignments are excluded.
   */
  List<RoleRef> findActiveRoles(UUID userId, UUID tenantId);

  /**
   * Deduplicated names of every permission granted (via {@code role_permissions}) by any active
   * role held by a user within a tenant.
   */
  List<String> findActivePermissionNames(UUID userId, UUID tenantId);

  /**
   * C3 (US-018 T-029) — every {@code (permission name, role id)} pair a user holds through active
   * assignments of live roles within a tenant, from one statement, ordered by name then role id.
   * The access-review effective-permissions read groups it by name.
   */
  List<PermissionViaRole> findActivePermissionsViaRoles(UUID userId, UUID tenantId);
}
