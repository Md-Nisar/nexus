package com.example.nexus.rbac.application.port.out;

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
   * Deduplicated names of every permission granted (via {@code role_permissions}) by any active
   * role held by a user within a tenant.
   */
  List<String> findActivePermissionNames(UUID userId, UUID tenantId);
}
