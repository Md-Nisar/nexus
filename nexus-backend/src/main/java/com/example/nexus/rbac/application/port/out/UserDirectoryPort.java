package com.example.nexus.rbac.application.port.out;

import java.util.Optional;
import java.util.UUID;

/**
 * Minimal read-only view of the identity context needed by {@code rbac} (03-design.md §4.4).
 * Implemented by {@code identity.infrastructure.persistence.JpaUserDirectoryAdapter} — {@code
 * rbac} never imports {@code identity} (ArchUnit-enforced).
 */
public interface UserDirectoryPort {

  /**
   * The owning tenant of a user, or empty when no such user exists. Empty maps to a 404; a
   * non-matching value (versus the caller's own tenant) maps to a 403.
   */
  Optional<UUID> findTenantId(UUID userId);

  /**
   * The owning tenant and whether the account is {@code ACTIVE}, or empty when no such user exists
   * (US-018 A7: the break-glass CLI refuses a missing or non-ACTIVE target). {@code rbac} sees only
   * the boolean, never {@code identity}'s status enum.
   */
  Optional<DirectoryUser> findDirectoryUser(UUID userId);

  /** A user's tenant and whether the account is ACTIVE. */
  record DirectoryUser(UUID tenantId, boolean active) {}
}
