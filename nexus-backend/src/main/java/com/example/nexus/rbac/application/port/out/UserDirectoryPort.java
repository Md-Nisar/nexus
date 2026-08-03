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
}
