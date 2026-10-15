package com.example.nexus.rbac.application.port.out;

import java.util.Collection;
import java.util.Map;
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
   * The user's tenant and {@code ACTIVE}-ness, or empty when no such user exists (US-018 A7, the
   * break-glass target lookup). A plain, non-locking read.
   */
  Optional<DirectoryUser> findUser(UUID userId);

  /**
   * US-018 A7 (O-7, L-2): the current status of each user in {@code userIds} that belongs to
   * {@code tenantId}, read by ONE locking statement ({@code FOR SHARE}) that takes the {@code
   * users} row locks in ascending primary-key order. A locking read returns the latest committed
   * status, not the transaction's snapshot, and holds the rows until the caller's transaction
   * ends, so a concurrent status change either is seen or waits. A user that is not found in the
   * tenant is absent from the map.
   *
   * <p>Used only by the break-glass grant, inside its transaction and after the set lock. Must be
   * called inside an active transaction, with a non-empty {@code userIds}.
   */
  Map<UUID, DirectoryUserStatus> lockUserStatuses(UUID tenantId, Collection<UUID> userIds);
}
