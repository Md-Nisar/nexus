package com.example.nexus.rbac.application.port.out;

import java.util.Collection;
import java.util.OptionalLong;
import java.util.UUID;

/**
 * Store of the per-user permission epoch (US-018 A9, design §9.1, §9.2). An access token carries
 * the epoch read when it was minted; a request whose token epoch is lower than the stored one is
 * stale.
 *
 * <p>Redis is the only implementation (ADR 0016). The epoch is never derived from an application
 * instance's clock.
 */
public interface PermissionEpochPort {

  /**
   * Reads the current epoch of a user.
   *
   * @param tenantId the user's tenant
   * @param userId the user
   * @return the stored epoch, {@code 0} when no epoch is stored (no recent revocation), or empty
   *     when the store could not answer in time
   */
  OptionalLong current(UUID tenantId, UUID userId);

  /**
   * Raises the epoch of every given user to {@code max(old + 1, store time in ms)} and refreshes
   * the key TTL.
   *
   * @param tenantId the users' tenant
   * @param userIds the users whose tokens become stale
   * @throws org.springframework.dao.DataAccessException if the store fails or times out
   */
  void bump(UUID tenantId, Collection<UUID> userIds);
}
