package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.domain.User;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/** Spring Data JPA repository for the {@link User} aggregate. */
public interface JpaUserRepository extends JpaRepository<User, UUID> {

  /**
   * Looks up a user by tenant and pre-computed email blind index.
   *
   * <p>Served by the {@code uq_users_tenant_id_email_hmac} UNIQUE index. Callers must compute the
   * {@code emailHmac} argument via {@code EmailBlindIndexService.blindIndex()} using the same
   * normalization contract.
   *
   * @param tenantId  the tenant identifier
   * @param emailHmac the HMAC-SHA256 blind index of the email address
   * @return the matching user, or empty if not found
   */
  Optional<User> findByTenantIdAndEmailHmac(UUID tenantId, String emailHmac);

  /**
   * Resets the failure counter and clears the lockout timestamp directly via a bulk UPDATE,
   * intentionally bypassing the {@code @Version} optimistic-lock check.
   *
   * <p>This is the safe path for the REQUIRES_NEW {@code persistResetAttempts} boundary: if the
   * caller's outer transaction has already mutated the same entity in its session (e.g. via
   * {@link User#unlockIfExpired}), a JPA save in REQUIRES_NEW would increment {@code version} to
   * V+1 and the outer session would then fail to flush at version V (M-OL-1). A JPQL bulk UPDATE
   * leaves {@code version} unchanged so the outer session can flush normally.
   *
   * @param userId the user whose failed attempts and lockout should be cleared
   * @return the number of rows updated (0 or 1)
   */
  @Modifying(clearAutomatically = true)
  @Query("UPDATE User u SET u.failedAttemptCount = 0, u.lockedUntil = null WHERE u.id = :userId")
  int resetFailedAttemptsDirect(@Param("userId") UUID userId);

  /**
   * US-018 A7 (O-7, L-2): the id and status of each listed user of one tenant, as a locking read
   * ({@code FOR SHARE}) for the break-glass grant transaction. Backs {@code
   * UserDirectoryPort#lockUserStatuses}.
   *
   * <p>Native, so the lock is rendered directly (Spring Data JPA does not combine {@code @Lock}
   * with {@code nativeQuery = true}) and the plan is pinned: {@code FORCE INDEX (PRIMARY)} keeps
   * the scan, and therefore the locks, on the listed primary keys in ascending order, never on
   * {@code idx_users_tenant_id_status} (which would lock the tenant's whole status range). {@code
   * tenant_id} is a residual predicate. A projection, not an entity, so no managed {@link User}
   * from an earlier read in the same persistence context can hide the locked row's current status.
   * Bind parameters are {@code byte[]}, like the other native locking reads.
   */
  @Query(
      value =
          """
          SELECT id, status FROM users FORCE INDEX (PRIMARY)
          WHERE id IN (:userIds) AND tenant_id = :tenantId
          ORDER BY id
          FOR SHARE
          """,
      nativeQuery = true)
  List<UserStatusRow> lockStatusesByIds(
      @Param("userIds") Collection<byte[]> userIds, @Param("tenantId") byte[] tenantId);

  /** Row of {@link #lockStatusesByIds}: the user id as {@code BINARY(16)} and the status name. */
  interface UserStatusRow {
    byte[] getId();

    String getStatus();
  }
}
