package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.domain.User;
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
}
