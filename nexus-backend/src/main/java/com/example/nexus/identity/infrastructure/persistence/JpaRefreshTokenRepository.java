package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.domain.RefreshToken;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * Spring Data JPA repository for {@link RefreshToken}.
 * Bulk revocation queries target only active tokens ({@code revokedAt IS NULL}) to
 * support idempotent calls and the theft-detection family revocation pattern (T-4.2).
 */
public interface JpaRefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

  Optional<RefreshToken> findByTokenHash(String tokenHash);

  @Modifying(clearAutomatically = true)
  @Transactional
  @Query("UPDATE RefreshToken r SET r.revokedAt = :revokedAt "
      + "WHERE r.familyId = :familyId AND r.revokedAt IS NULL")
  void revokeByFamilyId(@Param("familyId") UUID familyId, @Param("revokedAt") Instant revokedAt);

  @Modifying(clearAutomatically = true)
  @Transactional
  @Query("UPDATE RefreshToken r SET r.revokedAt = :revokedAt "
      + "WHERE r.userId = :userId AND r.revokedAt IS NULL")
  void revokeByUserId(@Param("userId") UUID userId, @Param("revokedAt") Instant revokedAt);
}
