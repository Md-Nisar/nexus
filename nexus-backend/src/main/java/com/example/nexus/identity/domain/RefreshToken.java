package com.example.nexus.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.UUID;
import lombok.Getter;
import lombok.NoArgsConstructor;


/**
 * Long-lived refresh token associated with a user session; grouped by {@code familyId} for rotation.
 */
@Entity
@Table(name = "refresh_tokens")
@Getter
@NoArgsConstructor(access = lombok.AccessLevel.PROTECTED)
public class RefreshToken {

  @Id
  @Column(name = "id", columnDefinition = "BINARY(16)", nullable = false)
  private UUID id;

  @Column(name = "user_id", columnDefinition = "BINARY(16)", nullable = false)
  private UUID userId; // raw UUID, no @ManyToOne — avoids lazy-load traps

  @Column(name = "token_hash", length = 64, nullable = false)
  private String tokenHash; // SHA-256 hex

  @Column(name = "family_id", columnDefinition = "BINARY(16)", nullable = false)
  private UUID familyId;

  @Column(name = "expires_at", nullable = false)
  private Instant expiresAt;

  @Column(name = "revoked_at")
  private Instant revokedAt;

  @Version
  @Column(name = "version", nullable = false)
  private long version;

  @Column(name = "created_at", insertable = false, updatable = false)
  private Instant createdAt;

  @Column(name = "updated_at", insertable = false, updatable = false)
  private Instant updatedAt;

  /**
   * Marks this token as revoked. Follows the {@code User.verify()} pattern — intention-revealing
   * domain method rather than a public setter. Calling multiple times updates {@code revokedAt}.
   *
   * @param revokedAt the instant at which the token was revoked
   */
  public void revoke(Instant revokedAt) {
    this.revokedAt = revokedAt;
  }

  /**
   * Creates a refresh token with all required fields; {@code revokedAt} defaults to {@code null}.
   */
  public RefreshToken(UUID id, UUID userId, String tokenHash, UUID familyId, Instant expiresAt) {
    this.id = id;
    this.userId = userId;
    this.tokenHash = tokenHash;
    this.familyId = familyId;
    this.expiresAt = expiresAt;
  }
}
