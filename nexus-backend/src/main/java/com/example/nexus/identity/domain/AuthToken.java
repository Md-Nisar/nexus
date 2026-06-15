package com.example.nexus.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.UUID;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * One-time token used for email verification or password reset.
 */
@Entity
@Table(name = "auth_tokens")
@Getter
@NoArgsConstructor(access = lombok.AccessLevel.PROTECTED)
public class AuthToken {

  @Id
  @Column(name = "id", length = 16, nullable = false)
  private UUID id;

  @Column(name = "user_id", length = 16, nullable = false)
  private UUID userId;

  @Enumerated(EnumType.STRING)
  @Column(name = "type", length = 20, nullable = false)
  private AuthTokenType type;

  @Column(name = "token_hash", length = 64, nullable = false)
  private String tokenHash; // SHA-256 hex, UNIQUE

  @Column(name = "expires_at", nullable = false)
  private Instant expiresAt;

  @Column(name = "consumed_at")
  private Instant consumedAt;

  @Version
  @Column(name = "version", nullable = false)
  private long version;

  @Column(name = "created_at", insertable = false, updatable = false)
  private Instant createdAt;

  @Column(name = "updated_at", insertable = false, updatable = false)
  private Instant updatedAt;

  /**
   * Creates an auth token with all required fields; {@code consumedAt} defaults to {@code null}.
   */
  public AuthToken(UUID id, UUID userId, AuthTokenType type, String tokenHash, Instant expiresAt) {
    this.id = id;
    this.userId = userId;
    this.type = type;
    this.tokenHash = tokenHash;
    this.expiresAt = expiresAt;
  }
}
