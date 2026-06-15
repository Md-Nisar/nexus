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

/** Tenant-aware identity entity representing a registered user (see ADR-0005, ADR-0006). */
@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = lombok.AccessLevel.PROTECTED)
public class User {

  @Id
  @Column(name = "id", length = 16, nullable = false)
  private UUID id;

  @Column(name = "tenant_id", length = 16, nullable = false)
  private UUID tenantId;

  @Column(name = "email_cipher", nullable = false)
  private EmailCipher emailCipher; // AttributeEncryptor auto-applies (no @Convert needed)

  @Column(name = "email_hmac", length = 64, nullable = false, updatable = false)
  private String emailHmac; // no setter — immutable after insert (SEC-T9)

  @Enumerated(EnumType.STRING)
  @Column(name = "status", length = 20, nullable = false)
  private UserStatus status;

  @Column(name = "token_version", nullable = false)
  private int tokenVersion;

  @Column(name = "email_verified_at")
  private Instant emailVerifiedAt;

  @Column(name = "failed_attempt_count", nullable = false)
  private int failedAttemptCount;

  @Column(name = "locked_until")
  private Instant lockedUntil;

  @Column(name = "consent_accepted_at")
  private Instant consentAcceptedAt;

  @Version
  @Column(name = "version", nullable = false)
  private long version;

  @Column(name = "created_at", insertable = false, updatable = false)
  private Instant createdAt;

  @Column(name = "updated_at", insertable = false, updatable = false)
  private Instant updatedAt;

  /**
   * Creates a user in {@link UserStatus#PENDING} status with zero token version and failed-attempt
   * count; all timestamp fields are set by the database.
   */
  public User(UUID id, UUID tenantId, EmailCipher emailCipher, String emailHmac) {
    this.id = id;
    this.tenantId = tenantId;
    this.emailCipher = emailCipher;
    this.emailHmac = emailHmac;
    this.status = UserStatus.PENDING;
    this.tokenVersion = 0;
    this.failedAttemptCount = 0;
  }
}
