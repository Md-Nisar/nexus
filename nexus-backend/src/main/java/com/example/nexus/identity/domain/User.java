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
  @Column(name = "id", columnDefinition = "BINARY(16)", nullable = false)
  private UUID id;

  @Column(name = "tenant_id", columnDefinition = "BINARY(16)", nullable = false)
  private UUID tenantId;

  @Column(name = "email_cipher", nullable = false)
  private EmailCipher emailCipher; // AttributeEncryptor auto-applies (no @Convert needed)

  @Column(name = "email_hmac", length = 64, nullable = false, updatable = false)
  private String emailHmac; // no setter — immutable after insert (SEC-T9)

  @Column(name = "password_hash", length = 255, nullable = false)
  private String passwordHash;

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
  public User(
      UUID id,
      UUID tenantId,
      EmailCipher emailCipher,
      String emailHmac,
      String passwordHash,
      Instant consentAcceptedAt) {
    this.id = id;
    this.tenantId = tenantId;
    this.emailCipher = emailCipher;
    this.emailHmac = emailHmac;
    this.passwordHash = passwordHash;
    this.consentAcceptedAt = consentAcceptedAt;
    this.status = UserStatus.PENDING;
    this.tokenVersion = 0;
    this.failedAttemptCount = 0;
  }

  /**
   * Transitions this user from {@link UserStatus#PENDING} to {@link UserStatus#ACTIVE}.
   * Throws {@link IllegalStateException} if called on a user that is not PENDING — this
   * is an internal invariant violation, not a user-facing error.
   */
  public void verify(Instant verifiedAt) {
    if (this.status != UserStatus.PENDING) {
      throw new IllegalStateException(
          "Cannot verify user in status " + this.status + "; expected PENDING");
    }
    this.status = UserStatus.ACTIVE;
    this.emailVerifiedAt = verifiedAt;
  }

  /** Increments the consecutive-failure counter and returns the new count. */
  public int recordFailedAttempt() {
    this.failedAttemptCount += 1;
    return this.failedAttemptCount;
  }

  /**
   * Transitions to {@link UserStatus#LOCKED} and sets the auto-expiry instant. Idempotent.
   *
   * <p>Lockout does NOT revoke active refresh-token families — this is a brute-force defense,
   * not a compromise-response control (M-9 / DF-4). If session invalidation is needed in future,
   * wire {@code SecureEventService.revokeFamily} at the call site.
   */
  public void lockAccount(Instant lockedUntil) {
    this.status = UserStatus.LOCKED;
    this.lockedUntil = lockedUntil;
  }

  /**
   * Zeroes the failure counter and clears lockedUntil. Does NOT change status.
   * Called on successful login to reset the brute-force counter.
   */
  public void resetFailedAttempts() {
    this.failedAttemptCount = 0;
    this.lockedUntil = null;
  }

  /**
   * If status is {@link UserStatus#LOCKED} and {@code lockedUntil} is strictly before {@code now}
   * ({@link Instant#isBefore}, not {@code !isAfter}), transitions to {@link UserStatus#ACTIVE},
   * zeroes {@code failedAttemptCount}, clears {@code lockedUntil}, and returns {@code true}.
   * Otherwise returns {@code false} with no state change.
   *
   * <p>Lockout does NOT revoke active refresh-token families — this is a brute-force defense,
   * not a compromise-response control. If session invalidation is needed in future, wire
   * {@code SecureEventService.revokeFamily} at the call site.
   */
  public boolean unlockIfExpired(Instant now) {
    if (this.status == UserStatus.LOCKED && this.lockedUntil != null && this.lockedUntil.isBefore(now)) {
      this.status = UserStatus.ACTIVE;
      this.failedAttemptCount = 0;
      this.lockedUntil = null;
      return true;
    }
    return false;
  }
}
