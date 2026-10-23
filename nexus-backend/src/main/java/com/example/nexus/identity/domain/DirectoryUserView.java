package com.example.nexus.identity.domain;

import java.time.Instant;
import java.util.UUID;

/**
 * One user as the user directory shows it (US-019 B1, design §4.1): exactly the five readable
 * fields. The blind index, password hash, failure counter and lock expiry never reach this type.
 *
 * <p>{@link #toString()} redacts the email so a logged view never carries PII (NF-P1).
 *
 * @param id the user id
 * @param email the decrypted email address
 * @param status the stored status
 * @param emailVerifiedAt when the email was verified, or {@code null} if it is not
 * @param createdAt when the user was created
 */
public record DirectoryUserView(
    UUID id, String email, UserStatus status, Instant emailVerifiedAt, Instant createdAt) {

  /** Whether the email address has been verified. */
  public boolean emailVerified() {
    return emailVerifiedAt != null;
  }

  @Override
  public String toString() {
    return "DirectoryUserView[id=" + id + ", email=REDACTED, status=" + status + "]";
  }
}
