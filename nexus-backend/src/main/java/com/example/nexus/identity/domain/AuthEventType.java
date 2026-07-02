package com.example.nexus.identity.domain;

import java.util.EnumSet;
import java.util.Set;

/**
 * Canonical taxonomy of authentication-related audit event types.
 *
 * <p>Each constant carries its own {@code wireName} — the literal String persisted to the
 * {@code auth_events.event_type} column — so renaming the Java constant name never silently
 * changes the stored value, and the stored value is auditable in one place.
 *
 * <p>{@link AuthEvent#getEventType()} stays a plain {@code String} column (no {@code
 * @Enumerated}) because historical rows hold non-enum literals (see the name-mapping table in
 * {@code docs/features/US-008/03-design.md} §2.2) that this enum's wire names do not cover.
 */
public enum AuthEventType {

  // AC1 canonical 9 (renames applied per OQ-1)
  LOGIN_SUCCESS("LOGIN_SUCCESS"),
  LOGIN_FAILURE("LOGIN_FAILURE"),
  LOCKOUT("LOCKOUT"), // renamed from ACCOUNT_LOCKED
  LOGOUT("LOGOUT"),
  REGISTER("REGISTER"), // renamed from REGISTRATION_SUCCESS
  VERIFY("VERIFY"), // renamed from VERIFICATION_SUCCESS
  PASSWORD_RESET_REQUESTED("PASSWORD_RESET_REQUESTED"),
  PASSWORD_CHANGED("PASSWORD_CHANGED"),
  TOKEN_REFRESH_REUSE("TOKEN_REFRESH_REUSE"), // renamed from REFRESH_FAMILY_REVOKED

  // Retained granular states (beyond AC1's 9 — superset, per OQ-1)
  LOGIN_PENDING_ACCOUNT("LOGIN_PENDING_ACCOUNT"),
  ACCOUNT_UNLOCKED("ACCOUNT_UNLOCKED"),
  ACCOUNT_LOCKED_WRITE_FAILED("ACCOUNT_LOCKED_WRITE_FAILED"),
  REGISTRATION_DUPLICATE_EMAIL("REGISTRATION_DUPLICATE_EMAIL"),
  VERIFICATION_FAILED("VERIFICATION_FAILED"),
  TOKEN_REFRESH_SUCCESS("TOKEN_REFRESH_SUCCESS"),
  TOKEN_REFRESH_FAILURE("TOKEN_REFRESH_FAILURE"),
  PASSWORD_RESET_THROTTLED("PASSWORD_RESET_THROTTLED"),
  PASSWORD_RESET_FAILED("PASSWORD_RESET_FAILED"),
  RESEND_REQUESTED("RESEND_REQUESTED"),
  RESEND_THROTTLED("RESEND_THROTTLED");

  private static final Set<AuthEventType> PRIORITY =
      EnumSet.of(LOCKOUT, TOKEN_REFRESH_REUSE, PASSWORD_CHANGED, ACCOUNT_LOCKED_WRITE_FAILED);

  private final String wireName;

  AuthEventType(String wireName) {
    this.wireName = wireName;
  }

  /** Returns the literal String persisted to {@code auth_events.event_type}. */
  public String wireName() {
    return wireName;
  }

  /**
   * Used by {@code AuthEventRetryBuffer} to route into the priority vs. standard buffer lane.
   *
   * @return {@code true} for the 4 highest-value forensic/security-incident signals ({@link
   *     #LOCKOUT}, {@link #TOKEN_REFRESH_REUSE}, {@link #PASSWORD_CHANGED}, {@link
   *     #ACCOUNT_LOCKED_WRITE_FAILED}); {@code false} for all other types.
   */
  public boolean isPriority() {
    return PRIORITY.contains(this);
  }
}
