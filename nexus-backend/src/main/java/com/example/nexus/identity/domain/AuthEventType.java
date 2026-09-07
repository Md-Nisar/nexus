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
  RESEND_THROTTLED("RESEND_THROTTLED"),

  // RBAC role-change events (US-012, Res. 2 — US-012 owns emission; US-014 extends/verifies)
  ROLE_ASSIGNED("ROLE_ASSIGNED"),
  ROLE_REVOKED("ROLE_REVOKED"),

  // US-014 AC4: a DENIED role assignment/revocation attempt (403 authorization denials only).
  // Deliberately NOT in PRIORITY below — see the comment on that field.
  ROLE_ASSIGNMENT_DENIED("ROLE_ASSIGNMENT_DENIED"),

  // US-015 AC12 (03-design.md §6.4, D7): role-definition and role-permission audit events.
  // ROLE_PERMISSION_GRANTED/ROLE_PERMISSION_REVOKED are PRIORITY; ROLE_CREATED is not — see the
  // comment on the PRIORITY field below for the admission reasoning.
  ROLE_CREATED("ROLE_CREATED"),
  ROLE_PERMISSION_GRANTED("ROLE_PERMISSION_GRANTED"),
  ROLE_PERMISSION_REVOKED("ROLE_PERMISSION_REVOKED");

  // ROLE_ASSIGNED/ROLE_REVOKED are PRIORITY (T-R4, reversing the original US-012 D10 decision):
  // role-change audit events must not share the drop-newest STANDARD lane with high-volume
  // events like LOGIN_FAILURE — a lost ROLE_ASSIGNED record is exactly the repudiation risk
  // AC7 exists to prevent.
  //
  // ROLE_ASSIGNMENT_DENIED is deliberately NOT priority (US-014 design decision 5): a denial row
  // is far cheaper to generate per row than a success row — it requires no valid mutation, no
  // lock, and (for the cross-tenant-target path) only a published, low-entropy role id, whereas
  // ROLE_ASSIGNED/ROLE_REVOKED require an actual state mutation with a last-admin guard and
  // duplicate check in the way. The priority lane is capacity-200 with drop-newest overflow (ADR
  // 0011 §1), so admitting this cheaper-to-generate type would let a user:write holder's probing
  // loop crowd out LOCKOUT/TOKEN_REFRESH_REUSE — the same hazard the two-lane split exists to
  // prevent (T-D1), reproduced inside the protected lane — and would hand that caller a direct
  // pager trigger (depth-critical >=180 -> page). Membership in the priority lane turns on
  // cost-and-uniqueness per row, not mere triggerability by an authenticated caller (today:
  // TENANT_ADMIN only — see design §0 decision 5a).
  //
  // ROLE_PERMISSION_GRANTED/ROLE_PERMISSION_REVOKED are PRIORITY (US-015 03-design.md §6.4, D7):
  // applying the same cost-and-uniqueness test, each row requires an actual role_permissions
  // mutation past the AC7 system-role guard, a permission-existence read, a duplicate check, and
  // (for the 3 dangerous permissions) a locking admin-status read — and uniqueness is bounded by
  // |permissions| = 7 per role, so a probing loop cannot mint unbounded distinct rows. Forensic
  // value is strictly greater than a single ROLE_ASSIGNED: one row changes the effective
  // privileges of every current and future holder of that role.
  //
  // ROLE_CREATED is deliberately NOT priority (US-015 03-design.md §6.4, D7): it is the cheapest
  // of the three to generate (one INSERT, no locking read, no existence check) and its
  // uniqueness is caller-controlled and unbounded (distinct names, one cheap INSERT each) — the
  // same hazard profile as ROLE_ASSIGNMENT_DENIED, not ROLE_ASSIGNED. A freshly created role
  // also carries zero permissions and confers nothing until a separately audited grant.
  private static final Set<AuthEventType> PRIORITY =
      EnumSet.of(
          LOCKOUT,
          TOKEN_REFRESH_REUSE,
          PASSWORD_CHANGED,
          ACCOUNT_LOCKED_WRITE_FAILED,
          ROLE_ASSIGNED,
          ROLE_REVOKED,
          ROLE_PERMISSION_GRANTED,
          ROLE_PERMISSION_REVOKED);

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
   * @return {@code true} for the 8 highest-value forensic/security-incident signals ({@link
   *     #LOCKOUT}, {@link #TOKEN_REFRESH_REUSE}, {@link #PASSWORD_CHANGED}, {@link
   *     #ACCOUNT_LOCKED_WRITE_FAILED}, {@link #ROLE_ASSIGNED}, {@link #ROLE_REVOKED}, {@link
   *     #ROLE_PERMISSION_GRANTED}, {@link #ROLE_PERMISSION_REVOKED}); {@code false} for all other
   *     types.
   */
  public boolean isPriority() {
    return PRIORITY.contains(this);
  }
}
