package com.example.nexus.identity.infrastructure.audit;

/**
 * US-008 T-08-15 (design §4.2, ADR 0011 §1) — the two independent lanes of {@link
 * AuthEventRetryBuffer}. Routing is decided by {@code AuthEventType.isPriority()}: {@code true}
 * routes to {@link #PRIORITY}, {@code false} routes to {@link #STANDARD}.
 *
 * <p>Package-private — an infrastructure-internal routing/tagging detail. Callers outside this
 * package observe lane state only through {@link AuthEventRetryBuffer#depth(AuditLane)} /
 * {@link AuthEventRetryBuffer#oldestAgeSeconds(AuditLane)}, both of which are also
 * package-private-friendly (T-08-17's tests live in this same package).
 */
enum AuditLane {
  /** Capacity 200 — {@code LOCKOUT}, {@code TOKEN_REFRESH_REUSE}, {@code PASSWORD_CHANGED},
   *  {@code ACCOUNT_LOCKED_WRITE_FAILED} (design §4.1). */
  PRIORITY,

  /** Capacity 800 — every other {@code AuthEventType}, including {@code LOGIN_FAILURE}. */
  STANDARD
}
