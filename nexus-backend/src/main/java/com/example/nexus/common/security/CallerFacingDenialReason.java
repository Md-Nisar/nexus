package com.example.nexus.common.security;

/**
 * The {@code reason} written on every {@code RBAC_001} response (US-019 B7, design §9.2). It is
 * decoupled from {@link DenialReason} so that internal names can change without changing the wire,
 * and so that only in-tenant rules a caller can act on are disclosed (T-I22, RES-47). Opaque
 * failures (malformed authentication, missing tenant, cross-tenant, a plainly absent permission)
 * all map to {@link #UNSPECIFIED}. Logs and metrics keep the internal {@link DenialReason} names.
 *
 * <p>Applied only by {@code GlobalExceptionHandler.handleInsufficientPermission}; the generic
 * {@code ACCESS_DENIED} response never carries a reason (RC-63(l)).
 */
public enum CallerFacingDenialReason {
  GRANT_EXCEEDS_CALLER,
  SELF_ASSIGNMENT,
  ADMINISTRATOR_REQUIRED,
  UNSPECIFIED;

  /** Maps an internal denial reason to its wire value; exhaustive by construction. */
  public static CallerFacingDenialReason of(DenialReason reason) {
    return switch (reason) {
      case GRANT_EXCEEDS_CALLER -> GRANT_EXCEEDS_CALLER;
      case SELF_ASSIGNMENT -> SELF_ASSIGNMENT;
      case NOT_TENANT_ADMIN -> ADMINISTRATOR_REQUIRED;
      case PERMISSION_ABSENT, MALFORMED_AUTHENTICATION, MISSING_TENANT, CROSS_TENANT_TARGET ->
          UNSPECIFIED;
    };
  }
}
