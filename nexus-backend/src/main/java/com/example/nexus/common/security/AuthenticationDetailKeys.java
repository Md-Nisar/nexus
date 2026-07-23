package com.example.nexus.common.security;

/**
 * Single-sourced keys for the {@code Authentication.getDetails()} map produced by {@code
 * JwtAuthenticationFilter} and consumed by {@link AuthenticatedRequestDetails} and {@code
 * UserProfileController} — a rename on one side without the other previously fails closed with
 * no compile-time warning (threat-model finding T-06).
 *
 * <p>Also single-sources the MDC keys {@code JwtAuthenticationFilter} populates for log
 * propagation, so a rename on the producer side can't silently degrade a consumer (e.g. {@code
 * GlobalExceptionHandler}'s RBAC denial log) to a null field with no compiler warning.
 */
public final class AuthenticationDetailKeys {

  public static final String TENANT_ID = "tenantId";
  public static final String EMAIL_VERIFIED = "emailVerified";
  public static final String TOKEN_VERSION = "tokenVersion";
  public static final String PERMISSIONS = "permissions";

  /** MDC key under which {@code JwtAuthenticationFilter} puts the authenticated user's id. */
  public static final String MDC_USER_ID = "userId";

  /** MDC key under which {@code JwtAuthenticationFilter} puts the authenticated user's tenant id. */
  public static final String MDC_TENANT_ID = "tenantId";

  private AuthenticationDetailKeys() {}
}
