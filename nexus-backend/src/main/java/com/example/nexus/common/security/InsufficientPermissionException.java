package com.example.nexus.common.security;

import org.springframework.security.access.AccessDeniedException;

/**
 * Thrown when an authenticated principal lacks a specific RBAC permission required to invoke an
 * operation.
 *
 * <p><b>Deliberate divergence from {@code common.domain.DomainException} (ADR-0013 D3):</b> this is
 * the first cross-context exception in the codebase that does <em>not</em> extend {@code
 * DomainException}. It extends Spring Security's {@link AccessDeniedException} instead, so that
 * {@code GlobalExceptionHandler}'s most-specific {@code @ExceptionHandler} dispatch can distinguish
 * RBAC permission denials from generic access-denied responses without {@code common} taking a
 * dependency on {@code rbac}.
 *
 * <p>This is a one-off, confined to {@code common.security}. Future shared exceptions should
 * continue to extend {@code DomainException} unless they have the same Spring Security dispatch
 * requirement as this class — do not treat this as the new norm.
 *
 * <p>{@link #getReason()} keeps the denial signal separable from the human-readable message so
 * that logs and metrics can distinguish "authenticated but lacks the permission" from failures
 * upstream of the permission check (malformed authentication, missing tenant) without parsing
 * free text (threat-model T-08 / Condition 5).
 */
public class InsufficientPermissionException extends AccessDeniedException {

  private static final long serialVersionUID = 1L;

  private final String requiredPermission;
  private final DenialReason reason;

  public InsufficientPermissionException(String requiredPermission, DenialReason reason) {
    super("Access denied: missing required permission '" + requiredPermission + "'");
    this.requiredPermission = requiredPermission;
    this.reason = reason;
  }

  public String getRequiredPermission() {
    return requiredPermission;
  }

  public DenialReason getReason() {
    return reason;
  }
}
