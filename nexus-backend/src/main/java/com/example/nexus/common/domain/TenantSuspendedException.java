package com.example.nexus.common.domain;

/**
 * Signals that an operation was attempted for a suspended or inactive tenant.
 * Maps to HTTP 403 Forbidden with error code {@code TENANT_SUSPENDED}.
 */
public class TenantSuspendedException extends DomainException {

  public TenantSuspendedException(String message) {
    super("TENANT_SUSPENDED", message);
  }
}
