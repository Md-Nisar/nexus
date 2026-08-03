package com.example.nexus.rbac.domain;

import com.example.nexus.common.domain.ConflictException;

/**
 * Thrown when a revocation would leave a tenant with zero active {@code TENANT_ADMIN}
 * assignments. Maps to HTTP 409 with error code {@code RBAC_002}.
 *
 * <p>This guard is actor-agnostic: it fires for any caller revoking the tenant's last active
 * {@code TENANT_ADMIN} assignment, not only self-revocation.
 *
 * <p>The message is a fixed static literal baked into this no-arg constructor and must never be
 * built from a caught exception or any other data-supplied text — {@code GlobalExceptionHandler}'s
 * generic {@code ConflictException} handler echoes {@link #getMessage()} verbatim into the
 * client-visible RFC 7807 response body.
 */
public class LastAdminRoleException extends ConflictException {

  public LastAdminRoleException() {
    super("RBAC_002", "Cannot revoke the last active TENANT_ADMIN assignment in this tenant");
  }
}
