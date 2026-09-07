package com.example.nexus.rbac.domain;

import com.example.nexus.common.domain.ConflictException;

/**
 * Thrown when a role name case-insensitively matches a reserved system-role name (see {@link
 * RbacRoleNames#RESERVED}), regardless of whether a colliding system role currently exists in the
 * tenant. Maps to HTTP 409 with error code {@code RBAC_007}.
 *
 * <p>This check exists to close a permanent, application-unremediable denial of service: {@code
 * nexus_app} has neither {@code UPDATE} nor {@code DELETE} on {@code roles}, so a name collision
 * with a future-seeded system role, once created, could only be undone by a DBA
 * (threat-model.md RC-1).
 *
 * <p>The message is a fixed static literal baked into this no-arg constructor and must never be
 * constructed from a caught {@code DataIntegrityViolationException}'s message or any other
 * DB-supplied text: {@code GlobalExceptionHandler}'s generic {@code ConflictException} handler
 * echoes {@link #getMessage()} verbatim into the client-visible RFC 7807 response body.
 */
@SuppressWarnings("java:S110")
public class ReservedRoleNameException extends ConflictException {

  public ReservedRoleNameException() {
    super("RBAC_007", "This name is reserved for a system role");
  }
}
