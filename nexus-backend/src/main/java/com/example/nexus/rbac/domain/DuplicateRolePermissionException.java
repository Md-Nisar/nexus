package com.example.nexus.rbac.domain;

import com.example.nexus.common.domain.ConflictException;

/**
 * Thrown when a permission is already attached to a role — either the pre-check (AC4's common
 * path) or the {@code pk_role_permissions} constraint-violation translation (the concurrent-attach
 * TOCTOU backstop). Maps to HTTP 409 with error code {@code RBAC_005}.
 *
 * <p>The message is a fixed static literal baked into this no-arg constructor and must never be
 * constructed from a caught {@code DataIntegrityViolationException}'s message or any other
 * DB-supplied text: {@code GlobalExceptionHandler}'s generic {@code ConflictException} handler
 * echoes {@link #getMessage()} verbatim into the client-visible RFC 7807 response body.
 */
@SuppressWarnings("java:S110")
public class DuplicateRolePermissionException extends ConflictException {

  public DuplicateRolePermissionException() {
    super("RBAC_005", "This permission is already attached to this role");
  }
}
