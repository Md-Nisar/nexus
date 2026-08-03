package com.example.nexus.rbac.domain;

import com.example.nexus.common.domain.ConflictException;

/**
 * Thrown when a user already actively holds the role being assigned. Maps to HTTP 409 with error
 * code {@code RBAC_004}.
 *
 * <p>The message is a fixed static literal baked into this no-arg constructor and must never be
 * constructed from a caught {@code DataIntegrityViolationException}'s message or any other
 * DB-supplied text: {@code GlobalExceptionHandler}'s generic {@code ConflictException} handler
 * echoes {@link #getMessage()} verbatim into the client-visible RFC 7807 response body, and MySQL's
 * constraint-violation message for this constraint would leak the constraint name, index name, and
 * a hex fragment of {@code user_roles.active_key} that encodes the raw target user/role UUIDs.
 */
public class DuplicateRoleAssignmentException extends ConflictException {

  public DuplicateRoleAssignmentException() {
    super("RBAC_004", "This user already actively holds this role");
  }
}
