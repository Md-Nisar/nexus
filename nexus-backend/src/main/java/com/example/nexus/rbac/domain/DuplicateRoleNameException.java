package com.example.nexus.rbac.domain;

import com.example.nexus.common.domain.ConflictException;

/**
 * Thrown when a role name collides with an existing role in the same tenant, per {@code
 * uq_roles_tenant_name}. Maps to HTTP 409 with error code {@code RBAC_006}.
 *
 * <p>The message deliberately does not over-promise: {@code uq_roles_tenant_name} runs under
 * {@code utf8mb4_0900_ai_ci}, which is accent-insensitive as well as case-insensitive (e.g. {@code
 * "Rôle"} collides with {@code "role"}), so the message states only that a collision occurred, not
 * how matching works.
 *
 * <p>The message is a fixed static literal baked into this no-arg constructor and must never be
 * constructed from a caught {@code DataIntegrityViolationException}'s message or any other
 * DB-supplied text: {@code GlobalExceptionHandler}'s generic {@code ConflictException} handler
 * echoes {@link #getMessage()} verbatim into the client-visible RFC 7807 response body.
 */
@SuppressWarnings("java:S110")
public class DuplicateRoleNameException extends ConflictException {

  public DuplicateRoleNameException() {
    super("RBAC_006", "A role with this name already exists in this tenant");
  }
}
