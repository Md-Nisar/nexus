package com.example.nexus.rbac.domain;

import com.example.nexus.common.domain.ConflictException;

/**
 * Thrown when a write (attach/detach permission) targets a role with {@code is_system_role =
 * TRUE}. Maps to HTTP 409 with error code {@code RBAC_003}. Covers both seeded system roles —
 * {@code TENANT_ADMIN} and, per 03-design.md §1 RC-5b, {@code MEMBER} — identically; this is
 * {@code MEMBER}'s only gate against a dangerous-permission attach, since AC7 runs before AC11.
 *
 * <p>The message is a fixed static literal baked into this no-arg constructor and must never be
 * constructed from a caught {@code DataIntegrityViolationException}'s message or any other
 * DB-supplied text: {@code GlobalExceptionHandler}'s generic {@code ConflictException} handler
 * echoes {@link #getMessage()} verbatim into the client-visible RFC 7807 response body.
 */
@SuppressWarnings("java:S110")
public class SystemRoleImmutableException extends ConflictException {

  public SystemRoleImmutableException() {
    super("RBAC_003", "System roles cannot be modified through this API");
  }
}
