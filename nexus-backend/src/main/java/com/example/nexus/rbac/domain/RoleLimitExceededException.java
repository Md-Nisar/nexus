package com.example.nexus.rbac.domain;

import com.example.nexus.common.domain.ConflictException;

/**
 * Thrown when a tenant has already reached its configured per-tenant role cap ({@code
 * nexus.rbac.max-roles-per-tenant}, default 500) and attempts to create another role. Maps to
 * HTTP 409 with error code {@code RBAC_008}.
 *
 * <p>This cap exists because {@code POST /roles} is unthrottled and {@code GET /roles} is
 * unpaginated, and {@code nexus_app} holds no {@code DELETE} on {@code roles} — without a cap, an
 * unbounded write loop amplifies every subsequent read by every user in the tenant with no
 * application-level cleanup path (threat-model.md RC-4).
 *
 * <p>The message is a fixed static literal baked into this no-arg constructor and must never be
 * constructed from a caught {@code DataIntegrityViolationException}'s message or any other
 * DB-supplied text: {@code GlobalExceptionHandler}'s generic {@code ConflictException} handler
 * echoes {@link #getMessage()} verbatim into the client-visible RFC 7807 response body.
 */
@SuppressWarnings("java:S110")
public class RoleLimitExceededException extends ConflictException {

  public RoleLimitExceededException() {
    super("RBAC_008", "This tenant has reached its role limit");
  }
}
