package com.example.nexus.rbac.domain;

import com.example.nexus.common.domain.ConflictException;

/**
 * Thrown when an assign or an attach finds, in its post-insert current read of the role's
 * permissions, that the role changed class while the request waited on the role row (US-019
 * RC-56.2, RC-56.3, RC-66.3; design §10.9): it became admin-defining, or, on assign, it gained
 * {@code user:directory:read} for a caller who is not an administrator. The insert rolls back with
 * no audit row. Maps to HTTP 409 with error code {@code RBAC_012}, which is <b>retryable</b>: the
 * retry classifies the current role and meets the rule that now applies ({@code RBAC_010}, the set
 * lock, the PII grant rule). Distinct from {@code RBAC_010} because its remedy differs.
 *
 * <p>The message is a fixed static literal: it names no role, permission or holder, and {@code
 * GlobalExceptionHandler}'s {@code ConflictException} handler echoes it verbatim to the client.
 */
@SuppressWarnings("java:S110")
public class RoleClassificationChangedException extends ConflictException {

  public RoleClassificationChangedException() {
    super("RBAC_012", "The role changed while your request was waiting. Try again.");
  }
}
