package com.example.nexus.rbac.domain;

import com.example.nexus.common.domain.ConflictException;

/**
 * Thrown when attaching a permission would make a role admin-defining (it would then carry every
 * permission of the catalogue) while the role has an active holder whose assigner is not currently
 * an administrator (US-018 narrow provenance rule, ADR-0021 D8, design §5.6). Maps to HTTP 409 with
 * error code {@code RBAC_010}.
 *
 * <p>The message is a fixed static literal baked into this no-arg constructor: it names no holder,
 * no assigner and no count, and must never be built from data. {@code GlobalExceptionHandler}'s
 * generic {@code ConflictException} handler echoes {@link #getMessage()} verbatim into the
 * client-visible RFC 9457 response body.
 */
@SuppressWarnings("java:S110")
public class AttachProvenanceConflictException extends ConflictException {

  public AttachProvenanceConflictException() {
    super(
        "RBAC_010",
        "This permission cannot be attached yet: it would make the role an administrator role"
            + " while some of its holders were assigned by someone who is not an administrator."
            + " Revoke those assignments first.");
  }
}
