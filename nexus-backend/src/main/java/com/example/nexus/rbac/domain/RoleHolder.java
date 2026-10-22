package com.example.nexus.rbac.domain;

import java.time.Instant;
import java.util.UUID;

/**
 * One active holder of a role, as the access-review role-holders read returns it (US-018 C3).
 * Ids and a timestamp only: no email, no name. {@code assignedBy} is {@code null} when the caller
 * is not an administrator (the same redaction rule and shape as {@code listActive}, R1-4).
 */
public record RoleHolder(UUID userId, UUID assignmentId, Instant assignedAt, UUID assignedBy) {

  /** The redacted shape: everything but {@code assignedBy}. */
  public RoleHolder withAssignedByRedacted() {
    return new RoleHolder(userId, assignmentId, assignedAt, null);
  }
}
