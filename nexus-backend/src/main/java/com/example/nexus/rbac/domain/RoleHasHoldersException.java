package com.example.nexus.rbac.domain;

import com.example.nexus.common.domain.ConflictException;

/**
 * Thrown when a role is deleted while it still has an active holder (US-018 C1, {@code DELETE
 * /api/v1/roles/{roleId}}). Maps to HTTP 409 with error code {@code RBAC_009}; the surrounding
 * transaction rolls back, so the role stays live.
 *
 * <p>The message is a fixed static literal and names no holder.
 */
@SuppressWarnings("java:S110")
public class RoleHasHoldersException extends ConflictException {

  public RoleHasHoldersException() {
    super("RBAC_009", "This role still has active holders; revoke them first");
  }
}
