package com.example.nexus.rbac.domain;

import java.time.Instant;
import java.util.UUID;

/**
 * Read model for an active (non-revoked) role assignment, projected by M4/M4a for listing and for
 * the post-assign response (03-design.md §4.6/§5.2).
 */
public record ActiveRoleAssignment(
    UUID userId, UUID roleId, String roleName, Instant assignedAt, UUID assignedBy) {}
