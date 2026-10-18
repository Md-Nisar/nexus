package com.example.nexus.rbac.interfaces.rest.dto;

import java.time.Instant;

/**
 * One active holder of a role (US-018 C3). Ids and a timestamp only. {@code assignedBy} is omitted
 * ({@code null}) unless the caller is an administrator, the same rule and shape as {@link
 * RoleAssignmentResponse}.
 */
public record RoleHolderResponse(
    String userId, String assignmentId, Instant assignedAt, String assignedBy) {}
