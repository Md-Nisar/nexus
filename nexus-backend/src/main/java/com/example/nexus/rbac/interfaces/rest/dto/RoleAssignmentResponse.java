package com.example.nexus.rbac.interfaces.rest.dto;

import java.time.Instant;

/**
 * Response element for both the 201 body of {@code POST /api/v1/users/{userId}/roles} and each
 * element of {@link RoleAssignmentListResponse}'s {@code data} array.
 *
 * <p>{@code assignedBy} may be {@code null} when the caller lacks visibility per {@code
 * RoleAssignmentService#listActive}'s redaction rule (O-10/T-I5) — a caller without an active
 * {@code TENANT_ADMIN} assignment in the tenant sees it omitted/null.
 */
public record RoleAssignmentResponse(
    String userId, String roleId, String roleName, Instant assignedAt, String assignedBy) {}
