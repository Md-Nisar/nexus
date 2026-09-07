package com.example.nexus.rbac.interfaces.rest.dto;

/**
 * Response element for {@code POST /api/v1/roles/{roleId}/permissions}'s 201 body and each
 * element of {@link PermissionListResponse}'s {@code data} array — used by both AC3 (a role's
 * attached permissions) and AC6 (the full catalogue) (03-design.md §8.4, D5).
 *
 * <p>No {@code createdAt}: {@code permissions} is migration-seeded and read-only at runtime
 * (ADR-0013 D1); its creation timestamp is a schema artifact with no client meaning.
 */
public record PermissionResponse(String id, String name, String description) {}
