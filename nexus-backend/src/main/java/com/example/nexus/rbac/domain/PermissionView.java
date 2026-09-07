package com.example.nexus.rbac.domain;

import java.util.UUID;

/**
 * Projection of a permission. One type deliberately serves both AC3 (a role's attached
 * permissions) and AC6 (the full permission catalogue) — the field set and shape are identical
 * for both endpoints, so a second, synonym record was rejected (03-design.md §4.4).
 */
public record PermissionView(UUID id, String name, String description) {}
