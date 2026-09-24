package com.example.nexus.rbac.domain;

import java.util.UUID;

/**
 * Projection pairing a role id with one of its attached permission names, returned by M10 and M12
 * (US-017 D3/D24, §4.3). Mirrors {@link ActiveAssignmentRef}'s shape and rationale exactly:
 * ids/names only, never entities, so the ANY/ALL policy in {@link RbacAdminEquivalence} stays the
 * only place that combines them (§4.3, §8.3).
 */
public record RolePermissionName(UUID roleId, String permissionName) {}
