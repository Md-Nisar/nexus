package com.example.nexus.rbac.domain;

import java.util.UUID;

/**
 * One {@code (roleId, permissionId)} pair held by a user through an active assignment (US-018 M13,
 * 03-design.md §4.3). Ids only: permission names never cross the port (ADR-0017 D2, ADR-0018 D3).
 *
 * <p>Deliberately not {@link RolePermissionId}: that type is the JPA {@code @EmbeddedId} of {@link
 * RolePermission}, and the persistence key is not reused as an authorization projection (US-018
 * 04-tasks.md A-1).
 */
public record RolePermissionRef(UUID roleId, UUID permissionId) {}
