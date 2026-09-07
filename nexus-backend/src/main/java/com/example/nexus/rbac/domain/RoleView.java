package com.example.nexus.rbac.domain;

import java.time.Instant;
import java.util.UUID;

/**
 * Projection of a role, used on every US-015 read and write path in place of the managed {@link
 * Role} entity. Deliberately not the entity: {@code Role} maps {@code tenantId}, {@code name},
 * {@code description} and {@code systemRole} as plain updatable columns, and {@code nexus_app}
 * holds {@code SELECT, INSERT} on {@code roles} with no {@code UPDATE} at all — an accidental
 * dirty-flush on a loaded {@code Role} would fail in production only, since every {@code *IT}
 * connects as the Testcontainers superuser (03-design.md §4.3).
 */
public record RoleView(
    UUID id, UUID tenantId, String name, String description, boolean systemRole, Instant createdAt) {}
