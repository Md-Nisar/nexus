package com.example.nexus.rbac.interfaces.rest.dto;

import java.time.Instant;

/**
 * Response element for {@code POST /api/v1/roles}'s 201 body and each element of {@link
 * RoleListResponse}'s {@code data} array (03-design.md §8.1/§8.2, D5).
 *
 * <p><b>Boolean JSON naming trap, pinned (D5):</b> the record component is {@code boolean
 * isSystemRole}, so the accessor is {@code isSystemRole()} and the serialised key is {@code
 * isSystemRole} — not {@code systemRole}. {@code isSystemRole} is exposed deliberately: an Epic 3
 * admin UI needs it to grey out AC7-protected roles client-side instead of discovering
 * immutability through a 409.
 *
 * <p>Deliberately absent: {@code tenantId} (every role here is, by construction, the caller's own
 * tenant), {@code updatedAt} (nothing in this story can update a role — {@code roles} has no
 * {@code UPDATE} grant), and any permission list (that is the separate {@code GET
 * /roles/{roleId}/permissions} endpoint).
 */
public record RoleResponse(
    String id, String name, String description, boolean isSystemRole, Instant createdAt) {}
