package com.example.nexus.rbac.interfaces.rest.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Request body for {@code POST /api/v1/roles} (03-design.md §8.1, D6).
 *
 * <p>Models exactly two fields. No {@code tenantId} — the tenant is sourced exclusively from the
 * caller's authenticated context. No {@code isSystemRole} — a client-settable value would let a
 * caller mint an AC7-immune role. Both are enforced by not modelling them at all, which is
 * stronger than validating them away (the {@code AssignRoleRequest} T-S3 precedent).
 *
 * <p>{@code name} is deliberately not trimmed — rejecting is explicit, matching {@code
 * AuthenticatedRequestDetails.tenantId()}'s documented "no trimming" opacity discipline.
 *
 * <p><b>{@code description} is untrusted, tenant-controlled free text and must never be written to
 * a log, a metric tag, or an audit payload</b> (threat-model.md T-T9/RC-3) — it is the only
 * tenant-controlled field in this story not covered by an allow-list strong enough for those
 * sinks. {@link com.example.nexus.rbac.domain.RoleView#description()} carries the same
 * constraint.
 */
public record CreateRoleRequest(
    @NotBlank
        @Size(max = 64)
        @Pattern(regexp = "^[A-Za-z0-9][A-Za-z0-9 ._-]*$", message = "must be a valid role name")
        String name,
    @Size(max = 255)
        @Pattern(
            regexp = "^[^\\p{Cntrl}\\u2028\\u2029]*$",
            message = "must not contain control characters")
        String description) {}
