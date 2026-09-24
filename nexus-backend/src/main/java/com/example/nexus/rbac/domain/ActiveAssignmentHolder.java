package com.example.nexus.rbac.domain;

import java.util.UUID;

/**
 * Projection of an active assignment's id, holder and role, returned by M11's locking read
 * (US-017 D6, §4.3). Mirrors {@link ActiveAssignmentRef}'s shape and rationale exactly: ids only,
 * never entities, so a caller cannot load-mutate-save a {@link UserRole} from a locking read
 * (§4.3, §8.3).
 *
 * <p><b>{@code roleId} added post-06-code-review.md H-1</b> (2026-09-24): the lockout guard needs
 * to know which specific role each locked holder holds, so it can restrict the distinct-holder
 * check to the tenant's <em>caller-qualifying</em> role population (literal {@code TENANT_ADMIN}
 * or a role carrying ALL THREE dangerous permissions) rather than the broader ANY-admin-equivalent
 * lock-set population — see {@code RoleAssignmentService#wouldLeaveTenantWithoutCallerQualifyingHolder}.
 */
public record ActiveAssignmentHolder(UUID assignmentId, UUID userId, UUID roleId) {}
