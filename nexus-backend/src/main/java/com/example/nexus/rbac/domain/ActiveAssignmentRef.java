package com.example.nexus.rbac.domain;

import java.time.Instant;
import java.util.UUID;

/**
 * Projection of an active assignment, used on the revocation write path (M3). Deliberately not a
 * managed {@link UserRole} entity reference: a managed entity on this path can be accidentally
 * mutated and re-saved in a way the least-privilege {@code nexus_app} DB grant then rejects (T-T6
 * fix, 03-design.md §5.2).
 *
 * <p>{@code assignedAt} is carried here (not just {@code id}) because M6's revocation write uses
 * an app-side clamp for {@code revokedAt} — {@code max(now, assignedAt)} — rather than a
 * DB-side {@code FUNCTION('now', 6)}: the latter was found, empirically, to be rejected by this
 * codebase's pinned Hibernate version ("Function now() has 0 parameters, but 1 arguments given"),
 * which is exactly the fallback 03-design.md §5.2 M6 anticipated for that scenario. The clamp
 * needs {@code assignedAt} to enforce {@code revoked_at >= assigned_at} (the DB CHECK constraint)
 * without a second DB read.
 */
public record ActiveAssignmentRef(UUID id, Instant assignedAt) {}
