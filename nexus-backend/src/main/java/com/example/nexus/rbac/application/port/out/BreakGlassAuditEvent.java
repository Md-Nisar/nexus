package com.example.nexus.rbac.application.port.out;

import java.util.UUID;

/**
 * Typed carrier for one break-glass invocation's audit payload (US-018 A7, 03-design.md §7). Lives
 * beside {@link RbacAuditPort}: a port contract, not a domain concept.
 *
 * <p>Every field except {@code reason} may be {@code null}, and a {@code null} is <b>omitted</b>
 * from the persisted row, never written as a placeholder: an argument-validation refusal carries
 * only {@code reason} (no tenant, no target, no change reference, RC-54(a)). {@code reason} is
 * {@code null} on a grant.
 */
public record BreakGlassAuditEvent(
    UUID tenantId, UUID targetUserId, String changeRef, String reason) {}
