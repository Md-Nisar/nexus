package com.example.nexus.rbac.application.port.out;

import java.util.UUID;

/**
 * Typed carrier for a {@code ROLE_BREAK_GLASS_GRANT} audit payload (US-018 A7, 03-design.md §7.2).
 * Lives beside {@link RbacAuditPort}: it is a port contract, not a domain concept.
 *
 * <p>There is no actor user id and no request context: the break-glass CLI runs outside any
 * request and the operator's identity never enters tenant data (Decision 10). {@code changeRef}
 * is the only operator attribution.
 *
 * @param tenantId the target user's tenant; {@code null} when the target user does not exist
 * @param targetUserId the user the grant was (or would have been) made to
 * @param changeRef the operator-supplied change reference
 */
public record BreakGlassAuditEvent(UUID tenantId, UUID targetUserId, String changeRef) {}
