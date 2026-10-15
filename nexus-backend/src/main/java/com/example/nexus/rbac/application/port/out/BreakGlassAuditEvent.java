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
 * <p>On {@code INVALID_ARGUMENT} (RC-54(a), L-6) all three fields are {@code null}, so the row's
 * metadata is exactly {@code {actorType, reason}} and carries no rejected argument value.
 *
 * @param tenantId the target user's tenant; {@code null} when the target user does not exist,
 *     on {@code CHANGE_REF_REUSED} (checked before the user lookup) and on {@code
 *     INVALID_ARGUMENT}
 * @param targetUserId the user the grant was (or would have been) made to; {@code null} on {@code
 *     INVALID_ARGUMENT}
 * @param changeRef the operator-supplied change reference; {@code null} on {@code
 *     INVALID_ARGUMENT}
 */
public record BreakGlassAuditEvent(UUID tenantId, UUID targetUserId, String changeRef) {}
