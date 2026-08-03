package com.example.nexus.rbac.application.port.out;

import com.example.nexus.common.domain.RequestContext;
import java.util.UUID;

/**
 * Typed carrier for a role-assignment/revocation audit payload. Lives beside {@link
 * RbacAuditPort}: it is a port contract, not a domain concept (03-design.md §4.5).
 *
 * <p>{@code requestContext} carries {@code traceId} (the correlation id) plus {@code
 * ipAddress}/{@code userAgent} for the native {@code auth_events} columns.
 */
public record RbacAuditEvent(
    UUID tenantId,
    UUID targetUserId,
    UUID roleId,
    String roleName,
    UUID actorUserId,
    RequestContext requestContext) {}
