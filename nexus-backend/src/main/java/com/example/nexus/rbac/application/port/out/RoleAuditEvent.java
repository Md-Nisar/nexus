package com.example.nexus.rbac.application.port.out;

import com.example.nexus.common.domain.RequestContext;
import java.util.UUID;

/**
 * Typed carrier for a role-definition audit payload — role creation and role-permission
 * grant/revoke (AC12). Lives beside {@link RbacAuditPort}: it is a port contract, not a domain
 * concept (03-design.md §6.1).
 *
 * <p>Deliberately <b>not</b> a widening of {@link RbacAuditEvent}: that record has nowhere to put
 * {@code permissionId}/{@code permissionName}, and smuggling them through {@code roleId}/{@code
 * roleName} would corrupt the field semantics {@code RoleAssignmentAuditIT} asserts on.
 *
 * <p><b>No {@code targetUserId} field at all</b> — these events have no subject user, by
 * construction rather than by null convention. {@code auth_events.user_id} stays {@code NULL} for
 * all three US-015 event types; the actor lives in metadata instead (as {@code createdBy}/{@code
 * grantedBy}/{@code revokedBy}).
 *
 * <p>{@code permissionId}/{@code permissionName} are {@code null} only for {@code ROLE_CREATED} —
 * a freshly created role carries no permissions. They are populated for both grant and revoke.
 *
 * <p>{@code holderCount} (03-design.md §4.7 / D13) is populated <b>only</b> on the
 * dangerous-attach path of {@code RoleManagementService.attachPermission} — the count of users
 * who actively hold the role at the moment a dangerous permission is attached to it (T-E21's
 * mint-side signal). {@code null} in every other case — {@code createRole}, {@code
 * detachPermission}, and every non-dangerous {@code attachPermission} — and therefore omitted
 * from the durable audit metadata by {@code RbacAuthEventAdapter}'s existing omit-when-null
 * convention (never serialised as a JSON {@code null}).
 */
public record RoleAuditEvent(
    UUID tenantId,
    UUID roleId,
    String roleName,
    UUID permissionId,
    String permissionName,
    UUID actorUserId,
    RequestContext requestContext,
    Integer holderCount) {}
