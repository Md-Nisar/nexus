package com.example.nexus.rbac.application.port.out;

import com.example.nexus.common.security.DenialReason;

/**
 * Outbound audit port for RBAC authorization changes (03-design.md §4.5, §6.2). Implemented by
 * {@code identity.infrastructure.audit.RbacAuthEventAdapter}, which delegates to {@code
 * SecureEventService} so {@code rbac} gets audit infrastructure for free without importing {@code
 * identity}.
 *
 * <p><b>Two documented groups (Decision 9, US-018 A6):</b>
 *
 * <ul>
 *   <li><b>Group A (atomic):</b> {@link #recordRoleAssigned}, {@link #recordRoleRevoked}, {@link
 *       #recordRoleCreated}, {@link #recordRolePermissionGranted}, {@link
 *       #recordRolePermissionRevoked} — called INLINE, inside the caller's own mutation
 *       transaction, after the mutation and before the method returns. These join that
 *       transaction ({@code SecureEventService#recordEventInCurrentTransaction}, {@code MANDATORY})
 *       and <b>MUST THROW</b> on failure, so a lost audit write rolls back the mutation it was
 *       meant to record (design §6.2). Cache eviction, INFO logs and timers remain post-commit;
 *       only the audit write itself moved inline.
 *   <li><b>Group B (best-effort):</b> {@link #recordRoleAssignmentDenied} — called INLINE,
 *       pre-throw, from a transaction that is about to roll back. Durability rests entirely on
 *       {@code SecureEventService#recordEvent}'s independent ({@code REQUIRES_NEW}) transaction.
 *       <b>MUST NEVER throw and MUST NOT block</b> — on failure it must swallow its own failure
 *       (buffering for bounded backed-off retry, or logging and continuing) and never propagate.
 * </ul>
 *
 * No caller handles exceptions from the five Group B overload calls; Group A's five methods are
 * called from within a {@code try}/{@code catch (RuntimeException)} that exists for other reasons
 * (timer/outcome bookkeeping) and simply rethrows.
 */
public interface RbacAuditPort {

  /**
   * Records a successful role assignment (Group A — atomic, US-018 A6). Joins the caller's
   * transaction and MUST THROW on failure.
   */
  void recordRoleAssigned(RbacAuditEvent event);

  /**
   * Records a successful role revocation (Group A — atomic, US-018 A6). Joins the caller's
   * transaction and MUST THROW on failure.
   */
  void recordRoleRevoked(RbacAuditEvent event);

  /**
   * Records a DENIED role-assignment or revocation attempt (US-014 AC4). Must never throw or
   * block — same contract as the two success methods above.
   *
   * <p>Called INLINE, before the caller throws, from a transaction that is about to roll back:
   * durability rests entirely on the implementation committing in an independent
   * ({@code REQUIRES_NEW}) transaction. Scoped to the 403 authorization denials
   * ({@code CROSS_TENANT_TARGET}, {@code NOT_TENANT_ADMIN}, and from US-018 {@code
   * SELF_ASSIGNMENT} and {@code GRANT_EXCEEDS_CALLER}); never called for the 409 conflicts
   * or the 404s, and never from a read path — an "assignment denied" event for a read is a
   * semantic mislabel, and would also widen the emitting population to every {@code user:read}
   * holder rather than the {@code user:role:assign} holders this event type is scoped to.
   *
   * @param operation the verb being denied, {@code "assign"} or {@code "revoke"} — persisted in
   *     the durable audit metadata (03-design.md D17/RC-13) so assign-side and revoke-side denials
   *     are discriminable in {@code auth_events}. <b>This parameter and the
   *     {@code nexus.rbac.audit_write_failed{operation="deny"}} metric tag are deliberately
   *     different axes and MUST NOT be unified or confused</b>: the metric tag identifies which of
   *     this port's methods failed to write (fixed at {@code "deny"} here, so no existing dashboard
   *     breaks), while this parameter identifies which caller verb produced the denial being
   *     recorded.
   */
  void recordRoleAssignmentDenied(RbacAuditEvent event, DenialReason reason, String operation);

  /**
   * Same contract as {@link #recordRoleAssignmentDenied(RbacAuditEvent, DenialReason, String)},
   * for a grant-subset denial ({@code GRANT_EXCEEDS_CALLER}, US-018 A2, 03-design.md §4.4) that
   * also records how many of the target role's permissions the caller lacked.
   *
   * @param missingCount the NUMBER of missing permissions, persisted as {@code missingCount} in
   *     the audit metadata. Never the ids or names themselves: {@code auth_events} is readable by
   *     {@code audit:read} holders, and the ids would disclose the role's contents. {@code null}
   *     omits the key.
   */
  void recordRoleAssignmentDenied(
      RbacAuditEvent event, DenialReason reason, String operation, Integer missingCount);

  /**
   * Records a successful role creation (AC12, Group A — atomic, US-018 A6). Joins the caller's
   * transaction and MUST THROW on failure. {@code event.permissionId()}/{@code
   * event.permissionName()} are {@code null} — a freshly created role carries no permissions.
   */
  void recordRoleCreated(RoleAuditEvent event);

  /**
   * Records a successful role-permission grant (AC12, Group A — atomic, US-018 A6). Joins the
   * caller's transaction and MUST THROW on failure.
   */
  void recordRolePermissionGranted(RoleAuditEvent event);

  /**
   * Records a successful role-permission revocation (AC12, Group A — atomic, US-018 A6). Joins the
   * caller's transaction and MUST THROW on failure.
   */
  void recordRolePermissionRevoked(RoleAuditEvent event);
}
