package com.example.nexus.rbac.application.port.out;

import com.example.nexus.common.security.DenialReason;

/**
 * Outbound audit port for RBAC authorization changes (03-design.md §4.5). Implemented by {@code
 * identity.infrastructure.audit.RbacAuthEventAdapter}, which delegates to {@code
 * SecureEventService} ({@code REQUIRES_NEW}) so {@code rbac} gets audit durability for free without
 * importing {@code identity}.
 *
 * <p><b>Contract (restating {@code AuthEventPort.record}'s guarantee): implementations MUST NEVER
 * throw and MUST NOT block.</b> On failure they must swallow their own failures — buffering for
 * bounded backed-off retry, or logging and continuing — and never propagate to the caller. Callers
 * invoke {@link #recordRoleAssigned} and {@link #recordRoleRevoked} after commit (or, absent an
 * active transaction, inline as a best-effort fallback); {@link #recordRoleAssignmentDenied} is
 * invoked inline, pre-throw, before the caller's transaction commits or rolls back — see its own
 * Javadoc. No caller handles exceptions from any of the three.
 */
public interface RbacAuditPort {

  /** Records a successful role assignment. Must never throw or block. */
  void recordRoleAssigned(RbacAuditEvent event);

  /** Records a successful role revocation. Must never throw or block. */
  void recordRoleRevoked(RbacAuditEvent event);

  /**
   * Records a DENIED role-assignment or revocation attempt (US-014 AC4). Must never throw or
   * block — same contract as the two success methods above.
   *
   * <p>Called INLINE, before the caller throws, from a transaction that is about to roll back:
   * durability rests entirely on the implementation committing in an independent
   * ({@code REQUIRES_NEW}) transaction. Scoped to the two 403 authorization denials
   * ({@code CROSS_TENANT_TARGET}, {@code NOT_TENANT_ADMIN}); never called for the 409 conflicts
   * or the 404s, and never from a read path — an "assignment denied" event for a read is a
   * semantic mislabel, and would also widen the emitting population to every {@code user:read}
   * holder rather than the {@code user:write} holders this event type is scoped to.
   */
  void recordRoleAssignmentDenied(RbacAuditEvent event, DenialReason reason);
}
