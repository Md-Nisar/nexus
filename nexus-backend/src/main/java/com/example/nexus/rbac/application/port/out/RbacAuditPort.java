package com.example.nexus.rbac.application.port.out;

/**
 * Outbound audit port for RBAC authorization changes (03-design.md §4.5). Implemented by {@code
 * identity.infrastructure.audit.RbacAuthEventAdapter}, which delegates to {@code
 * SecureEventService} ({@code REQUIRES_NEW}) so {@code rbac} gets audit durability for free without
 * importing {@code identity}.
 *
 * <p><b>Contract (restating {@code AuthEventPort.record}'s guarantee): implementations MUST NEVER
 * throw and MUST NOT block.</b> On failure they must swallow their own failures — buffering for
 * bounded backed-off retry, or logging and continuing — and never propagate to the caller. Callers
 * invoke these methods after commit (or, absent an active transaction, inline as a best-effort
 * fallback) and do not handle exceptions from them.
 */
public interface RbacAuditPort {

  /** Records a successful role assignment. Must never throw or block. */
  void recordRoleAssigned(RbacAuditEvent event);

  /** Records a successful role revocation. Must never throw or block. */
  void recordRoleRevoked(RbacAuditEvent event);
}
