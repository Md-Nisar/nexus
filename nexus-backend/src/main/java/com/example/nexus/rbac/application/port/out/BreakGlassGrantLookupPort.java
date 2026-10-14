package com.example.nexus.rbac.application.port.out;

/**
 * Outbound port for the break-glass replay check (US-018 A7, RC-37.2, RC-47). Implemented in
 * {@code identity.infrastructure.audit} over {@code auth_events}.
 */
public interface BreakGlassGrantLookupPort {

  /**
   * Whether a change reference already appears on a SUCCESS {@code ROLE_BREAK_GLASS_GRANT} row in
   * <b>any</b> tenant. A change reference approves one grant anywhere, so the lookup is global, not
   * tenant-scoped (T-S11). The comparison is exact and parameter-bound; one non-locking read.
   *
   * <p>Not atomic with the grant: two concurrent runs with one reference can both pass it. That is
   * accepted (T-S11) and bounded by the set lock to two different zero-administrator tenants; the
   * runbook allows one invocation at a time per reference.
   */
  boolean existsSuccessfulGrantWithChangeRef(String changeRef);
}
