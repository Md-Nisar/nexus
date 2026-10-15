package com.example.nexus.rbac.application.port.out;

/**
 * Outbound lookup for the break-glass replay refusal (US-018 A7, RC-37.2, RC-47; 03-design.md
 * §7.2). Implemented in {@code identity.infrastructure.persistence.BreakGlassGrantLookupAdapter}.
 *
 * <p>The lookup is <b>global</b>, not tenant-scoped: a change reference approves one grant
 * anywhere. It is a non-locking read; two concurrent runs with one reference can both pass it,
 * and the per-tenant set lock limits that to two different zero-admin tenants (T-S11, accepted).
 */
public interface BreakGlassGrantLookupPort {

  /**
   * Whether a {@code ROLE_BREAK_GLASS_GRANT} SUCCESS row in any tenant carries exactly {@code
   * changeRef} as its {@code metadata.changeRef}. A failure to answer propagates (fail closed).
   *
   * @param changeRef the validated, canonical change reference
   */
  boolean existsSuccessfulGrantWithChangeRef(String changeRef);
}
