package com.example.nexus.rbac.application.port.out;

import java.util.UUID;

/**
 * D14 / RC-10 (03-design.md §4.8). Denial throttle for the privileged role-change gate,
 * bounding the cost of repeated authorization denials on {@code assign()}/{@code revoke()}.
 *
 * <p>Declares two methods per §4.8's normative Javadoc, not the §2 architecture diagram's
 * single-method {@code tryConsumeDenial} label — the diagram is a drafting artefact; §4.8
 * governs (A-1).
 *
 * <p>Deliberately declares no throttle mechanism: no {@code RateLimitStore}, no
 * {@code RateLimitResult}, nothing outside {@code java.util}. The implementing adapter lives in
 * {@code identity.infrastructure.security}, keeping the dependency direction
 * {@code identity -> rbac} and this module's ArchUnit rule
 * ({@code HexagonalArchitectureTest.rbac_must_not_depend_on_identity}) green.
 */
public interface RoleChangeThrottlePort {

  /**
   * Is this actor currently throttled in this tenant? Keyed by {@code (tenantId, actorUserId)}
   * — never by IP (this path is authenticated; IP is neither stable nor attributable here) and
   * never by target (an attacker chooses the target freely).
   *
   * <p>MUST fail SAFE and MUST NOT throw: an unavailable throttle store returns {@code false}
   * ("not throttled"), so the gate's own authorization decision — which is authoritative — still
   * runs. The throttle bounds cost, it is not an authorization control, and must never be able to
   * <b>permit</b> anything.
   *
   * @param tenantId the tenant the role-change request targets
   * @param actorUserId the caller attempting the role change
   * @return {@code true} iff this actor has crossed the denial bound in the current window
   */
  boolean isThrottled(UUID tenantId, UUID actorUserId);

  /**
   * Records one privilege-gate denial against the {@code (tenantId, actorUserId)} bucket. Never
   * throws.
   *
   * <p><b>Deviation from §4.8 (A-3):</b> the design's verbatim signature returns {@code void}.
   * This port returns {@code boolean} — {@code true} iff <i>this</i> denial is the one that
   * crossed the bound — because {@code RBAC_DENIAL_THROTTLE_ENGAGED} must be emitted exactly
   * once, on the transition into the throttled state, carrying {@code operation}, which is known
   * only to the service calling this method, not to the throttle. A {@code void} signature would
   * leave the service with no way to detect the transition without a second, redundant query.
   *
   * @param tenantId the tenant the denied role-change request targeted
   * @param actorUserId the caller whose request was denied
   * @return {@code true} iff this denial is the one that crossed {@code max-denials} within
   *     {@code window-seconds}, i.e. the transition into the throttled state
   */
  boolean recordDenial(UUID tenantId, UUID actorUserId);
}
