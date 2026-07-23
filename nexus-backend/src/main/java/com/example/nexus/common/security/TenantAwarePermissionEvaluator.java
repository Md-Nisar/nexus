package com.example.nexus.common.security;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * Evaluates whether the current {@link Authentication} carries a specific RBAC permission,
 * delegating to {@link AuthenticatedRequestDetails} for extraction/validation of the tenant and
 * permission set stashed on the authentication by {@code JwtAuthenticationFilter}.
 *
 * <p>Stateless: no injected dependencies, safe to reference by bean name from SpEL in {@link
 * RequiresPermission}. The bean name {@code permissionEvaluator} must match that SpEL reference
 * case-sensitively.
 *
 * <p><b>Tenant-provenance invariant (threat-model T-02; ADR-0013 amendment).</b> This evaluator
 * performs no tenant-to-tenant comparison of its own (design §B5) — it assumes the {@code
 * permissions[]} entry on {@link Authentication#getDetails()} was already resolved for the same
 * tenant as the {@code tenantId} entry on that same details map. That invariant is guaranteed
 * <b>only</b> by {@code JwtRs256Service.issue}, which sources both the {@code
 * RoleResolutionService} lookup and the {@code tenant_id} claim from the same {@code
 * user.getTenantId()} value, and by {@code JwtAuthenticationFilter}, the sole production code
 * that copies those claims onto an authenticated {@code Authentication}'s details (enforced by
 * an ArchUnit guard in {@code HexagonalArchitectureTest}). Any new code that constructs an
 * authenticated {@code Authentication} carrying a {@code permissions} detail <b>must</b> reuse
 * that same tenant-scoped resolution path — never assemble {@code tenantId} and {@code
 * permissions} from different tenant contexts (e.g. an admin-impersonation/tenant-switch
 * feature, a service-to-service token, or a hand-rolled test principal that leaks into a shared
 * path). A violation here is silent and produces a cross-tenant privilege escalation this
 * evaluator cannot detect. See ADR-0013 for the full rationale.
 */
@Component("permissionEvaluator")
public class TenantAwarePermissionEvaluator {

  /**
   * @param authentication the current authentication
   * @param permission the permission required to proceed
   * @return {@code true} if {@code authentication} carries {@code permission}; this method never
   *     returns {@code false} — every negative path throws {@link
   *     InsufficientPermissionException} instead, so that denials are routed to the specific RBAC
   *     error code rather than falling back to Spring Security's generic access-denied handling
   * @throws InsufficientPermissionException if {@code authentication} is null, unauthenticated,
   *     has malformed details, or lacks {@code permission}
   */
  public boolean hasPermission(Authentication authentication, String permission) {
    AuthenticatedRequestDetails details =
        AuthenticatedRequestDetails.fromAuthentication(authentication, permission);
    if (!details.hasPermission(permission)) {
      throw new InsufficientPermissionException(permission, DenialReason.PERMISSION_ABSENT);
    }
    return true;
  }
}
