package com.example.nexus.rbac.interfaces.rest;

import com.example.nexus.common.domain.FieldValidationException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.security.AuthenticatedRequestDetails;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.rbac.domain.RoleChangeActor;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;

/**
 * Shared fail-closed helper backing every RBAC controller handler (US-012's {@code
 * UserRoleController} and US-015's {@code RoleController}/{@code PermissionController}) —
 * 03-design.md §4.1 D4.
 *
 * <p><b>Why extract at all:</b> three copies of a fail-closed security helper is the failure
 * mode this class exists to avoid — divergence between copies is invisible until one of them is
 * the one that fails open (threat-model.md T-S6).
 *
 * <p><b>Why {@code final}, a private constructor, and only {@code static} methods (T-S6):</b> no
 * subclass can override a branch, and there is no instance state to reason about.
 *
 * <p>Package-private deliberately, not {@code public}: kept inside {@code rbac.interfaces.rest} so
 * it stays visible to {@code rbac_must_not_depend_on_identity}'s intent and to human review, rather
 * than living in a neutral {@code common.web} package that would recreate cross-context coupling
 * with the rule still green.
 */
final class RbacControllerSupport {

  private static final Pattern CANONICAL_UUID =
      Pattern.compile(
          "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

  private RbacControllerSupport() {}

  /**
   * Unwraps {@code authentication} into a {@link RoleChangeActor}. Tenant provenance is delegated
   * to {@link AuthenticatedRequestDetails#fromAuthentication}, which already fails closed
   * (malformed details → {@code MALFORMED_AUTHENTICATION}; blank/absent tenant → {@code
   * MISSING_TENANT}).
   *
   * <p><b>Principal provenance must fail closed too (T-S4).</b> {@code
   * authentication.getPrincipal()} is not guaranteed by any compile-time contract to be a
   * parseable UUID string. A null, non-{@code String}, or non-UUID principal must not be allowed
   * to throw an unhandled {@code ClassCastException}/{@code IllegalArgumentException} that falls
   * through to the generic 500 handler — it must throw {@link InsufficientPermissionException}
   * with {@link DenialReason#MALFORMED_AUTHENTICATION} instead.
   */
  static RoleChangeActor resolveActor(Authentication authentication, String requiredPermission) {
    AuthenticatedRequestDetails details =
        AuthenticatedRequestDetails.fromAuthentication(authentication, requiredPermission);

    if (!(authentication.getPrincipal() instanceof String principalId)) {
      throw new InsufficientPermissionException(
          requiredPermission, DenialReason.MALFORMED_AUTHENTICATION);
    }
    UUID actorUserId;
    try {
      actorUserId = UUID.fromString(principalId);
    } catch (IllegalArgumentException e) {
      throw new InsufficientPermissionException(
          requiredPermission, DenialReason.MALFORMED_AUTHENTICATION);
    }
    UUID tenantId;
    try {
      tenantId = UUID.fromString(details.tenantId());
    } catch (IllegalArgumentException e) {
      // Distinct from the principal-parse failure above (03-design.md §4.1, §8.5 row 4): an
      // unparseable tenantId is MISSING_TENANT, not MALFORMED_AUTHENTICATION.
      throw new InsufficientPermissionException(requiredPermission, DenialReason.MISSING_TENANT);
    }
    return new RoleChangeActor(actorUserId, tenantId);
  }

  /**
   * Validates {@code value} as a canonical-UUID-shaped string and parses it, in that order (D15).
   * A malformed value throws {@link FieldValidationException}, which {@code
   * GlobalExceptionHandler#handleFieldValidation} already maps to 400 with a {@code details[]}
   * entry naming {@code field} — never a raw {@code UUID.fromString} failure reaching an
   * unhandled-exception path.
   */
  static UUID parsePathUuid(String value, String field) {
    if (value == null || !CANONICAL_UUID.matcher(value).matches()) {
      throw new FieldValidationException("VALIDATION_FAILED", field, "must be a canonical UUID");
    }
    return UUID.fromString(value);
  }

  /**
   * Constructs a {@link RequestContext} from the HTTP request, mirroring {@code
   * RegistrationController#requestContext} exactly (client IP, MDC trace ID, User-Agent header).
   */
  static RequestContext requestContext(HttpServletRequest req) {
    return RequestContext.of(req.getRemoteAddr(), MDC.get("traceId"), req.getHeader("User-Agent"));
  }
}
