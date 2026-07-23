package com.example.nexus.common.security;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.core.Authentication;

/**
 * Snapshot of the RBAC-relevant details stashed on the {@link Authentication} by {@code
 * JwtAuthenticationFilter}: the caller's tenant and resolved permission set.
 *
 * <p>{@link #fromAuthentication(Authentication, String)} validates the shape of {@link
 * Authentication#getDetails()} defensively — it does not trust that the details map was populated
 * correctly upstream — and throws {@link InsufficientPermissionException} on any malformed input,
 * fail-closed, rather than a generic exception. The {@code requiredPermission} argument exists
 * solely to construct that exception; it is not otherwise used by this factory.
 *
 * <p>{@code tenantId} is treated as an opaque string: no trimming, case-folding, or comparison is
 * performed here (design §B5).
 */
public record AuthenticatedRequestDetails(String tenantId, Set<String> permissions) {

  public AuthenticatedRequestDetails {
    permissions = Set.copyOf(permissions);
  }

  /**
   * Builds an {@link AuthenticatedRequestDetails} from the given {@link Authentication}.
   *
   * @param authentication the current authentication; must be non-null, authenticated, and carry
   *     a {@code Map} details object with a non-blank string {@code tenantId} and a {@code List}
   *     of string {@code permissions}
   * @param requiredPermission the permission the caller was attempting to exercise; used only to
   *     construct {@link InsufficientPermissionException} if validation fails
   * @return the validated tenant/permissions snapshot
   * @throws InsufficientPermissionException if {@code authentication} is null, unauthenticated,
   *     or its details are missing/malformed in any of the ways described above
   */
  public static AuthenticatedRequestDetails fromAuthentication(
      Authentication authentication, String requiredPermission) {
    if (authentication == null || !authentication.isAuthenticated()) {
      throw new InsufficientPermissionException(
          requiredPermission, DenialReason.MALFORMED_AUTHENTICATION);
    }
    if (!(authentication.getDetails() instanceof Map<?, ?> details)) {
      throw new InsufficientPermissionException(
          requiredPermission, DenialReason.MALFORMED_AUTHENTICATION);
    }
    if (!(details.get(AuthenticationDetailKeys.TENANT_ID) instanceof String tenantId)
        || tenantId.isBlank()) {
      throw new InsufficientPermissionException(requiredPermission, DenialReason.MISSING_TENANT);
    }
    if (!(details.get(AuthenticationDetailKeys.PERMISSIONS) instanceof List<?> rawPermissions)
        || !rawPermissions.stream().allMatch(String.class::isInstance)) {
      throw new InsufficientPermissionException(
          requiredPermission, DenialReason.MALFORMED_AUTHENTICATION);
    }
    Set<String> permissions =
        rawPermissions.stream().map(String.class::cast).collect(Collectors.toSet());
    return new AuthenticatedRequestDetails(tenantId, permissions);
  }

  /**
   * @param permission the permission to check
   * @return {@code true} if {@code permission} is present in {@link #permissions()}; never throws
   */
  public boolean hasPermission(String permission) {
    return permissions.contains(permission);
  }
}
