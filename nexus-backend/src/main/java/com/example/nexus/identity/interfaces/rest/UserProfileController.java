package com.example.nexus.identity.interfaces.rest;

import com.example.nexus.common.security.AuthenticationDetailKeys;
import com.example.nexus.identity.interfaces.rest.dto.MeResponse;
import java.util.List;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes the authenticated user's profile, derived entirely from the JWT claims
 * stored in {@link Authentication#getDetails()} — no database call required.
 */
@RestController
@RequestMapping("/api/v1/users")
@ConditionalOnProperty(name = "feature.nexus-us003-auth-login.enabled", havingValue = "true")
public class UserProfileController {

  @GetMapping("/me")
  MeResponse me(Authentication authentication) {
    Map<?, ?> details = (Map<?, ?>) authentication.getDetails();
    List<String> roles = authentication.getAuthorities().stream()
        .map(a -> a.getAuthority().replace("ROLE_", ""))
        .toList();
    Object tokenVersionObj = details.get(AuthenticationDetailKeys.TOKEN_VERSION);
    int tokenVersion = tokenVersionObj instanceof Number n ? n.intValue() : 0;
    // Sourced from the JWT's permissions[] claim (itself resolved by RoleResolutionService at
    // token-mint time), not a fresh lookup — this endpoint makes no DB call (US-010 AC8).
    Object permissionsObj = details.get(AuthenticationDetailKeys.PERMISSIONS);
    List<String> permissions =
        permissionsObj instanceof List<?> list
            ? list.stream().map(String.class::cast).toList()
            : List.of();
    return new MeResponse(
        (String) authentication.getPrincipal(),
        Boolean.TRUE.equals(details.get(AuthenticationDetailKeys.EMAIL_VERIFIED)),
        (String) details.get(AuthenticationDetailKeys.TENANT_ID),
        roles,
        permissions,
        tokenVersion);
  }
}
