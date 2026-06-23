package com.example.nexus.identity.interfaces.rest;

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
    Object tokenVersionObj = details.get("tokenVersion");
    int tokenVersion = tokenVersionObj instanceof Number n ? n.intValue() : 0;
    return new MeResponse(
        (String) authentication.getPrincipal(),
        Boolean.TRUE.equals(details.get("emailVerified")),
        (String) details.get("tenantId"),
        roles,
        tokenVersion);
  }
}
