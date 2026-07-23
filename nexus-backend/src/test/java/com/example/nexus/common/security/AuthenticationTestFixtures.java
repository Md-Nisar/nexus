package com.example.nexus.common.security;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Shared test fixtures for building an {@link Authentication} with a given {@code details}
 * payload, used by {@link TenantAwarePermissionEvaluatorTest} and {@link
 * AuthenticatedRequestDetailsTest} to exercise the same {@code Authentication.getDetails()}
 * contract without duplicating the helper in both classes.
 */
final class AuthenticationTestFixtures {

  private AuthenticationTestFixtures() {}

  static Authentication authenticationWithDetails(Object details) {
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(
            "user-1", null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
    auth.setDetails(details);
    return auth;
  }

  static Authentication authenticatedWith(String tenantId, List<String> permissions) {
    Map<String, Object> details = new HashMap<>();
    details.put("tenantId", tenantId);
    details.put("permissions", permissions);
    return authenticationWithDetails(details);
  }
}
