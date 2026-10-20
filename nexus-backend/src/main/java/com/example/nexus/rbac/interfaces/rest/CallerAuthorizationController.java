package com.example.nexus.rbac.interfaces.rest;

import com.example.nexus.common.security.AuthenticatedEndpoint;
import com.example.nexus.rbac.application.CallerAuthorizationService;
import com.example.nexus.rbac.application.CallerAuthorizationService.CallerAuthorization;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.interfaces.rest.dto.CallerAuthorizationResponse;
import com.example.nexus.rbac.interfaces.rest.dto.CallerAuthorizationResponse.RoleEntry;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * US-019 B4 (03-design.md §6): the signed-in caller's own live authorization profile, which the
 * access-management UI uses to decide its affordances. The server stays authoritative for every
 * action.
 *
 * <p>{@code @AuthenticatedEndpoint}: no permission is needed, so the only parameter is {@link
 * Authentication} and the caller is addressed through the principal and the token's tenant
 * (T-S13; {@code HexagonalArchitectureTest.authenticated_endpoints_take_no_uuid_identifier}).
 * Rides the {@code feature.nexus-us019-user-directory} flag (Gate 1 Q6); off, the route is the
 * generic 404. The response is not cacheable: Spring Security's default {@code Cache-Control:
 * no-cache, no-store} header applies.
 */
@RestController
@ConditionalOnProperty(name = "feature.nexus-us019-user-directory.enabled", havingValue = "true")
@Tag(name = "Caller Authorization", description = "The signed-in caller's own roles and permissions")
public class CallerAuthorizationController {

  /**
   * The label {@link RbacControllerSupport#resolveActor} reports if the principal or tenant is
   * malformed. This handler requires no permission, so it names the requirement it does have.
   */
  private static final String AUTHENTICATED = "authenticated";

  private final CallerAuthorizationService callerAuthorizationService;

  public CallerAuthorizationController(CallerAuthorizationService callerAuthorizationService) {
    this.callerAuthorizationService = callerAuthorizationService;
  }

  @GetMapping("/api/v1/users/me/authorization")
  @AuthenticatedEndpoint
  @Operation(summary = "The caller's own live roles, permissions and administrator status")
  @ApiResponse(responseCode = "200", description = "The caller's authorization profile")
  @ApiResponse(responseCode = "401", description = "No or invalid bearer token")
  @ApiResponse(responseCode = "404", description = "Feature disabled")
  public CallerAuthorizationResponse authorization(Authentication authentication) {
    RoleChangeActor actor = RbacControllerSupport.resolveActor(authentication, AUTHENTICATED);
    CallerAuthorization profile = callerAuthorizationService.read(actor);
    return new CallerAuthorizationResponse(
        actor.userId().toString(),
        profile.roles().stream()
            .map(role -> new RoleEntry(role.roleId().toString(), role.name()))
            .toList(),
        profile.permissions(),
        profile.isAdministrator());
  }
}
