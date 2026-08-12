package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.identity.interfaces.rest.dto.MeResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;


@Tag("UnitTest")
class UserProfileControllerTest {

  private UserProfileController controller;


  @BeforeEach
  void setUp() {
    controller = new UserProfileController();
  }

  @Test
  void me_returnsProfile_from_authenticationDetails() {
    Authentication auth = buildAuthentication(
        "user-uuid-1",
        "tenant-uuid-1",
        true,
        List.of("USER"),
        List.of("tenant:read", "tenant:write"),
        2);

    MeResponse response = controller.me(auth);

    assertThat(response.userId()).isEqualTo("user-uuid-1");
    assertThat(response.tenantId()).isEqualTo("tenant-uuid-1");
    assertThat(response.emailVerified()).isTrue();
    assertThat(response.roles()).containsExactly("USER");
    assertThat(response.permissions()).containsExactly("tenant:read", "tenant:write");
    assertThat(response.tokenVersion()).isEqualTo(2);
  }

  @Test
  void me_stripsRolePrefix() {
    Authentication auth = buildAuthentication(
        "user-uuid-2", "tenant-uuid-2", false, List.of("ADMIN"), List.of(), 0);

    MeResponse response = controller.me(auth);

    assertThat(response.roles()).containsExactly("ADMIN");
  }

  @Test
  void me_defaultsPermissionsToEmpty_when_detailsMissingPermissions() {
    // No "permissions" key at all — must degrade to empty, never throw (AC4 spirit).
    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
        "user-uuid-3", null, List.of(new SimpleGrantedAuthority("ROLE_MEMBER")));
    auth.setDetails(Map.of(
        "tenantId", "tenant-uuid-3",
        "emailVerified", true,
        "tokenVersion", 0));

    MeResponse response = controller.me(auth);

    assertThat(response.permissions()).isEmpty();
  }

  private static Authentication buildAuthentication(
      String sub,
      String tenantId,
      boolean emailVerified,
      List<String> roles,
      List<String> permissions,
      int tokenVersion) {
    var authorities = roles.stream()
        .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
        .toList();
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(sub, null, authorities);
    auth.setDetails(Map.of(
        "tenantId", tenantId,
        "emailVerified", emailVerified,
        "tokenVersion", tokenVersion,
        "permissions", permissions));
    return auth;
  }
}
