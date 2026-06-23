package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.nexus.identity.interfaces.rest.dto.MeResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class UserProfileControllerTest {

  private UserProfileController controller;
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    controller = new UserProfileController();
    mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
  }

  @Test
  void me_returnsProfile_from_authenticationDetails() {
    Authentication auth = buildAuthentication(
        "user-uuid-1", "tenant-uuid-1", true, List.of("USER"), 2);

    MeResponse response = controller.me(auth);

    assertThat(response.userId()).isEqualTo("user-uuid-1");
    assertThat(response.tenantId()).isEqualTo("tenant-uuid-1");
    assertThat(response.emailVerified()).isTrue();
    assertThat(response.roles()).containsExactly("USER");
    assertThat(response.tokenVersion()).isEqualTo(2);
  }

  @Test
  void me_stripsRolePrefix() {
    Authentication auth = buildAuthentication(
        "user-uuid-2", "tenant-uuid-2", false, List.of("ADMIN"), 0);

    MeResponse response = controller.me(auth);

    assertThat(response.roles()).containsExactly("ADMIN");
  }

  private static Authentication buildAuthentication(
      String sub, String tenantId, boolean emailVerified, List<String> roles, int tokenVersion) {
    var authorities = roles.stream()
        .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
        .toList();
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(sub, null, authorities);
    auth.setDetails(Map.of(
        "tenantId", tenantId,
        "emailVerified", emailVerified,
        "tokenVersion", tokenVersion));
    return auth;
  }
}
