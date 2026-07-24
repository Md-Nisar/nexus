package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.domain.AccessTokenResult;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.rbac.application.RoleResolutionService;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;

/**
 * US-010 AC5 / Test Scenario 5: with the maximum realistic role/permission set (5 roles, 20
 * permissions), the compact JWT must stay under 4KB.
 */
@Tag("UnitTest")
class JwtSizeBenchmarkTest {

  private static RsaKeyConfig rsaKeyConfig;

  @BeforeAll
  static void setUpKeyConfig() throws Exception {
    Environment devEnv = mock(Environment.class);
    when(devEnv.getActiveProfiles()).thenReturn(new String[] {"dev"});
    rsaKeyConfig = new RsaKeyConfig(devEnv);
    rsaKeyConfig.init();
  }

  @Test
  void should_stayUnder4KB_when_userHasFiveRolesAndTwentyPermissions() {
    List<String> roles =
        IntStream.rangeClosed(1, 5).mapToObj(i -> "ROLE_" + i).toList();
    List<String> permissions =
        IntStream.rangeClosed(1, 20).mapToObj(i -> "resource" + i + ":action").toList();

    RoleResolutionService roleResolutionService = mock(RoleResolutionService.class);
    when(roleResolutionService.resolve(any(), any()))
        .thenReturn(new ResolvedPermissions(roles, permissions));

    JwtRs256Service svc =
        new JwtRs256Service(rsaKeyConfig, UUID::randomUUID, Clock.systemUTC(), 900L,
            roleResolutionService);

    User user = mock(User.class);
    when(user.getId()).thenReturn(UUID.randomUUID());
    when(user.getTenantId()).thenReturn(UUID.randomUUID());
    when(user.getStatus()).thenReturn(UserStatus.ACTIVE);
    when(user.getTokenVersion()).thenReturn(0);

    AccessTokenResult result = svc.issue(user);
    int tokenSizeBytes = result.token().getBytes(StandardCharsets.UTF_8).length;

    assertThat(tokenSizeBytes).isLessThan(4096);
  }
}
