package com.example.nexus.common.security;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.common.web.CorrelationIdFilter;
import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.application.service.LoginUseCase;
import com.example.nexus.identity.application.service.RefreshTokenUseCase;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.support.web.GuardedTestControllerConfig;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * MockMvc-level proof of US-011/T-013 (design §B6): {@code @RequiresPermission} on an arbitrary
 * method — {@link com.example.nexus.support.web.GuardedTestController} — is enforced end-to-end
 * through the real {@code JwtAuthenticationFilter}, real {@code SecurityContextHolder}, real
 * method-security proxy, and real {@link TenantAwarePermissionEvaluator}, mirroring the harness
 * conventions established by {@code SecurityConfigTest}.
 *
 * <p>{@link #permissionEvaluator} is a {@code @MockitoSpyBean} wrapping the real evaluator bean:
 * normal calls execute real logic (so 200/403 outcomes are genuine), while the spy also lets the
 * 401 cases assert {@code Mockito.verifyNoInteractions(permissionEvaluator)} — proving the
 * request never reached method security in the first place.
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.MOCK,
    properties = {
        "spring.datasource.url=jdbc:h2:mem:nexus-requires-permission-test;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.flyway.enabled=false",
        "spring.mail.host=127.0.0.1",
        "spring.mail.properties.mail.smtp.connectiontimeout=200",
        "spring.mail.properties.mail.smtp.timeout=200",
        "nexus.identity.encryption.password=test-enc-password-32-chars-long!!",
        "nexus.identity.encryption.salt=cafebabecafebabecafebabecafebabe",
        "nexus.identity.hmac-key=test-not-a-secret-hmac-key-min-32-bytes!!",
        "nexus.identity.default-tenant-id=00000000-0000-7000-8000-000000000001",
        "nexus.identity.argon2.memory-kb=4096",
        "nexus.identity.argon2.iterations=1",
        "nexus.identity.argon2.parallelism=1",
        "nexus.mail.from-address=test@nexus.test",
        "nexus.frontend.base-url=http://localhost:2000",
        // High ceiling so no test request is throttled
        "nexus.security.rate-limit.ip-max-attempts=1000",
        "nexus.security.rate-limit.ip-window-seconds=60",
        "nexus.security.rate-limit.user-max-attempts=1000",
        "nexus.security.rate-limit.user-window-seconds=900",
        "nexus.security.rate-limit.refresh-max-attempts=1000",
        "feature.nexus-us002-auth-registration.enabled=true",
        "feature.nexus-us003-auth-login.enabled=true",
        // No SMTP server on localhost — disable mail health indicator to keep /actuator/health UP
        "management.health.mail.enabled=false"
    })
@Import(GuardedTestControllerConfig.class)
class RequiresPermissionMockMvcTest {

  @Autowired private WebApplicationContext ctx;

  @MockitoBean LoginUseCase loginUseCase;
  @MockitoBean RefreshTokenUseCase refreshTokenUseCase;
  @MockitoBean JwtPort jwtPort;
  @MockitoBean AuthEventPort authEventPort;

  @MockitoSpyBean private TenantAwarePermissionEvaluator permissionEvaluator;

  private MockMvc mvc;

  private static final String PLACEHOLDER_JWT = "header.payload.signature";

  @BeforeEach
  void setUp() {
    // webAppContextSetup only wires the DispatcherServlet plus whatever is applied explicitly —
    // unlike a real deployment, application @Component filters (e.g. CorrelationIdFilter, which
    // sets the traceId MDC key GlobalExceptionHandler reads) are NOT auto-registered, so it is
    // added explicitly here to exercise the real 403 body shape (traceId) asserted below.
    mvc = MockMvcBuilders.webAppContextSetup(ctx)
        .addFilter(ctx.getBean(CorrelationIdFilter.class))
        .apply(springSecurity())
        .build();
  }

  private JwtClaims claims(List<String> permissions) {
    return new JwtClaims(
        UUID.randomUUID().toString(),
        "00000000-0000-7000-8000-000000000001",
        true,
        List.of(),
        permissions,
        1_000_000_000L,
        9_999_999_999L,
        UUID.randomUUID().toString(),
        0,
        JwtClaims.CURRENT_VERSION);
  }

  @Test
  void should_return200_when_authenticatedCallerHasRequiredPermission() throws Exception {
    when(jwtPort.verify(any())).thenReturn(claims(List.of("tenant:write")));

    mvc.perform(get("/internal-test/guarded")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + PLACEHOLDER_JWT))
        .andExpect(status().isOk());
  }

  @Test
  void should_return403WithRbac001Shape_when_authenticatedCallerLacksRequiredPermission()
      throws Exception {
    when(jwtPort.verify(any())).thenReturn(claims(List.of("user:read")));

    mvc.perform(get("/internal-test/guarded")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + PLACEHOLDER_JWT))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("RBAC_001"))
        .andExpect(
            jsonPath("$.detail").value("You do not have permission to perform this action"))
        .andExpect(jsonPath("$.requiredPermission").value("tenant:write"))
        .andExpect(jsonPath("$.traceId").isNotEmpty());
  }

  @Test
  void should_return401Auth003_when_noJwtPresented() throws Exception {
    mvc.perform(get("/internal-test/guarded"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("AUTH_003"));

    Mockito.verifyNoInteractions(permissionEvaluator);
  }

  @Test
  void should_return401_when_jwtIsTamperedAndFilterRejectsBeforeEvaluator() throws Exception {
    when(jwtPort.verify(any()))
        .thenThrow(new AuthenticationException("AUTH_003", "Token expired or invalid"));

    mvc.perform(get("/internal-test/guarded")
            .header(HttpHeaders.AUTHORIZATION, "Bearer tampered.or.invalid.token"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("AUTH_003"));

    Mockito.verifyNoInteractions(permissionEvaluator);
  }

  @Test
  void should_remainReachable_when_permitAllEndpointHitWithMethodSecurityEnabled()
      throws Exception {
    mvc.perform(get("/actuator/health"))
        .andExpect(status().isOk());
  }

  @Test
  void should_return200_when_authenticatedCallerHasPermissionOnFreshFixtureMethod()
      throws Exception {
    when(jwtPort.verify(any())).thenReturn(claims(List.of("user:read")));

    mvc.perform(get("/internal-test/guarded-user-read")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + PLACEHOLDER_JWT))
        .andExpect(status().isOk());
  }

  @Test
  void should_return403_when_authenticatedCallerLacksPermissionOnFreshFixtureMethod()
      throws Exception {
    when(jwtPort.verify(any())).thenReturn(claims(List.of("tenant:write")));

    mvc.perform(get("/internal-test/guarded-user-read")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + PLACEHOLDER_JWT))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("RBAC_001"))
        .andExpect(jsonPath("$.requiredPermission").value("user:read"));
  }

  // --- Documented Spring AOP proxy-shape limitations (RequiresPermission Javadoc; threat-model
  // T-05; security-review F-1) — regression tests locking in the *known, accepted* bypasses so a
  // future Spring upgrade that silently changes this behaviour (in either direction) is caught,
  // rather than resting solely on a Javadoc claim nobody re-verifies.

  @Test
  void should_return403_when_sameMethodCalledExternallyThroughTheProxyWithoutPermission()
      throws Exception {
    when(jwtPort.verify(any())).thenReturn(claims(List.of("user:read")));

    mvc.perform(get("/internal-test/guarded-external-only")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + PLACEHOLDER_JWT))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("RBAC_001"));
  }

  @Test
  void should_bypassPermissionCheck_when_annotatedMethodInvokedViaSelfInvocation()
      throws Exception {
    when(jwtPort.verify(any())).thenReturn(claims(List.of("user:read")));

    mvc.perform(get("/internal-test/self-invoke")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + PLACEHOLDER_JWT))
        .andExpect(status().isOk());
  }

  @Test
  void should_bypassPermissionCheck_when_annotatedMethodIsFinal() throws Exception {
    when(jwtPort.verify(any())).thenReturn(claims(List.of("user:read")));

    mvc.perform(get("/internal-test/guarded-final")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + PLACEHOLDER_JWT))
        .andExpect(status().isOk());
  }
}
