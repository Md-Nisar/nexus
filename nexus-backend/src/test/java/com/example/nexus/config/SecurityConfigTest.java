package com.example.nexus.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.application.service.LoginUseCase;
import com.example.nexus.identity.application.service.RefreshTokenUseCase;
import com.example.nexus.identity.domain.LoginResult;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Context integration tests for {@link SecurityConfig}: security rule enforcement, cookie
 * attributes, CORS headers, and absence of HTTP Basic (T-032).
 *
 * <p>Uses H2 in-memory DB (no Docker) with {@code create-drop}. Service-layer beans are replaced
 * with {@link MockBean}s so this test never touches real business logic.
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.MOCK,
    properties = {
        "spring.datasource.url=jdbc:h2:mem:nexus-sec-test;DB_CLOSE_DELAY=-1",
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
class SecurityConfigTest {

  @Autowired private WebApplicationContext ctx;

  @MockitoBean LoginUseCase loginUseCase;
  @MockitoBean RefreshTokenUseCase refreshTokenUseCase;
  @MockitoBean JwtPort jwtPort;
  @MockitoBean AuthEventPort authEventPort;

  private MockMvc mvc;

  private static final String VALID_LOGIN_BODY =
      "{\"email\":\"test@example.com\",\"password\":\"ValidPass99!\"}";

  private static final LoginResult MOCK_LOGIN_RESULT =
      new LoginResult("header.payload.signature", 900L, UUID.randomUUID().toString(), "a".repeat(64));

  @BeforeEach
  void setUp() {
    mvc = MockMvcBuilders.webAppContextSetup(ctx)
        .apply(springSecurity())
        .build();
  }

  // ── Default-deny: protected endpoints require authentication ───────────────

  @Test
  void protected_endpoint_without_token_returns_401() throws Exception {
    mvc.perform(get("/api/v1/users/me"))
        .andExpect(status().isUnauthorized())
        .andExpect(content().contentType("application/problem+json"))
        .andExpect(jsonPath("$.code").value("AUTH_003"))
        .andExpect(jsonPath("$.status").value(401));
  }

  @Test
  void arbitrary_protected_path_returns_401() throws Exception {
    mvc.perform(get("/api/v1/unknown-protected-path"))
        .andExpect(status().isUnauthorized());
  }

  // ── Public paths must not be blocked by the security layer ─────────────────

  @Test
  void public_paths_not_blocked() throws Exception {
    // JWKS endpoint — always 200 regardless of auth state
    mvc.perform(get("/.well-known/jwks.json"))
        .andExpect(status().isOk());

    // Actuator health — public
    mvc.perform(get("/actuator/health"))
        .andExpect(status().isOk());

    // Login — security permits it; controller returns 200 because use case is mocked
    when(loginUseCase.execute(any(), any(), any(), any())).thenReturn(MOCK_LOGIN_RESULT);
    mvc.perform(post("/api/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content(VALID_LOGIN_BODY))
        .andExpect(status().isOk());
  }

  // ── Cookie attributes (T-1.4) ─────────────────────────────────────────────

  @Test
  void login_cookie_attributes() throws Exception {
    when(loginUseCase.execute(any(), any(), any(), any())).thenReturn(MOCK_LOGIN_RESULT);

    mvc.perform(post("/api/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content(VALID_LOGIN_BODY))
        .andExpect(status().isOk())
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("HttpOnly")))
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Secure")))
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("SameSite=Strict")))
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Path=/api/v1/auth")))
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=1209600")));
  }

  @Test
  void logout_clears_cookie_max_age_0() throws Exception {
    mvc.perform(post("/api/v1/auth/logout"))
        .andExpect(status().isNoContent())
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")))
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("HttpOnly")))
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Secure")))
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("SameSite=Strict")))
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Path=/api/v1/auth")));
  }

  // ── CORS (T-1.5) ──────────────────────────────────────────────────────────

  @Test
  void cors_does_not_expose_set_cookie() throws Exception {
    // Set-Cookie is intentionally NOT exposed: the refresh-token cookie is HttpOnly, so
    // JavaScript can never read it regardless of CORS exposure — exposing it would only
    // add attack surface with no functional benefit.
    mvc.perform(options("/api/v1/auth/login")
            .header("Origin", "http://localhost:2000")
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "Content-Type"))
        .andExpect(status().isOk())
        .andExpect(
            header().string("Access-Control-Expose-Headers", not(containsString("Set-Cookie"))));
  }

  @Test
  void cors_allows_credentials() throws Exception {
    mvc.perform(options("/api/v1/auth/login")
            .header("Origin", "http://localhost:2000")
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "Content-Type"))
        .andExpect(status().isOk())
        .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
  }

  // ── Expired / invalid JWT must produce 401, not 500 (T-3.5) ──────────────

  @Test
  void expired_jwt_returns_401_not_500() throws Exception {
    when(jwtPort.verify(any()))
        .thenThrow(new AuthenticationException("AUTH_003", "Token expired or invalid"));

    mvc.perform(get("/api/v1/users/me")
            .header(HttpHeaders.AUTHORIZATION, "Bearer expired.or.invalid.token"))
        .andExpect(status().isUnauthorized())
        .andExpect(content().contentType("application/problem+json"))
        .andExpect(jsonPath("$.code").value("AUTH_003"));
  }

  // ── HTTP Basic is disabled — no WWW-Authenticate challenge ────────────────

  @Test
  void http_basic_removed() throws Exception {
    MvcResult result = mvc.perform(get("/api/v1/users/me"))
        .andExpect(status().isUnauthorized())
        .andReturn();

    assertThat(result.getResponse().getHeader("WWW-Authenticate"))
        .as("WWW-Authenticate: Basic must not be present — HTTP Basic is disabled")
        .isNull();
  }
}
