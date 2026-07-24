package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.example.nexus.TestcontainersConfiguration;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Integration tests for the sliding-window rate limiter on the login endpoint.
 *
 * <p>Same package as {@link InMemoryRateLimitStore} to access the package-private
 * {@code storeSize()} method. Each test uses a unique IP prefix to avoid cross-test
 * pollution in the shared in-memory store.
 *
 * <p>{@code @SpringBootTest(properties)} pins ip-max-attempts=3, ip-window-seconds=10,
 * user-max-attempts=3, user-window-seconds=10 so rate-limit behaviour is observable in a
 * handful of requests. The high values in application-test.yml are intentional for lockout ITs.
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.MOCK,
    properties = {
        // Override the high-throughput values from application-test.yml (designed for lockout ITs)
        // with low thresholds so rate-limit behaviour is observable in a handful of requests.
        "nexus.security.rate-limit.ip-max-attempts=3",
        "nexus.security.rate-limit.ip-window-seconds=10",
        "nexus.security.rate-limit.user-max-attempts=3",
        "nexus.security.rate-limit.user-window-seconds=10"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class RateLimitIT {

  @Autowired private WebApplicationContext ctx;

  private MockMvc mvc;

  @BeforeEach
  void setUp() {
    mvc = MockMvcBuilders.webAppContextSetup(ctx)
        .apply(springSecurity())
        .build();
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private MockHttpServletRequestBuilder asIp(MockHttpServletRequestBuilder builder, String ip) {
    return builder.with(req -> {
      req.setRemoteAddr(ip);
      return req;
    });
  }

  private ResultActions postLogin(String ip, String email, String password) throws Exception {
    return mvc.perform(asIp(
        post("/api/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"),
        ip));
  }

  // ── Tests ─────────────────────────────────────────────────────────────────

  /**
   * After 3 allowed attempts (the configured max), the 4th attempt from the same IP
   * is rate-limited with HTTP 429 and a numeric Retry-After header.
   */
  @Test
  void login_rate_limit_by_ip() throws Exception {
    String ip = "10.1.0.1";
    String email = "rl-ip-" + UUID.randomUUID() + "@example.com";

    // 3 attempts are allowed (any non-429 response)
    for (int i = 0; i < 3; i++) {
      int status = postLogin(ip, email, "WrongPass99!")
          .andReturn().getResponse().getStatus();
      assertThat(status).as("attempt %d should not be rate-limited", i + 1).isNotEqualTo(429);
    }

    // 4th attempt must be rate-limited
    var result = postLogin(ip, email, "WrongPass99!")
        .andReturn().getResponse();
    assertThat(result.getStatus()).isEqualTo(429);
    String retryAfter = result.getHeader("Retry-After");
    assertThat(retryAfter).as("Retry-After header must be present on 429").isNotNull();
    assertThat(Long.parseLong(retryAfter)).as("Retry-After must be positive").isGreaterThan(0L);
  }

  /**
   * 3 different IPs hitting the same email address exhaust the USER key.
   * A 4th attempt from a brand-new IP is still blocked (USER key exhausted).
   */
  @Test
  void login_rate_limit_by_username() throws Exception {
    String email = "rl-user-" + UUID.randomUUID() + "@example.com";

    // Attempts from 3 unique IPs — each allowed because IP keys are fresh
    for (int i = 1; i <= 3; i++) {
      String ip = "10.2.0." + i;
      int status = postLogin(ip, email, "WrongPass99!")
          .andReturn().getResponse().getStatus();
      assertThat(status).as("attempt %d from ip %s should be allowed", i, ip).isNotEqualTo(429);
    }

    // 4th attempt: new IP (IP key is empty) but USER key is exhausted → 429
    int status = postLogin("10.2.0.4", email, "WrongPass99!")
        .andReturn().getResponse().getStatus();
    assertThat(status).as("4th attempt against same email must be 429 (USER key exhausted)")
        .isEqualTo(429);
  }

  /**
   * After the window expires (> 10 s), the rate-limit resets and a new attempt is allowed.
   * Note: this test deliberately sleeps 11 s.
   */
  @Test
  void rate_limit_resets_after_window() throws Exception {
    String ip = "10.3.0.1";
    String email = "rl-win-" + UUID.randomUUID() + "@example.com";

    // Exhaust the limit
    for (int i = 0; i < 3; i++) {
      postLogin(ip, email, "WrongPass99!");
    }
    // 4th attempt must be blocked
    int blockedStatus = postLogin(ip, email, "WrongPass99!")
        .andReturn().getResponse().getStatus();
    assertThat(blockedStatus).as("should be rate-limited before window expires").isEqualTo(429);

    // Wait for the 10-second window to expire
    Thread.sleep(11_000L);

    // After reset, a new attempt must not be 429
    int afterReset = postLogin(ip, email, "WrongPass99!")
        .andReturn().getResponse().getStatus();
    assertThat(afterReset).as("should be allowed after window reset").isNotEqualTo(429);
  }

  /**
   * X-Forwarded-For header is completely ignored; rate-limiting uses
   * {@code request.getRemoteAddr()} only (T-1.3).
   */
  @Test
  void spoof_xff_does_not_bypass_ip_limit() throws Exception {
    String ip = "10.4.0.1";
    String email = "rl-xff-" + UUID.randomUUID() + "@example.com";

    // 3 attempts with a spoofed XFF header — the filter reads getRemoteAddr() so IP key fills up
    for (int i = 0; i < 3; i++) {
      int status = mvc.perform(asIp(
              post("/api/v1/auth/login")
                  .contentType(MediaType.APPLICATION_JSON)
                  .content("{\"email\":\"" + email + "\",\"password\":\"WrongPass99!\"}")
                  .header("X-Forwarded-For", "9.9.9.9"),
              ip))
          .andReturn().getResponse().getStatus();
      assertThat(status).as("attempt %d with XFF should not be 429 yet", i + 1).isNotEqualTo(429);
    }

    // 4th attempt: same XFF but getRemoteAddr()="10.4.0.1" is exhausted → 429
    int status = mvc.perform(asIp(
            post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\",\"password\":\"WrongPass99!\"}")
                .header("X-Forwarded-For", "9.9.9.9"),
            ip))
        .andReturn().getResponse().getStatus();
    assertThat(status).as("4th attempt with XFF must be 429 — XFF does not bypass IP limit")
        .isEqualTo(429);
  }

  /**
   * Exhausting IP-A's rate-limit does not affect IP-B: independent counters per IP.
   * Each IP uses a distinct email so the USER key is not shared and cannot cross-pollute.
   */
  @Test
  void different_ips_have_independent_counters() throws Exception {
    // Distinct emails per IP: prevents the shared USER key from exhausting and blocking IP-B
    String emailA = "rl-ind-a-" + UUID.randomUUID() + "@example.com";
    String emailB = "rl-ind-b-" + UUID.randomUUID() + "@example.com";
    String ipA = "10.6.0.1";
    String ipB = "10.6.0.2";

    // Exhaust IP-A with emailA
    for (int i = 0; i < 3; i++) {
      postLogin(ipA, emailA, "WrongPass99!");
    }
    int blockedA = postLogin(ipA, emailA, "WrongPass99!")
        .andReturn().getResponse().getStatus();
    assertThat(blockedA).as("IP-A 4th attempt must be 429").isEqualTo(429);

    // IP-B with emailB (fresh IP key AND fresh USER key) must not be rate-limited
    int statusB = postLogin(ipB, emailB, "WrongPass99!")
        .andReturn().getResponse().getStatus();
    assertThat(statusB).as("IP-B must not be rate-limited (independent counter)").isNotEqualTo(429);
  }
}
