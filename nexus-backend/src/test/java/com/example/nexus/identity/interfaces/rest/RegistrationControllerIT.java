package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.TokenGenerator;
import com.example.nexus.identity.application.TokenHasher;
import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AuthToken;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.NestedTestConfiguration;
import org.springframework.test.context.NestedTestConfiguration.EnclosingConfiguration;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.WebApplicationContext;

/**
 * Controller-layer IT for {@link RegistrationController}: HTTP contract, Bean Validation,
 * feature-flag, SEC-5 anti-enumeration timing, and log sanity (no raw email/token in logs).
 *
 * <p>The outer class uses Testcontainers MySQL (feature flag ON). The inner
 * {@link WhenFeatureFlagDisabled} class uses H2 with the flag OFF to assert 404 on all endpoints.
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "nexus.identity.encryption.password=test-enc-password-32-chars-long!!",
        "nexus.identity.encryption.salt=cafebabecafebabecafebabecafebabe",
        "nexus.identity.hmac-key=test-not-a-secret-hmac-key-min-32-bytes!!",
        "nexus.identity.default-tenant-id=00000000-0000-7000-8000-000000000001",
        "feature.nexus-us002-auth-registration.enabled=true"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class RegistrationControllerIT {

  // Default :0 prevents PlaceholderResolutionException when the inner class's MOCK context
  // (no HTTP server) injects this enclosing-class instance via Spring's nested-test machinery.
  @Value("${local.server.port:0}") private int port;

  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private AuthTokenPort authTokenPort;
  @Autowired private EmailBlindIndexService emailBlindIndexService;
  @Autowired private TokenGenerator tokenGenerator;
  @Autowired private TokenHasher tokenHasher;
  @Autowired private UuidGenerator uuidGenerator;

  private RestTemplate restTemplate;

  private static final UUID TENANT_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final String STRONG_PASS = "ValidPassphrase_99!";

  @BeforeEach
  void setUp() {
    restTemplate = new RestTemplate();
    // Suppress RestTemplate's default behaviour of throwing on 4xx/5xx so we can assert the status
    restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
      @Override
      public boolean hasError(ClientHttpResponse response) {
        return false;
      }
    });
  }

  // ── POST /api/v1/auth/register ────────────────────────────────────

  @Test
  void register_newUser_returns201WithMessage() {
    var resp = postRegister("ctrl-new-" + UUID.randomUUID() + "@example.com", STRONG_PASS, true);
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(resp.getBody()).containsKey("message");
  }

  @Test
  void register_duplicateEmail_returns201IdenticalShape() {
    String email = "ctrl-dup-" + UUID.randomUUID() + "@example.com";
    var first = postRegister(email, STRONG_PASS, true);
    var second = postRegister(email, STRONG_PASS, true);
    assertThat(first.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(second.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(second.getBody()).containsKey("message");
  }

  @Test
  void register_shortPassword_returns400WithPolicyCode() {
    var resp = postRegister(
        "ctrl-badpwd-" + UUID.randomUUID() + "@example.com", "tooshort", true);
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(resp.getBody()).containsEntry("code", "AUTH_PWD_001");
  }

  @Test
  void register_missingConsent_returns400() {
    var resp = postRegister(
        "ctrl-noconsent-" + UUID.randomUUID() + "@example.com", STRONG_PASS, false);
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  @Test
  void register_invalidEmail_returns400() {
    var resp = postRegister("not-an-email", STRONG_PASS, true);
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  @Test
  void register_email255Chars_returns400() {
    // @Size(max=254) on email — 255-char value should fail Bean Validation.
    String longEmail = "a".repeat(243) + "@example.com"; // 243 + 12 = 255 chars
    var resp = postRegister(longEmail, STRONG_PASS, true);
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  @Test
  void register_email254Chars_returns201() {
    // RFC 5321: total max 254 chars AND local part max 64 chars.
    // 64 + 1(@) + 62 + 1(.) + 62 + 1(.) + 59 + 4(.com) = 254 chars; each label ≤ 63 chars.
    String longEmail = "a".repeat(64) + "@"
        + "b".repeat(62) + "."
        + "c".repeat(62) + "."
        + "d".repeat(59) + ".com";
    var resp = postRegister(longEmail, STRONG_PASS, true);
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CREATED);
  }

  @Test
  void register_password1024Chars_returns201() {
    // Boundary: exactly 1024 chars is within @Size(max=1024) — only policy check applies.
    String longPass = "aB1!".repeat(256); // 4 * 256 = 1024 chars
    var resp = postRegister("ctrl-max-pwd-" + UUID.randomUUID() + "@example.com", longPass, true);
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CREATED);
  }

  @Test
  void register_password1025Chars_returns400() {
    // 1025 chars exceeds @Size(max=1024) — Bean Validation rejects before the service.
    String tooLong = "a".repeat(1025);
    var resp = postRegister("ctrl-tolong-" + UUID.randomUUID() + "@example.com", tooLong, true);
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  @Test
  void resend_blankEmail_returns400() {
    var resp = doPost("/api/v1/auth/resend-verification", Map.of("email", ""));
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  // ── POST /api/v1/auth/verify-email ───────────────────────────────

  @Test
  void verifyEmail_validToken_returns200() {
    User user = createPendingUser("ctrl-vrf-ok-" + UUID.randomUUID() + "@example.com");
    String rawToken = createToken(user.getId(), Duration.ofHours(24));

    var resp = doPost("/api/v1/auth/verify-email", Map.of("token", rawToken));
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(resp.getBody()).containsKey("message");
  }

  @Test
  void verifyEmail_expiredToken_returns410WithCode() {
    User user = createPendingUser("ctrl-vrf-exp-" + UUID.randomUUID() + "@example.com");
    String rawToken = createToken(user.getId(), Duration.ofSeconds(-1));

    var resp = doPost("/api/v1/auth/verify-email", Map.of("token", rawToken));
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.GONE);
    assertThat(resp.getBody()).containsEntry("code", "AUTH_VRF_002");
  }

  @Test
  void verifyEmail_consumedToken_returns410() {
    User user = createPendingUser("ctrl-vrf-cons-" + UUID.randomUUID() + "@example.com");
    String rawToken = createToken(user.getId(), Duration.ofHours(24));

    doPost("/api/v1/auth/verify-email", Map.of("token", rawToken)); // consume
    var resp = doPost("/api/v1/auth/verify-email", Map.of("token", rawToken)); // 2nd attempt
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.GONE);
    assertThat(resp.getBody()).containsEntry("code", "AUTH_VRF_002");
  }

  @Test
  void verifyEmail_invalidTokenFormat_returns400() {
    var resp = doPost("/api/v1/auth/verify-email", Map.of("token", "not-64-hex"));
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  // ── POST /api/v1/auth/resend-verification ────────────────────────

  @Test
  void resend_pendingUserNoRecentToken_returns200() {
    String email = "ctrl-resend-ok-" + UUID.randomUUID() + "@example.com";
    createPendingUser(email); // PENDING, no tokens → cooldown not triggered

    var resp = doPost("/api/v1/auth/resend-verification", Map.of("email", email));
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(resp.getBody()).containsKey("message");
  }

  @Test
  void resend_unknownEmail_returns200() {
    var resp = doPost(
        "/api/v1/auth/resend-verification",
        Map.of("email", "unknown-" + UUID.randomUUID() + "@example.com"));
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  @Test
  void resend_withinCooldown_returns429WithRetryAfterHeader() {
    String email = "ctrl-throttle-" + UUID.randomUUID() + "@example.com";
    postRegister(email, STRONG_PASS, true); // creates PENDING user + registration token

    // Token was just created (<60 s ago) → cooldown triggers 429
    var resp = doPost("/api/v1/auth/resend-verification", Map.of("email", email));
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    assertThat(resp.getHeaders().getFirst("Retry-After"))
        .as("Retry-After header must be present on 429 responses")
        .isNotNull();
  }

  // ── SEC-5: anti-enumeration timing ────────────────────────────────

  @Test
  void register_sec5_newAndDuplicatePathsHaveEquivalentTiming() {
    String dupEmail = "ctrl-tim-dup-" + UUID.randomUUID() + "@example.com";
    postRegister(dupEmail, STRONG_PASS, true); // seed the duplicate

    // Warm up JVM — discarded
    for (int i = 0; i < 3; i++) {
      postRegister("ctrl-tim-wm-" + i + "-" + UUID.randomUUID() + "@example.com", STRONG_PASS, true);
      postRegister(dupEmail, STRONG_PASS, true);
    }

    int n = 50;
    long[] newMs = new long[n];
    long[] dupMs = new long[n];

    for (int i = 0; i < n; i++) {
      String newEmail = "ctrl-tim-n-" + i + "-" + UUID.randomUUID() + "@example.com";

      long t = System.nanoTime();
      postRegister(newEmail, STRONG_PASS, true);
      newMs[i] = (System.nanoTime() - t) / 1_000_000L;

      t = System.nanoTime();
      postRegister(dupEmail, STRONG_PASS, true);
      dupMs[i] = (System.nanoTime() - t) / 1_000_000L;
    }

    double meanNew = Arrays.stream(newMs).average().orElse(0);
    double meanDup = Arrays.stream(dupMs).average().orElse(0);

    assertThat(Math.abs(meanNew - meanDup))
        .as(
            "SEC-5: |mean_new(%.1f ms) - mean_dup(%.1f ms)| must be < 200 ms "
                + "(Argon2 dominates both paths; DB write overhead adds ~50 ms under shared Testcontainer load)",
            meanNew, meanDup)
        .isLessThan(200.0);
  }

  // ── Log sanity (SEC T-I3 / T-I4) ─────────────────────────────────

  @Test
  void register_noRawEmailInLogs_secTi3() {
    String email = "ctrl-log-email-" + UUID.randomUUID() + "@example.com";
    var appender = startLogCapture();
    postRegister(email, STRONG_PASS, true);
    stopLogCapture(appender);

    assertThat(appender.list.stream()
        .anyMatch(e -> e.getFormattedMessage().contains(email)))
        .as("Raw email '%s' must not appear in any log event (SEC T-I3)", email)
        .isFalse();
  }

  @Test
  void verifyEmail_noRawTokenInLogs_secTi4() {
    User user = createPendingUser("ctrl-log-tok-" + UUID.randomUUID() + "@example.com");
    String rawToken = createToken(user.getId(), Duration.ofHours(24));

    var appender = startLogCapture();
    doPost("/api/v1/auth/verify-email", Map.of("token", rawToken));
    stopLogCapture(appender);

    assertThat(appender.list.stream()
        .anyMatch(e -> e.getFormattedMessage().contains(rawToken)))
        .as("Raw token must not appear in any log event (SEC T-I4)")
        .isFalse();
  }

  // ── Feature flag disabled → 404 ───────────────────────────────────

  /**
   * Verifies that all registration endpoints return 404 when the feature flag is off.
   *
   * <p>Uses H2 in-memory DB (no Docker). {@code @NestedTestConfiguration(OVERRIDE)} prevents
   * inheriting {@code @Import(TestcontainersConfiguration)} from the enclosing class, which would
   * otherwise start a MySQL container and override {@code ddl-auto} to {@code validate} via
   * {@code DynamicPropertyRegistrar}, breaking the H2 + {@code create-drop} setup.
   */
  @Nested
  // OVERRIDE prevents inheriting @Import(TestcontainersConfiguration) from the enclosing class,
  // which would otherwise start a MySQL container and override ddl-auto to "validate" via
  // DynamicPropertyRegistrar, breaking the H2 + create-drop setup below.
  @NestedTestConfiguration(EnclosingConfiguration.OVERRIDE)
  @SpringBootTest(
      webEnvironment = WebEnvironment.MOCK,
      properties = {
          "spring.datasource.url=jdbc:h2:mem:nexus-flag-off;DB_CLOSE_DELAY=-1",
          "spring.datasource.username=sa",
          "spring.datasource.password=",
          "spring.datasource.driver-class-name=org.h2.Driver",
          "spring.jpa.hibernate.ddl-auto=create-drop",
          "spring.flyway.enabled=false",
          "spring.mail.host=127.0.0.1",
          "feature.nexus-us002-auth-registration.enabled=false",
          // Crypto properties that application-dev.yml provides for the outer context;
          // OVERRIDE means we must supply them explicitly here. Test-only values (NOT the
          // DEV_PASSWORD_PLACEHOLDER literal) — IdentityCryptoConfig rejects that literal unless
          // the active profile is dev/smoke (SEC-T5 guard), and OVERRIDE means no profile is
          // inherited here, so using the real dev placeholder would fail that check.
          "nexus.identity.encryption.password=test-enc-password-32-chars-long!!",
          "nexus.identity.encryption.salt=cafebabecafebabecafebabecafebabe",
          "nexus.identity.hmac-key=test-not-a-secret-hmac-key-min-32-bytes!!",
          "nexus.identity.default-tenant-id=00000000-0000-7000-8000-000000000001",
          "nexus.identity.argon2.memory-kb=4096",
          "nexus.identity.argon2.iterations=1",
          "nexus.identity.argon2.parallelism=1",
          "nexus.mail.from-address=test@nexus.test",
          "nexus.frontend.base-url=http://localhost:2000"
      })
  class WhenFeatureFlagDisabled {

    @Autowired private WebApplicationContext ctx;

    private MockMvc mvc;

    @BeforeEach
    void setUpMvc() {
      mvc = MockMvcBuilders.webAppContextSetup(ctx).build();
    }

    @Test
    void register_featureFlagOff_returns404() throws Exception {
      mvc.perform(post("/api/v1/auth/register")
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"email\":\"test@example.com\","
                  + "\"password\":\"ValidPassphrase_99!\","
                  + "\"consentAccepted\":true}"))
          .andExpect(status().isNotFound());
    }

    @Test
    void verifyEmail_featureFlagOff_returns404() throws Exception {
      mvc.perform(post("/api/v1/auth/verify-email")
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"token\":\"" + "a".repeat(64) + "\"}"))
          .andExpect(status().isNotFound());
    }

    @Test
    void resend_featureFlagOff_returns404() throws Exception {
      mvc.perform(post("/api/v1/auth/resend-verification")
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"email\":\"test@example.com\"}"))
          .andExpect(status().isNotFound());
    }
  }

  // ── Helpers ────────────────────────────────────────────────────────

  @SuppressWarnings({"rawtypes", "unchecked"})
  private ResponseEntity<Map> postRegister(String email, String password, boolean consent) {
    return doPost(
        "/api/v1/auth/register",
        Map.of("email", email, "password", password, "consentAccepted", (Object) consent));
  }

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> doPost(String path, Map<String, Object> body) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    return restTemplate.exchange(
        "http://localhost:" + port + path,
        HttpMethod.POST,
        new HttpEntity<>(body, headers),
        Map.class);
  }

  private User createPendingUser(String email) {
    String hmac = emailBlindIndexService.blindIndex(email);
    User user = new User(
        uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, "test-hash", null);
    return userRegistrationPort.save(user);
  }

  private String createToken(UUID userId, Duration ttl) {
    String rawToken = tokenGenerator.generate();
    AuthToken token = AuthToken.forVerification(
        uuidGenerator.newId(), userId, tokenHasher.hash(rawToken), Instant.now().plus(ttl));
    authTokenPort.save(token);
    return rawToken;
  }

  private ListAppender<ILoggingEvent> startLogCapture() {
    Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    root.addAppender(appender);
    return appender;
  }

  private void stopLogCapture(ListAppender<ILoggingEvent> appender) {
    Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    root.detachAppender(appender);
    appender.stop();
  }
}
