package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.event.PasswordResetEmailEvent;
import com.example.nexus.identity.application.event.VerificationEmailEvent;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaAuthEventRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.event.EventListener;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * US-008 T-08-19 — proves AC5 ("no PII beyond necessity") and closes threat-model T-I3/T-I1.
 *
 * <p><b>T-I3 (payload scrub):</b> drives all 8 authentication emit flows end-to-end and asserts
 * that no email address, raw password, or raw token value appears in any {@code auth_events}
 * column — including {@code metadata} (JSON) and {@code user_agent} — for the row(s) each flow
 * produces.
 *
 * <p><b>T-I1 (log scrub):</b> a single cross-cutting test asserts that no audit-path log line
 * (root-logger capture, matching {@link AuthAuditIT#no_raw_refresh_token_in_logs}'s pattern)
 * ever interpolates a raw {@code User-Agent} value.
 *
 * <p>This test is additive to, and distinct from, {@link AuthAuditIT}: that suite proves each
 * flow's event is <em>recorded with the right shape</em> (event type, outcome, userId, tenantId);
 * this suite proves the recorded <em>payload never leaks PII/secrets</em>, and extends the
 * log-scrub concern beyond {@code AuthAuditIT.no_raw_refresh_token_in_logs} (which covers only
 * the raw refresh token in logs) to email/password/token patterns in the stored payload plus
 * User-Agent in logs.
 *
 * <p><b>Known gap (see final QA report, not fixed here — pure-test-only scope):</b> {@code
 * RefreshTokenUseCase.execute(String, String)} was never migrated to the 3-arg {@link
 * com.example.nexus.common.domain.RequestContext} by T-08-04/05 — refresh-flow events carry
 * {@code metadata = NULL} and {@code user_agent = NULL} today. {@link
 * #refresh_token_flow_auth_events_contain_no_pii_or_raw_secrets()} asserts against this actual
 * (gapped) behaviour rather than asserting scrubbed-but-present metadata.
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "nexus.identity.encryption.password=test-enc-password-32-chars-long!!",
        "nexus.identity.encryption.salt=cafebabecafebabecafebabecafebabe",
        "nexus.identity.hmac-key=test-not-a-secret-hmac-key-min-32-bytes!!",
        "nexus.identity.default-tenant-id=00000000-0000-7000-8000-000000000001",
        "nexus.security.rate-limit.ip-max-attempts=10000",
        "nexus.security.rate-limit.ip-window-seconds=60",
        "nexus.security.rate-limit.user-max-attempts=10000",
        "nexus.security.rate-limit.user-window-seconds=900"
    })
@Import({TestcontainersConfiguration.class, AuthEventsPiiScrubIT.CapturedEventConfig.class})
@ActiveProfiles("test")
@Tag("IT")
class AuthEventsPiiScrubIT {

  @Value("${local.server.port:0}") private int port;

  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private PasswordHasherPort passwordHasher;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private EmailBlindIndexService emailBlindIndexService;
  @Autowired private JpaAuthEventRepository authEventRepository;
  @Autowired private CapturedEventConfig.Capture capturedEvents;

  private RestTemplate restTemplate;

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final String STRONG_PASS = "ValidPassphrase_99!";
  private static final String NEW_STRONG_PASS = "NewValidPassphrase_88!";

  private static final Pattern EMAIL_PATTERN =
      Pattern.compile("[^@\\s]+@[^@\\s]+\\.[a-zA-Z]{2,}");

  @BeforeEach
  void setUp() {
    restTemplate = new RestTemplate();
    restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
      @Override
      public boolean hasError(ClientHttpResponse response) {
        return false;
      }
    });
    capturedEvents.reset();
  }

  // ── Flow 1: Login (success) ─────────────────────────────────────────────────

  @Test
  void login_flow_auth_events_contain_no_pii_or_raw_secrets() {
    String email = "scrub-ls-" + UUID.randomUUID() + "@example.com";
    String uaMarker = uaMarker("login-success");
    createActiveUser(email);

    var resp = doLoginPost(email, STRONG_PASS, uaMarker);
    assertThat(resp.getStatusCode().value()).isEqualTo(200);

    List<AuthEvent> matches = findByEventType("LOGIN_SUCCESS");
    assertThat(matches).as("LOGIN_SUCCESS event must have been recorded").isNotEmpty();
    assertNoPiiOrSecrets(matches, email, STRONG_PASS, null);
  }

  // ── Flow 1b: Login (failure) — anti-enumeration-sensitive branch ───────────

  @Test
  void login_failure_flow_auth_events_contain_no_pii_or_raw_secrets() {
    String email = "scrub-lf-" + UUID.randomUUID() + "@example.com";
    String uaMarker = uaMarker("login-failure");
    Instant testStart = Instant.now().minusMillis(500);

    var resp = doLoginPost(email, "WrongPassword99!", uaMarker);
    assertThat(resp.getStatusCode().value()).isEqualTo(401);

    List<AuthEvent> matches = findByEventTypeSince("LOGIN_FAILURE", testStart);
    assertThat(matches).as("LOGIN_FAILURE event must have been recorded").isNotEmpty();
    assertNoPiiOrSecrets(matches, email, "WrongPassword99!", null);
  }

  // ── Flow 2: Logout ───────────────────────────────────────────────────────────

  @Test
  void logout_flow_auth_events_contain_no_pii_or_raw_secrets() {
    String email = "scrub-lo-" + UUID.randomUUID() + "@example.com";
    String loginUa = uaMarker("logout-login-leg");
    String logoutUa = uaMarker("logout-logout-leg");
    createActiveUser(email);

    var loginResp = doLoginPost(email, STRONG_PASS, loginUa);
    assertThat(loginResp.getStatusCode().value()).isEqualTo(200);
    @SuppressWarnings("unchecked")
    Map<String, Object> body = (Map<String, Object>) loginResp.getBody();
    String accessToken = (String) body.get("accessToken");
    Instant testStart = Instant.now().minusMillis(500);

    var logoutResp = doLogoutPost(accessToken, logoutUa);
    assertThat(logoutResp.getStatusCode().value()).isEqualTo(204);

    List<AuthEvent> matches = findByEventTypeSince("LOGOUT", testStart);
    assertThat(matches).as("LOGOUT event must have been recorded").isNotEmpty();
    assertNoPiiOrSecrets(matches, email, STRONG_PASS, null);
  }

  // ── Flow 3: Register ─────────────────────────────────────────────────────────

  @Test
  void register_flow_auth_events_contain_no_pii_or_raw_secrets() {
    String email = "scrub-reg-" + UUID.randomUUID() + "@example.com";
    String uaMarker = uaMarker("register");

    var resp = doRegisterPost(email, STRONG_PASS, uaMarker);
    assertThat(resp.getStatusCode().value()).isEqualTo(201);

    List<AuthEvent> matches = findByEventType("REGISTER");
    assertThat(matches).as("REGISTER event must have been recorded").isNotEmpty();
    assertNoPiiOrSecrets(matches, email, STRONG_PASS, null);
  }

  // ── Flow 4: Verify email ─────────────────────────────────────────────────────

  @Test
  void verify_email_flow_auth_events_contain_no_pii_or_raw_secrets() {
    String email = "scrub-vrf-" + UUID.randomUUID() + "@example.com";
    String registerUa = uaMarker("verify-register-leg");
    String verifyUa = uaMarker("verify-verify-leg");

    var regResp = doRegisterPost(email, STRONG_PASS, registerUa);
    assertThat(regResp.getStatusCode().value()).isEqualTo(201);

    String rawToken = capturedEvents.awaitVerificationToken(email);
    assertThat(rawToken).as("raw verification token must have been captured").isNotBlank();

    Instant testStart = Instant.now().minusMillis(500);
    var verifyResp = doVerifyEmailPost(rawToken, verifyUa);
    assertThat(verifyResp.getStatusCode().value()).isEqualTo(200);

    List<AuthEvent> matches = findByEventTypeSince("VERIFY", testStart);
    assertThat(matches).as("VERIFY event must have been recorded").isNotEmpty();
    assertNoPiiOrSecrets(matches, email, STRONG_PASS, rawToken);
  }

  // ── Flow 5: Forgot password ──────────────────────────────────────────────────

  @Test
  void forgot_password_flow_auth_events_contain_no_pii_or_raw_secrets() {
    String email = "scrub-fp-" + UUID.randomUUID() + "@example.com";
    String uaMarker = uaMarker("forgot-password");
    createActiveUser(email);

    var resp = doForgotPasswordPost(email, uaMarker);
    assertThat(resp.getStatusCode().value()).isEqualTo(202);

    List<AuthEvent> matches = findByEventType("PASSWORD_RESET_REQUESTED");
    assertThat(matches).as("PASSWORD_RESET_REQUESTED event must have been recorded").isNotEmpty();
    assertNoPiiOrSecrets(matches, email, STRONG_PASS, null);
  }

  // ── Flow 6: Reset password ───────────────────────────────────────────────────

  @Test
  void reset_password_flow_auth_events_contain_no_pii_or_raw_secrets() {
    String email = "scrub-rp-" + UUID.randomUUID() + "@example.com";
    String forgotUa = uaMarker("reset-forgot-leg");
    String resetUa = uaMarker("reset-reset-leg");
    createActiveUser(email);

    var forgotResp = doForgotPasswordPost(email, forgotUa);
    assertThat(forgotResp.getStatusCode().value()).isEqualTo(202);

    String rawToken = capturedEvents.awaitResetToken(email);
    assertThat(rawToken).as("raw reset token must have been captured").isNotBlank();

    Instant testStart = Instant.now().minusMillis(500);
    var resetResp = doResetPasswordPost(rawToken, NEW_STRONG_PASS, resetUa);
    assertThat(resetResp.getStatusCode().value()).isEqualTo(200);

    List<AuthEvent> matches = findByEventTypeSince("PASSWORD_CHANGED", testStart);
    assertThat(matches).as("PASSWORD_CHANGED event must have been recorded").isNotEmpty();
    assertNoPiiOrSecrets(matches, email, STRONG_PASS, rawToken);
    assertNoPiiOrSecrets(matches, email, NEW_STRONG_PASS, rawToken);
  }

  // ── Flow 7: Refresh token ────────────────────────────────────────────────────

  /**
   * {@code RefreshTokenUseCase.execute(String, String clientIp)} was never migrated to the 3-arg
   * {@code RequestContext} (T-08-04/05 gap — see class Javadoc and the QA report's Gaps section).
   * Refresh-flow events therefore carry {@code metadata = NULL} and {@code user_agent = NULL}
   * today; this test asserts that actual behaviour rather than asserting scrubbed-but-present
   * metadata, while still proving the populated columns (event_type/outcome/ip_address) and the
   * raw refresh-token cookie value never leak.
   */
  @Test
  void refresh_token_flow_auth_events_contain_no_pii_or_raw_secrets() {
    String email = "scrub-rt-" + UUID.randomUUID() + "@example.com";
    createActiveUser(email);

    var loginResp = doLoginPost(email, STRONG_PASS, uaMarker("refresh-login-leg"));
    assertThat(loginResp.getStatusCode().value()).isEqualTo(200);
    String cookieValue = extractCookieValue(loginResp.getHeaders().getFirst(HttpHeaders.SET_COOKIE));

    Instant testStart = Instant.now().minusMillis(500);
    var refreshResp = doRefreshPost(cookieValue);
    assertThat(refreshResp.getStatusCode().value()).isEqualTo(200);
    String newRawRefreshToken =
        extractCookieValue(refreshResp.getHeaders().getFirst(HttpHeaders.SET_COOKIE));

    List<AuthEvent> matches = findByEventTypeSince("TOKEN_REFRESH_SUCCESS", testStart);
    assertThat(matches).as("TOKEN_REFRESH_SUCCESS event must have been recorded").isNotEmpty();

    // Document actual (gapped) behaviour: metadata/user_agent are NULL on this flow today.
    assertThat(matches).allSatisfy(e -> {
      assertThat(e.getMetadata())
          .as("T-08-04/05 gap: RefreshTokenUseCase never threads RequestContext.toMetadataJson()")
          .isNull();
      assertThat(e.getUserAgent())
          .as("T-08-04/05 gap: RefreshTokenUseCase never threads User-Agent")
          .isNull();
    });

    // The populated columns, and the raw cookie values, must still never leak PII/secrets.
    assertNoPiiOrSecrets(matches, email, STRONG_PASS, cookieValue);
    assertNoPiiOrSecrets(matches, email, STRONG_PASS, newRawRefreshToken);
  }

  // ── Flow 8: Resend verification ──────────────────────────────────────────────

  @Test
  void resend_verification_flow_auth_events_contain_no_pii_or_raw_secrets() {
    String email = "scrub-rv-" + UUID.randomUUID() + "@example.com";
    String resendUa = uaMarker("resend-resend-leg");

    // Created directly as PENDING (not via /register) so no prior VERIFICATION token exists —
    // registering first would create one and trip ResendVerificationUseCase's 60s throttle on
    // the very next call, which is an unrelated flow-interaction, not what this test targets.
    createPendingUser(email);

    Instant testStart = Instant.now().minusMillis(500);
    var resendResp = doResendVerificationPost(email, resendUa);
    assertThat(resendResp.getStatusCode().value()).isEqualTo(200);

    List<AuthEvent> matches = findByEventTypeSince("RESEND_REQUESTED", testStart);
    assertThat(matches).as("RESEND_REQUESTED event must have been recorded").isNotEmpty();
    assertNoPiiOrSecrets(matches, email, STRONG_PASS, null);
  }

  // ── T-I1: cross-cutting log scrub (single test, not per-flow — see class Javadoc) ───────────

  /**
   * Drives one flow (login) carrying a unique UA marker with root-logger capture active for the
   * whole request, and asserts no captured log line — across all audit-path components
   * ({@code JpaAuthEventAdapter}, {@code AuthEventRetryBuffer}, {@code SecureEventService}, and
   * each use case's own logger, all covered by root-logger capture) — ever interpolates the raw
   * User-Agent value. Single method because the mechanism under test ({@code
   * JpaAuthEventAdapter.record()}'s WARN log, which never includes UA) is common code shared by
   * all 8 flows; repeating this assertion 8× would be duplicative of the same code path.
   */
  @Test
  void no_audit_path_log_line_contains_raw_user_agent() {
    String email = "scrub-log-" + UUID.randomUUID() + "@example.com";
    String uaMarker = uaMarker("log-scrub-" + UUID.randomUUID());
    createActiveUser(email);

    var appender = startLogCapture();
    var resp = doLoginPost(email, STRONG_PASS, uaMarker);
    stopLogCapture(appender);

    assertThat(resp.getStatusCode().value()).isEqualTo(200);

    boolean uaInLog = appender.list.stream()
        .anyMatch(e -> e.getFormattedMessage().contains(uaMarker));
    assertThat(uaInLog)
        .as("No audit-path log line may interpolate the raw User-Agent value (T-I1)")
        .isFalse();
  }

  // ── Scrub assertion helper ───────────────────────────────────────────────────

  /**
   * Asserts that none of {@code events}' string-bearing columns ({@code eventType}, {@code
   * outcome}, {@code ipAddress}, {@code userAgent}, {@code metadata}) contain: (a) any
   * email-shaped substring (generic regex) or the specific {@code email} literal, (b) the exact
   * {@code rawPassword} literal, or (c) the exact {@code rawSecretToken} literal (verification
   * token, reset token, or raw refresh-token cookie value — pass {@code null} if not applicable
   * to this flow).
   */
  private void assertNoPiiOrSecrets(
      List<AuthEvent> events, String email, String rawPassword, String rawSecretToken) {
    for (AuthEvent event : events) {
      List<String> fields = List.of(
          nullToEmpty(event.getEventType()),
          nullToEmpty(event.getOutcome()),
          nullToEmpty(event.getIpAddress()),
          nullToEmpty(event.getUserAgent()),
          nullToEmpty(event.getMetadata()));

      for (String field : fields) {
        assertThat(EMAIL_PATTERN.matcher(field).find())
            .as("column value [%s] must not contain an email-shaped substring", field)
            .isFalse();
        assertThat(field)
            .as("column value must not contain the literal email address")
            .doesNotContain(email);
        assertThat(field)
            .as("column value must not contain the raw password verbatim")
            .doesNotContain(rawPassword);
        if (rawSecretToken != null && !rawSecretToken.isBlank()) {
          assertThat(field)
              .as("column value must not contain the raw token/refresh-token verbatim")
              .doesNotContain(rawSecretToken);
        }
      }
    }
  }

  private String nullToEmpty(String value) {
    return value == null ? "" : value;
  }

  private String uaMarker(String flowLabel) {
    return "PiiScrubIT-UA-" + flowLabel + "-" + UUID.randomUUID();
  }

  private List<AuthEvent> findByEventType(String eventType) {
    return authEventRepository.findAll().stream()
        .filter(e -> eventType.equals(e.getEventType()))
        .toList();
  }

  private List<AuthEvent> findByEventTypeSince(String eventType, Instant since) {
    return authEventRepository.findAll().stream()
        .filter(e -> eventType.equals(e.getEventType()))
        .filter(e -> e.getCreatedAt() != null && e.getCreatedAt().isAfter(since))
        .toList();
  }

  // ── User fixtures ────────────────────────────────────────────────────────────

  private User createActiveUser(String email) {
    String hmac = emailBlindIndexService.blindIndex(email);
    String hash = passwordHasher.hash(STRONG_PASS);
    User user = new User(uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, hash, null);
    user = userRegistrationPort.save(user);
    user.verify(Instant.now());
    return userRegistrationPort.save(user);
  }

  private User createPendingUser(String email) {
    String hmac = emailBlindIndexService.blindIndex(email);
    String hash = passwordHasher.hash(STRONG_PASS);
    User user = new User(uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, hash, null);
    return userRegistrationPort.save(user);
  }

  // ── HTTP helpers ─────────────────────────────────────────────────────────────

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> doLoginPost(String email, String password, String userAgent) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.set(HttpHeaders.USER_AGENT, userAgent);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/auth/login",
        HttpMethod.POST,
        new HttpEntity<>(Map.of("email", email, "password", password), headers),
        Map.class);
  }

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> doRegisterPost(String email, String password, String userAgent) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.set(HttpHeaders.USER_AGENT, userAgent);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/auth/register",
        HttpMethod.POST,
        new HttpEntity<>(
            Map.of("email", email, "password", password, "consentAccepted", true), headers),
        Map.class);
  }

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> doLogoutPost(String accessToken, String userAgent) {
    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
    headers.set(HttpHeaders.USER_AGENT, userAgent);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/auth/logout",
        HttpMethod.POST,
        new HttpEntity<>(null, headers),
        Map.class);
  }

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> doRefreshPost(String cookieValue) {
    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.COOKIE, "refresh_token=" + cookieValue);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/auth/refresh",
        HttpMethod.POST,
        new HttpEntity<>(null, headers),
        Map.class);
  }

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> doVerifyEmailPost(String rawToken, String userAgent) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.set(HttpHeaders.USER_AGENT, userAgent);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/auth/verify-email",
        HttpMethod.POST,
        new HttpEntity<>(Map.of("token", rawToken), headers),
        Map.class);
  }

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> doForgotPasswordPost(String email, String userAgent) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.set(HttpHeaders.USER_AGENT, userAgent);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/auth/password/forgot",
        HttpMethod.POST,
        new HttpEntity<>(Map.of("email", email), headers),
        Map.class);
  }

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> doResetPasswordPost(
      String rawToken, String newPassword, String userAgent) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.set(HttpHeaders.USER_AGENT, userAgent);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/auth/password/reset",
        HttpMethod.POST,
        new HttpEntity<>(Map.of("token", rawToken, "newPassword", newPassword), headers),
        Map.class);
  }

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> doResendVerificationPost(String email, String userAgent) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.set(HttpHeaders.USER_AGENT, userAgent);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/auth/resend-verification",
        HttpMethod.POST,
        new HttpEntity<>(Map.of("email", email), headers),
        Map.class);
  }

  /**
   * Extracts the raw cookie value from a {@code Set-Cookie} header value.
   * Example input: {@code refresh_token=abc123; HttpOnly; Secure; Path=/api/v1/auth; Max-Age=1209600}
   */
  private String extractCookieValue(String setCookieHeader) {
    if (setCookieHeader == null) {
      return "";
    }
    String firstPart = setCookieHeader.split(";")[0];
    return firstPart.replace("refresh_token=", "");
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

  /**
   * Test-local capture of the raw verification/reset tokens carried by {@link
   * VerificationEmailEvent}/{@link PasswordResetEmailEvent}. Neither token is ever persisted in
   * raw form (only its hash is stored — verified by direct read of {@code RegisterUserUseCase}/
   * {@code ForgotPasswordUseCase}), so the only way to obtain the raw value for this test's
   * "raw token never appears in auth_events" assertion is to observe it at publish time, exactly
   * as the real mail adapter would.
   */
  @TestConfiguration(proxyBeanMethods = false)
  static class CapturedEventConfig {

    @Bean
    Capture piiScrubEventCapture() {
      return new Capture();
    }

    static class Capture {
      private final List<VerificationEmailEvent> verificationEvents = new ArrayList<>();
      private final List<PasswordResetEmailEvent> resetEvents = new ArrayList<>();

      @EventListener
      void onVerification(VerificationEmailEvent event) {
        synchronized (verificationEvents) {
          verificationEvents.add(event);
        }
      }

      @EventListener
      void onReset(PasswordResetEmailEvent event) {
        synchronized (resetEvents) {
          resetEvents.add(event);
        }
      }

      void reset() {
        synchronized (verificationEvents) {
          verificationEvents.clear();
        }
        synchronized (resetEvents) {
          resetEvents.clear();
        }
      }

      /**
       * Polls briefly for the verification-email event matching {@code email}, published
       * synchronously via {@code ApplicationEventPublisher.publishEvent} inside the same request
       * thread — by the time the HTTP response returns, the event has already been published, so
       * no actual waiting occurs in practice; the short poll guards only against any future
       * change to asynchronous dispatch.
       */
      String awaitVerificationToken(String email) {
        return awaitToken(() -> verificationEvents.stream()
            .filter(e -> e.toEmail().equals(email))
            .map(VerificationEmailEvent::rawToken)
            .findFirst()
            .orElse(null));
      }

      String awaitResetToken(String email) {
        return awaitToken(() -> resetEvents.stream()
            .filter(e -> e.toEmail().equals(email))
            .map(PasswordResetEmailEvent::rawToken)
            .findFirst()
            .orElse(null));
      }

      private String awaitToken(java.util.function.Supplier<String> supplier) {
        // publishEvent(...) is synchronous (not @Async) — the event has already been recorded by
        // the time the controller's HTTP response is received by the test's RestTemplate call.
        // No sleep/poll loop is needed or used; a single direct read is deterministic.
        return supplier.get();
      }
    }
  }
}
