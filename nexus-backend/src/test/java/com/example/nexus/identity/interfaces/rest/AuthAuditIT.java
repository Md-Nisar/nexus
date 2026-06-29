package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaAuthEventRepository;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;
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
 * End-to-end integration tests verifying that auth events are correctly persisted
 * for login, refresh, and logout operations, and that no raw tokens appear in logs.
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "nexus.identity.encryption.password=test-enc-password-32-chars-long!!",
        "nexus.identity.encryption.salt=cafebabecafebabecafebabecafebabe",
        "nexus.identity.hmac-key=test-not-a-secret-hmac-key-min-32-bytes!!",
        "nexus.identity.default-tenant-id=00000000-0000-7000-8000-000000000001",
        "nexus.security.rate-limit.max-attempts=10000",
        "nexus.security.rate-limit.window-seconds=300"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class AuthAuditIT {

  @Value("${local.server.port:0}") private int port;

  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private PasswordHasherPort passwordHasher;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private EmailBlindIndexService emailBlindIndexService;
  @Autowired private JpaAuthEventRepository authEventRepository;

  private RestTemplate restTemplate;

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final String STRONG_PASS = "ValidPassphrase_99!";

  @BeforeEach
  void setUp() {
    restTemplate = new RestTemplate();
    restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
      @Override
      public boolean hasError(ClientHttpResponse response) {
        return false;
      }
    });
  }

  // ── Tests ─────────────────────────────────────────────────────────────────

  /**
   * Successful login records a LOGIN_SUCCESS / SUCCESS audit event with the correct userId
   * and a non-null IP address.
   */
  @Test
  void login_success_records_audit_event() {
    String email = "audit-ls-" + UUID.randomUUID() + "@example.com";
    User user = createActiveUser(email);

    var resp = doLoginPost(email, STRONG_PASS);
    assertThat(resp.getStatusCode().value()).isEqualTo(200);

    boolean eventFound = authEventRepository.findAll().stream()
        .anyMatch(e -> "LOGIN_SUCCESS".equals(e.getEventType())
            && "SUCCESS".equals(e.getOutcome())
            && user.getId().equals(e.getUserId())
            && e.getIpAddress() != null);
    assertThat(eventFound)
        .as("LOGIN_SUCCESS event must be recorded for userId=%s", user.getId())
        .isTrue();
  }

  /**
   * Failed login (wrong password) records a LOGIN_FAILURE / FAILURE audit event with a
   * non-null IP address.
   */
  @Test
  void login_failure_records_audit_event() {
    String email = "audit-lf-" + UUID.randomUUID() + "@example.com";
    // Use a random email that doesn't exist — just verifying a failure event is produced
    var resp = doLoginPost(email, "WrongPassword99!");
    assertThat(resp.getStatusCode().value()).isEqualTo(401);

    boolean eventFound = authEventRepository.findAll().stream()
        .anyMatch(e -> "LOGIN_FAILURE".equals(e.getEventType())
            && "FAILURE".equals(e.getOutcome())
            && e.getIpAddress() != null);
    assertThat(eventFound).as("LOGIN_FAILURE event must be recorded on bad credentials").isTrue();
  }

  /**
   * Login attempt on a PENDING (unverified) account records LOGIN_PENDING_ACCOUNT event
   * with the correct userId.
   */
  @Test
  void login_pending_account_records_audit_event() {
    String email = "audit-pa-" + UUID.randomUUID() + "@example.com";
    User user = createPendingUser(email);

    var resp = doLoginPost(email, STRONG_PASS);
    // 403 for AccountNotVerifiedException
    assertThat(resp.getStatusCode().value()).isIn(401, 403);

    boolean eventFound = authEventRepository.findAll().stream()
        .anyMatch(e -> "LOGIN_PENDING_ACCOUNT".equals(e.getEventType())
            && user.getId().equals(e.getUserId()));
    assertThat(eventFound)
        .as("LOGIN_PENDING_ACCOUNT event must be recorded for userId=%s", user.getId())
        .isTrue();
  }

  /**
   * Successful token refresh records TOKEN_REFRESH_SUCCESS / SUCCESS audit event.
   */
  @Test
  void refresh_success_records_audit_event() {
    String email = "audit-rs-" + UUID.randomUUID() + "@example.com";
    User user = createActiveUser(email);

    // Login to obtain a refresh token cookie
    var loginResp = doLoginPost(email, STRONG_PASS);
    assertThat(loginResp.getStatusCode().value()).isEqualTo(200);
    String setCookie = loginResp.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
    assertThat(setCookie).as("login must set a refresh_token cookie").isNotNull();
    String cookieValue = extractCookieValue(setCookie);

    var refreshResp = doRefreshPost(cookieValue);
    assertThat(refreshResp.getStatusCode().value()).isEqualTo(200);

    boolean eventFound = authEventRepository.findAll().stream()
        .anyMatch(e -> "TOKEN_REFRESH_SUCCESS".equals(e.getEventType())
            && "SUCCESS".equals(e.getOutcome())
            && user.getId().equals(e.getUserId()));
    assertThat(eventFound)
        .as("TOKEN_REFRESH_SUCCESS event must be recorded for userId=%s", user.getId())
        .isTrue();
  }

  /**
   * Replaying an already-consumed refresh token triggers family revocation, recorded
   * as a REFRESH_FAMILY_REVOKED / FAILURE audit event.
   */
  @Test
  void refresh_family_revoke_records_audit_event() {
    String email = "audit-fr-" + UUID.randomUUID() + "@example.com";
    User user = createActiveUser(email);

    // Login → original cookie
    var loginResp = doLoginPost(email, STRONG_PASS);
    assertThat(loginResp.getStatusCode().value()).isEqualTo(200);
    String originalCookie = extractCookieValue(loginResp.getHeaders().getFirst(HttpHeaders.SET_COOKIE));

    // First refresh — consumes the original token, returns a new cookie
    var firstRefresh = doRefreshPost(originalCookie);
    assertThat(firstRefresh.getStatusCode().value()).isEqualTo(200);

    // Replay the original (now revoked) cookie — must trigger family revocation
    var secondRefresh = doRefreshPost(originalCookie);
    assertThat(secondRefresh.getStatusCode().value()).isEqualTo(401);

    boolean eventFound = authEventRepository.findAll().stream()
        .anyMatch(e -> "REFRESH_FAMILY_REVOKED".equals(e.getEventType())
            && "FAILURE".equals(e.getOutcome())
            && user.getId().equals(e.getUserId()));
    assertThat(eventFound)
        .as("REFRESH_FAMILY_REVOKED event must be recorded on token theft for userId=%s",
            user.getId())
        .isTrue();
  }

  /**
   * Logout returns HTTP 204 and records a LOGOUT / SUCCESS audit event.
   */
  @Test
  void logout_records_audit_event() {
    String email = "audit-lo-" + UUID.randomUUID() + "@example.com";
    createActiveUser(email);

    // Login to obtain an access token
    var loginResp = doLoginPost(email, STRONG_PASS);
    assertThat(loginResp.getStatusCode().value()).isEqualTo(200);
    @SuppressWarnings("unchecked")
    Map<String, Object> body = (Map<String, Object>) loginResp.getBody();
    assertThat(body).isNotNull();
    String accessToken = (String) body.get("accessToken");
    assertThat(accessToken).isNotBlank();

    var logoutResp = doLogoutPost(accessToken);
    assertThat(logoutResp.getStatusCode().value()).isEqualTo(204);

    boolean eventFound = authEventRepository.findAll().stream()
        .anyMatch(e -> "LOGOUT".equals(e.getEventType()) && "SUCCESS".equals(e.getOutcome()));
    assertThat(eventFound).as("LOGOUT event must be recorded after successful logout").isTrue();
  }

  /**
   * Token-less logout (no Bearer token, only refresh cookie) must still revoke server-side
   * refresh tokens — T-7.1 gap: expired/missing access token is the suspected-theft scenario.
   */
  @Test
  void tokenless_logout_revokes_server_side_refresh_tokens() {
    String email = "audit-tl-" + UUID.randomUUID() + "@example.com";
    createActiveUser(email);

    var loginResp = doLoginPost(email, STRONG_PASS);
    assertThat(loginResp.getStatusCode().value()).isEqualTo(200);
    String setCookie = loginResp.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
    assertThat(setCookie).isNotNull();
    String refreshToken = extractCookieValue(setCookie);

    // Logout with only the refresh cookie — no Bearer access token
    var logoutResp = doLogoutPostWithCookie(refreshToken);
    assertThat(logoutResp.getStatusCode().value()).as("token-less logout should return 204").isEqualTo(204);

    // Attempt to refresh after token-less logout — must be 401 (tokens revoked server-side)
    var refreshResp = doRefreshPost(refreshToken);
    assertThat(refreshResp.getStatusCode().value())
        .as("refresh after token-less logout must return 401 — server-side tokens were revoked")
        .isEqualTo(401);
  }

  /**
   * The raw refresh token value must never appear in any log message (SEC T-I4).
   */
  @Test
  void no_raw_refresh_token_in_logs() {
    String email = "audit-log-" + UUID.randomUUID() + "@example.com";
    createActiveUser(email);

    var appender = startLogCapture();
    var loginResp = doLoginPost(email, STRONG_PASS);
    stopLogCapture(appender);

    assertThat(loginResp.getStatusCode().value()).isEqualTo(200);
    String setCookie = loginResp.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
    assertThat(setCookie).isNotNull();
    String rawRefreshToken = extractCookieValue(setCookie);
    assertThat(rawRefreshToken).isNotBlank();

    boolean tokenInLog = appender.list.stream()
        .anyMatch(e -> e.getFormattedMessage().contains(rawRefreshToken));
    assertThat(tokenInLog)
        .as("Raw refresh token must not appear in any log event (SEC T-I4)")
        .isFalse();
  }

  /**
   * Bearer-authenticated logout must revoke ALL refresh-token families for the user,
   * not just the family tied to the cookie presented at logout. This proves the
   * revoke-by-user (not revoke-by-cookie) contract of {@code LogoutUseCase}.
   */
  @Test
  void bearer_logout_revokes_tokens_across_multiple_families() {
    String email = "audit-mf-" + UUID.randomUUID() + "@example.com";
    User user = createActiveUser(email);

    // Login #1 — family A
    var loginResp1 = doLoginPost(email, STRONG_PASS);
    assertThat(loginResp1.getStatusCode().value()).isEqualTo(200);
    @SuppressWarnings("unchecked")
    Map<String, Object> body1 = (Map<String, Object>) loginResp1.getBody();
    assertThat(body1).isNotNull();
    String accessToken = (String) body1.get("accessToken");
    assertThat(accessToken).isNotBlank();
    String refreshToken1 = extractCookieValue(loginResp1.getHeaders().getFirst(HttpHeaders.SET_COOKIE));
    assertThat(refreshToken1).isNotBlank();

    // Login #2 — family B (independent login creates a distinct refresh-token family)
    var loginResp2 = doLoginPost(email, STRONG_PASS);
    assertThat(loginResp2.getStatusCode().value()).isEqualTo(200);
    String refreshToken2 = extractCookieValue(loginResp2.getHeaders().getFirst(HttpHeaders.SET_COOKIE));
    assertThat(refreshToken2).isNotBlank();
    assertThat(refreshToken2).isNotEqualTo(refreshToken1);

    // Bearer-authenticated logout using the access token from login #1
    var logoutResp = doLogoutPost(accessToken);
    assertThat(logoutResp.getStatusCode().value()).as("logout must return 204").isEqualTo(204);

    // Both families must be revoked — not just the one attached to the access token's user session
    var refresh1Resp = doRefreshPost(refreshToken1);
    assertThat(refresh1Resp.getStatusCode().value())
        .as("family A refresh token must be 401 after logout")
        .isEqualTo(401);

    var refresh2Resp = doRefreshPost(refreshToken2);
    assertThat(refresh2Resp.getStatusCode().value())
        .as("family B refresh token must be 401 — logout is revoke-by-user, not revoke-by-cookie")
        .isEqualTo(401);

    // LOGOUT audit event recorded for this user
    boolean eventFound = authEventRepository.findAll().stream()
        .anyMatch(e -> "LOGOUT".equals(e.getEventType())
            && "SUCCESS".equals(e.getOutcome())
            && user.getId().equals(e.getUserId()));
    assertThat(eventFound)
        .as("LOGOUT/SUCCESS event must be recorded for userId=%s", user.getId())
        .isTrue();
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

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

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> doLoginPost(String email, String password) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/auth/login",
        HttpMethod.POST,
        new HttpEntity<>(Map.of("email", email, "password", password), headers),
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
  private ResponseEntity<Map> doLogoutPost(String accessToken) {
    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/auth/logout",
        HttpMethod.POST,
        new HttpEntity<>(null, headers),
        Map.class);
  }

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> doLogoutPostWithCookie(String cookieValue) {
    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.COOKIE, "refresh_token=" + cookieValue);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/auth/logout",
        HttpMethod.POST,
        new HttpEntity<>(null, headers),
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
}
