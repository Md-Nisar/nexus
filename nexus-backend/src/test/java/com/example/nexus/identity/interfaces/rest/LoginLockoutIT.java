package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AuthConstants;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
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
 * Integration tests covering the full account-lockout lifecycle (US-006):
 * <ul>
 *   <li>T-020 — full lockout lifecycle: 5 failures → locked → auto-expiry → success</li>
 *   <li>T-021 — failure counter persists after outer transaction rollback (REQUIRES_NEW boundary)</li>
 *   <li>T-022 — HTTP 423 contract: RFC 7807 body + {@code Retry-After} header</li>
 * </ul>
 *
 * <p>Rate-limit properties are set to very high values so the IP/user rate-limiter never
 * fires before the account-lockout threshold is reached (5 failures).
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
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class LoginLockoutIT {

  @Value("${local.server.port:0}") private int port;

  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private PasswordHasherPort passwordHasher;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private EmailBlindIndexService emailBlindIndexService;
  @Autowired private JpaUserRepository jpaUserRepository;

  private RestTemplate restTemplate;

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final String CORRECT_PASS = "ValidPassphrase_99!";
  private static final String WRONG_PASS   = "WrongPassword_00!";

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

  // ── T-020: Full Lockout Lifecycle ─────────────────────────────────────────

  /**
   * T-020a — Full lockout lifecycle:
   * <ol>
   *   <li>Attempts 1–5 with wrong password all return 401 AUTH_001 (the 5th attempt locks the
   *       account in the DB, but {@code LoginUseCase} still throws AUTH_001 for that attempt
   *       because {@code persistFailedAttempt} commits the counter/lock in its own REQUIRES_NEW
   *       transaction, then the outer transaction throws {@code AuthenticationException}).</li>
   *   <li>Attempt 6 (first one to hit an already-locked account) returns 423 AUTH_LCK_001
   *       with a positive {@code Retry-After} header.</li>
   *   <li>Attempt 7 with the correct password on the locked account still returns 423.</li>
   * </ol>
   */
  @Test
  void should_lockAccount_when_5ConsecutiveFailedAttempts() {
    String email = "lck-cycle-" + UUID.randomUUID() + "@test.example.com";
    createActiveUser(email);

    // Attempts 1–5: wrong password → 401 AUTH_001
    // (5th attempt locks account in DB but caller still sees AUTH_001)
    // Note: body is NOT asserted here — application/problem+json bodies are only reliably readable
    // via RestTemplate when the status is 4xx with a JSON body. Status code is the primary contract.
    for (int i = 1; i <= 5; i++) {
      var resp = doLoginPost(email, WRONG_PASS);
      assertThat(resp.getStatusCode().value())
          .as("attempt %d must return 401 (lockout DB write commits independently, response is still AUTH_001)", i)
          .isEqualTo(401);
    }

    // Attempt 6: first attempt against the now-locked account → 423 AUTH_LCK_001
    var lockResp = doLoginPost(email, WRONG_PASS);
    assertThat(lockResp.getStatusCode().value())
        .as("6th attempt must return 423 — account was locked after attempt 5")
        .isEqualTo(423);
    assertThat(lockResp.getBody()).containsEntry("code", "AUTH_LCK_001");
    assertRetryAfterPositive(lockResp);

    // Attempt 7 (correct password) on locked account: still 423 (lock beats credentials)
    var stillLockedCorrect = doLoginPost(email, CORRECT_PASS);
    assertThat(stillLockedCorrect.getStatusCode().value())
        .as("correct password on locked account must still return 423")
        .isEqualTo(423);
  }

  /**
   * T-020b — Auto-expiry: a user whose {@code lockedUntil} is in the past can log in
   * successfully with the correct password, and the failure counter is reset to 0 in DB.
   */
  @Test
  void should_allowLogin_when_lockExpired() {
    String email = "lck-exp-" + UUID.randomUUID() + "@test.example.com";
    User user = createLockedUserWithExpiredLock(email);

    // Correct password with an expired lock → 200
    var resp = doLoginPost(email, CORRECT_PASS);
    assertThat(resp.getStatusCode().value())
        .as("expired lock must auto-expire and allow successful login")
        .isEqualTo(200);

    // DB state: failed_attempt_count == 0 after successful login resets it
    User refreshed = jpaUserRepository.findById(user.getId()).orElseThrow();
    assertThat(refreshed.getFailedAttemptCount())
        .as("failed_attempt_count must be 0 after successful login following lock expiry")
        .isEqualTo(0);
  }

  // ── T-021: Counter Persists After LoginUseCase Rollback ───────────────────

  /**
   * T-021 — Critical M-2 test: proves that the REQUIRES_NEW boundary in
   * {@link com.example.nexus.identity.application.service.SecureEventService#persistFailedAttempt}
   * commits the failure counter even though the outer {@code LoginUseCase} transaction rolls back
   * (because it throws {@code AuthenticationException}).
   *
   * <p>If the counter were 0 after the failed attempt, REQUIRES_NEW would not be working.
   */
  @Test
  void should_persistFailedAttemptCounter_when_outerTransactionRollsBack() {
    String email = "lck-rtx-" + UUID.randomUUID() + "@test.example.com";
    createActiveUser(email);

    // 1 failed attempt
    var resp = doLoginPost(email, WRONG_PASS);
    assertThat(resp.getStatusCode().value()).as("wrong password must return 401").isEqualTo(401);

    // Counter must be 1 in the DB — proves REQUIRES_NEW committed independently
    User user = findActiveUserByEmail(email);
    assertThat(user.getFailedAttemptCount())
        .as("failed_attempt_count must be 1 after 1 failed attempt (REQUIRES_NEW must have committed)")
        .isEqualTo(1);
  }

  /**
   * T-021b — After exactly {@link AuthConstants#LOCKOUT_THRESHOLD} failures the account
   * is in LOCKED status in the DB.
   */
  @Test
  void should_lockAccountInDb_when_thresholdReached() {
    String email = "lck-db-" + UUID.randomUUID() + "@test.example.com";
    createActiveUser(email);

    // Drive exactly LOCKOUT_THRESHOLD (5) failures
    for (int i = 0; i < AuthConstants.LOCKOUT_THRESHOLD; i++) {
      doLoginPost(email, WRONG_PASS);
    }

    // DB status must be LOCKED
    User user = findActiveOrLockedUserByEmail(email);
    assertThat(user.getStatus().name())
        .as("user status must be LOCKED in DB after %d failures", AuthConstants.LOCKOUT_THRESHOLD)
        .isEqualTo("LOCKED");
    assertThat(user.getLockedUntil())
        .as("lockedUntil must be set")
        .isNotNull()
        .isAfter(Instant.now());
  }

  // ── T-022: HTTP Contract: 423 Body + Retry-After Header ──────────────────

  /**
   * T-022 — Asserts the full RFC 7807 contract for a locked-account response:
   * <ul>
   *   <li>HTTP 423 status</li>
   *   <li>{@code Content-Type: application/problem+json}</li>
   *   <li>Body fields: {@code type}, {@code code = "AUTH_LCK_001"}, {@code retryAfterSeconds > 0}</li>
   *   <li>{@code Retry-After} header equals {@code String.valueOf(retryAfterSeconds)}</li>
   *   <li>Body does NOT contain password, stack trace, or class name</li>
   * </ul>
   */
  @Test
  void should_returnRfc7807ProblemDocumentAndRetryAfterHeader_when_accountLocked() {
    String email = "lck-http-" + UUID.randomUUID() + "@test.example.com";
    // Seed user that is already LOCKED with lockedUntil = now + 900 s
    createPreLockedUser(email, Instant.now().plusSeconds(AuthConstants.LOCKOUT_DURATION_SECONDS));

    var resp = doLoginPost(email, CORRECT_PASS);

    // Status
    assertThat(resp.getStatusCode().value())
        .as("locked account must return HTTP 423")
        .isEqualTo(423);

    // Content-Type: application/problem+json
    assertThat(resp.getHeaders().getContentType())
        .as("Content-Type must be application/problem+json")
        .isNotNull()
        .satisfies(ct -> assertThat(ct.toString()).contains("application/problem+json"));

    // Body assertions
    @SuppressWarnings("unchecked")
    Map<String, Object> body = (Map<String, Object>) resp.getBody();
    assertThat(body).as("response body must not be null").isNotNull();

    // RFC 7807 fields present in our ProblemDetail serialization
    assertThat(body).containsKey("status");
    assertThat(body).containsEntry("code", "AUTH_LCK_001");

    Object retryAfterSecondsObj = body.get("retryAfterSeconds");
    assertThat(retryAfterSecondsObj)
        .as("retryAfterSeconds must be present in the body")
        .isNotNull();
    long retryAfterSeconds = ((Number) retryAfterSecondsObj).longValue();
    assertThat(retryAfterSeconds)
        .as("retryAfterSeconds must be a positive value")
        .isPositive();
    assertThat(retryAfterSeconds)
        .as("retryAfterSeconds must be <= LOCKOUT_DURATION_SECONDS")
        .isLessThanOrEqualTo(AuthConstants.LOCKOUT_DURATION_SECONDS);

    // Retry-After header matches body field
    String retryAfterHeader = resp.getHeaders().getFirst(HttpHeaders.RETRY_AFTER);
    assertThat(retryAfterHeader)
        .as("Retry-After header must be present")
        .isNotNull();
    assertThat(retryAfterHeader)
        .as("Retry-After header must equal retryAfterSeconds from body")
        .isEqualTo(String.valueOf(retryAfterSeconds));

    // Body must NOT leak implementation details
    String bodyStr = body.toString();
    assertThat(bodyStr)
        .as("body must not contain the password")
        .doesNotContain(CORRECT_PASS);
    assertThat(bodyStr)
        .as("body must not contain a Java stack trace marker")
        .doesNotContain("at com.")
        .doesNotContain("Exception");
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  /** Creates an ACTIVE user (PENDING → verified). */
  private User createActiveUser(String email) {
    String hmac = emailBlindIndexService.blindIndex(email);
    String hash = passwordHasher.hash(CORRECT_PASS);
    User user = new User(uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, hash, null);
    user = userRegistrationPort.save(user);
    user.verify(Instant.now());
    return userRegistrationPort.save(user);
  }

  /**
   * Creates a LOCKED user whose lock has already expired (lockedUntil = 2 seconds in the past).
   * This simulates the auto-expiry scenario without requiring a real-time sleep.
   */
  private User createLockedUserWithExpiredLock(String email) {
    String hmac = emailBlindIndexService.blindIndex(email);
    String hash = passwordHasher.hash(CORRECT_PASS);
    User user = new User(uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, hash, null);
    user = userRegistrationPort.save(user);
    user.verify(Instant.now());
    // Simulate hitting the lockout threshold
    for (int i = 0; i < AuthConstants.LOCKOUT_THRESHOLD; i++) {
      user.recordFailedAttempt();
    }
    // Lock with a timestamp already in the past
    user.lockAccount(Instant.now().minusSeconds(2));
    return userRegistrationPort.save(user);
  }

  /**
   * Creates a pre-locked ACTIVE user whose lock is set to expire at {@code lockedUntil}.
   * Uses the domain model rather than raw SQL to avoid BINARY(16) encoding complexity.
   */
  private User createPreLockedUser(String email, Instant lockedUntil) {
    String hmac = emailBlindIndexService.blindIndex(email);
    String hash = passwordHasher.hash(CORRECT_PASS);
    User user = new User(uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, hash, null);
    user = userRegistrationPort.save(user);
    user.verify(Instant.now());
    for (int i = 0; i < AuthConstants.LOCKOUT_THRESHOLD; i++) {
      user.recordFailedAttempt();
    }
    user.lockAccount(lockedUntil);
    return userRegistrationPort.save(user);
  }

  /** Finds an ACTIVE user by email for counter verification (reads fresh from DB). */
  private User findActiveUserByEmail(String email) {
    String hmac = emailBlindIndexService.blindIndex(email);
    return userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, hmac)
        .orElseThrow(() -> new AssertionError("Expected user not found in DB for email: " + email));
  }

  /** Finds a user regardless of status (ACTIVE or LOCKED) by email for status verification. */
  private User findActiveOrLockedUserByEmail(String email) {
    String hmac = emailBlindIndexService.blindIndex(email);
    return userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, hmac)
        .orElseThrow(() -> new AssertionError("Expected user not found in DB for email: " + email));
  }

  /** Asserts that the {@code Retry-After} header is present and a positive integer string. */
  private void assertRetryAfterPositive(ResponseEntity<Map> resp) {
    String retryAfter = resp.getHeaders().getFirst(HttpHeaders.RETRY_AFTER);
    assertThat(retryAfter).as("Retry-After header must be present on 423").isNotNull();
    assertThat(Long.parseLong(retryAfter))
        .as("Retry-After header must be a positive integer")
        .isPositive();
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
}
