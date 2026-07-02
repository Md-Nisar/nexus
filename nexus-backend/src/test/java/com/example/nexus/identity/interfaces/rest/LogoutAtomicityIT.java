package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.RefreshTokenPort;
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
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * US-008 / T-08-07 — T-R1 threat-model test: a forced refresh-token-revocation failure must
 * leave NO LOGOUT row in {@code auth_events} (no phantom logout).
 *
 * <p>{@link com.example.nexus.identity.application.service.LogoutUseCase#execute} calls {@code
 * refreshTokenPort.revokeByUserId(...)} <strong>before</strong> {@code authEventPort.record(...)}
 * within a single {@code @Transactional} boundary — see the class Javadoc's atomicity invariant
 * (US-008 §7.1: same-outer-TX by design, REQUIRES_NEW deliberately rejected for Logout). Forcing
 * the revocation call to throw therefore exercises the real production code path: the audit
 * write is never reached, and even if it were, the outer transaction rollback would undo it. This
 * IT proves the observable outcome (no LOGOUT row), which is what T-R1 requires — it does not
 * need a harder "throw between INSERT and COMMIT" fault, because the current revoke-then-audit
 * ordering makes that scenario unreachable. If a future change reorders audit-before-revoke, this
 * test's mechanism (mocking at the {@code RefreshTokenPort} boundary) would need revisiting.
 *
 * <p>Uses its own {@code @MockitoBean} override of {@link RefreshTokenPort}, so it is intentionally
 * kept in a separate file from {@link AuthAuditIT} — that override would otherwise apply
 * Spring-context-wide and break {@code AuthAuditIT}'s other tests, which rely on real revocation.
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
class LogoutAtomicityIT {

  @Value("${local.server.port:0}") private int port;

  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private PasswordHasherPort passwordHasher;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private EmailBlindIndexService emailBlindIndexService;
  @Autowired private JpaAuthEventRepository authEventRepository;

  @MockitoBean private RefreshTokenPort refreshTokenPort;

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

  /**
   * T-R1: forcing {@code RefreshTokenPort.revokeByUserId} to throw during logout must leave no
   * LOGOUT row for the user — revocation and audit commit atomically (or not at all).
   */
  @Test
  void should_recordNoLogoutRow_when_refreshTokenRevocationFails() {
    String email = "audit-r1-" + UUID.randomUUID() + "@example.com";
    User user = createActiveUser(email);

    var loginResp = doLoginPost(email, STRONG_PASS);
    assertThat(loginResp.getStatusCode().value()).isEqualTo(200);
    @SuppressWarnings("unchecked")
    Map<String, Object> body = (Map<String, Object>) loginResp.getBody();
    assertThat(body).isNotNull();
    String accessToken = (String) body.get("accessToken");
    assertThat(accessToken).isNotBlank();

    doThrow(new RuntimeException("simulated revocation failure"))
        .when(refreshTokenPort).revokeByUserId(any(), any());

    var logoutResp = doLogoutPost(accessToken);
    assertThat(logoutResp.getStatusCode().value())
        .as("forced revocation failure must not be swallowed as a normal 204 logout")
        .isGreaterThanOrEqualTo(400);

    boolean logoutRowExists = authEventRepository.findAll().stream()
        .anyMatch(e -> "LOGOUT".equals(e.getEventType()) && user.getId().equals(e.getUserId()));
    assertThat(logoutRowExists)
        .as("T-R1: no phantom LOGOUT row must exist when revocation fails for userId=%s",
            user.getId())
        .isFalse();

    // Sanity: the earlier LOGIN_SUCCESS row (unrelated to the forced failure) is untouched —
    // confirms we are asserting against real data, not an empty/rolled-back-everything table.
    boolean loginRowExists = authEventRepository.findAll().stream()
        .anyMatch(e -> "LOGIN_SUCCESS".equals(e.getEventType()) && user.getId().equals(e.getUserId()));
    assertThat(loginRowExists)
        .as("LOGIN_SUCCESS row from setup must remain — only LOGOUT is expected to be absent")
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
  private ResponseEntity<Map> doLogoutPost(String accessToken) {
    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/auth/logout",
        HttpMethod.POST,
        new HttpEntity<>(null, headers),
        Map.class);
  }
}
