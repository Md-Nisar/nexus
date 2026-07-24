package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.infrastructure.persistence.JpaAuthEventRepository;
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
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * US-008 / T-08-08 — T-R2 threat-model test: a registration that rolls back <strong>after</strong>
 * the {@code REGISTER} audit row is physically inserted must leave neither a {@code users} row
 * nor a {@code REGISTER} {@code auth_events} row (no partial "registered + no audit" or "audit +
 * no user" state).
 *
 * <p>{@link com.example.nexus.identity.application.RegisterUserUseCase#register} keeps the
 * {@code REGISTER} audit write in the <strong>same outer transaction</strong> as the {@code
 * users} INSERT — via {@code AuthEventPort} directly, no {@code SecureEventService}/REQUIRES_NEW
 * (US-008 design §7.1: same-TX is the deliberate, already-approved invariant for Register, same
 * rationale as Logout). To prove the atomicity claim rigorously — not just "an exception was
 * thrown somewhere in the method" — this test overrides {@link AuthEventPort} with a {@code
 * @MockitoBean} that <strong>delegates to the real {@link JpaAuthEventRepository}</strong> (so the
 * {@code REGISTER} row is genuinely inserted mid-transaction, visible to a same-transaction
 * {@code SELECT}) and then throws immediately after. The outer {@code @Transactional} rollback
 * that follows must undo both the earlier {@code users} INSERT and this {@code auth_events}
 * INSERT.
 *
 * <p>Kept in its own file (mirrors {@code LogoutAtomicityIT}) so the {@code @MockitoBean}
 * override does not apply to {@link RegistrationControllerIT}'s other tests, which rely on real
 * audit-write behavior.
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
        "nexus.security.rate-limit.user-window-seconds=900",
        "feature.nexus-us002-auth-registration.enabled=true"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class RegisterAtomicityIT {

  @Value("${local.server.port:0}") private int port;

  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private EmailBlindIndexService emailBlindIndexService;
  @Autowired private JpaAuthEventRepository authEventRepository;

  @MockitoBean private AuthEventPort authEventPort;

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
   * T-R2: a forced failure immediately after the {@code REGISTER} row is physically inserted
   * mid-transaction must roll back both the {@code users} row and the {@code auth_events} row.
   */
  @Test
  void should_recordNoUserAndNoRegisterEvent_when_postAuditRollbackOccurs() {
    String email = "audit-r2-" + UUID.randomUUID() + "@example.com";

    // Delegate to the real repository (genuine INSERT, visible within the still-open
    // transaction) then throw -- proves rollback of an already-persisted row, not merely
    // "an exception happened somewhere in the method".
    doAnswer(invocation -> {
      AuthEvent event = invocation.getArgument(0);
      authEventRepository.save(event);
      throw new RuntimeException("simulated post-audit failure");
    }).when(authEventPort).record(any(AuthEvent.class));

    var resp = doRegisterPost(email, STRONG_PASS);
    assertThat(resp.getStatusCode().value())
        .as("forced post-audit failure must not be swallowed as a normal 201 registration")
        .isGreaterThanOrEqualTo(400);

    String emailHmac = emailBlindIndexService.blindIndex(email);
    boolean userExists =
        userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, emailHmac).isPresent();
    assertThat(userExists)
        .as("T-R2: no user row must exist when the post-audit transaction rolls back")
        .isFalse();

    boolean registerRowExists = authEventRepository.findAll().stream()
        .anyMatch(e -> "REGISTER".equals(e.getEventType()));
    assertThat(registerRowExists)
        .as("T-R2: no REGISTER audit row must survive the rollback, even though it was "
            + "physically inserted mid-transaction before the forced failure")
        .isFalse();
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> doRegisterPost(String email, String password) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/auth/register",
        HttpMethod.POST,
        new HttpEntity<>(
            Map.of("email", email, "password", password, "consentAccepted", true), headers),
        Map.class);
  }
}
