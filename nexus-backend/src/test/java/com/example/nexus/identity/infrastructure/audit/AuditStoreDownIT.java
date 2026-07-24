package com.example.nexus.identity.infrastructure.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.port.out.AuditAlertPort;
import com.example.nexus.identity.domain.AuditAlertType;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.infrastructure.persistence.JpaAuthEventRepository;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * US-008 T-08-18 — T-R3 threat-model test: with {@code auth_events} writes failing (simulated
 * audit-store outage), the primary login flow must still return its real outcome, the failed
 * event must be buffered (not lost), and it must drain and persist once the store recovers.
 * Exhaustion of retries must raise an {@code AuditAlertPort} alert and increment the
 * corresponding counter (design §4, §8; ADR 0011).
 *
 * <p><b>Failure-simulation mechanism:</b> {@code @MockitoSpyBean JpaAuthEventRepository} — a
 * Mockito spy wrapping the real, container-backed repository bean. {@code doThrow(...)} on
 * {@code save(...)} simulates "store down" while every other production collaborator
 * ({@link com.example.nexus.identity.infrastructure.persistence.JpaAuthEventAdapter}, the real
 * {@link AuthEventRetryBuffer}, the real {@code auth_events} table) stays exactly as shipped.
 * Recovery is simply {@code Mockito.reset(...)}, which restores the spy's default
 * call-real-method behaviour, so a subsequent manual {@link AuthEventRetryBuffer#drain()} call
 * genuinely persists the buffered event to the real Testcontainers MySQL instance — verified by
 * a direct {@code auth_events} query, not merely a mock-invocation count. This mirrors the
 * established {@code @MockitoBean}-in-Testcontainers-{@code @SpringBootTest} pattern from {@code
 * LogoutAtomicityIT}/{@code RegisterAtomicityIT}, using the spy variant because (unlike those
 * tests) this scenario requires the mock to fall back to real persistence later in the same
 * test, not merely to be asserted against.
 *
 * <p><b>Driven flow:</b> a login with an unknown email (design §8's simplest reproducible
 * audit-write trigger) — {@code LoginUseCase} Step 5 records a single {@code LOGIN_FAILURE} via
 * {@code SecureEventService.recordEvent} (REQUIRES_NEW), requiring no pre-existing user or
 * lockout side effects. {@code LOGIN_FAILURE} routes to {@link AuditLane#STANDARD} (design §4.1
 * — only {@code LOCKOUT}/{@code TOKEN_REFRESH_REUSE}/{@code PASSWORD_CHANGED}/{@code
 * ACCOUNT_LOCKED_WRITE_FAILED} are priority).
 *
 * <p><b>Event identification:</b> since an unknown-email {@code LOGIN_FAILURE} carries no {@code
 * userId} (anti-enumeration), each test sends a unique {@code User-Agent} header value, which
 * {@code LoginController.requestContext(...)} threads through {@code RequestContext.of(...)}
 * into {@code AuthEvent.metadata} (the {@code userAgent} JSON field) — giving each test's event
 * an unambiguous marker to search for in {@code auth_events}, without relying on a time-window
 * heuristic.
 *
 * <p><b>Timing strategy:</b> {@link AuthEventRetryBuffer#drain()} and {@code depth}/{@code
 * oldestAgeSeconds} are called directly on the real, autowired singleton (this test class lives
 * in the same {@code identity.infrastructure.audit} package as the buffer, matching T-08-17's
 * established package-private-access convention) rather than waiting on the real 10 s {@code
 * @Scheduled} tick or introducing Awaitility. {@code max-attempts} and {@code backoff-schedule}
 * are overridden class-wide to small/short values so the exhaustion sub-case does not require
 * real backoff durations to elapse between manual {@code drain()} calls.
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
        "nexus.identity.audit.retry-buffer.enabled=true",
        "nexus.identity.audit.retry-buffer.max-attempts=2",
        "nexus.identity.audit.retry-buffer.backoff-schedule=1ms,1ms",
        "feature.nexus-us003-auth-login.enabled=true"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@org.junit.jupiter.api.Tag("IT")
class AuditStoreDownIT {

  @Value("${local.server.port:0}") private int port;

  @Autowired private JpaAuthEventRepository authEventRepositoryDirect;
  @Autowired private AuthEventRetryBuffer authEventRetryBuffer;
  @Autowired private MeterRegistry meterRegistry;

  @MockitoSpyBean private JpaAuthEventRepository authEventRepository;
  @MockitoBean private AuditAlertPort auditAlertPort;

  private RestTemplate restTemplate;

  @BeforeEach
  void setUp() {
    restTemplate = new RestTemplate();
    restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
      @Override
      public boolean hasError(ClientHttpResponse response) {
        return false;
      }
    });
    // @MockitoSpyBean/@MockitoBean stubbing does not automatically reset between tests in the
    // same class when the Spring context is cached (as it is here — identical @SpringBootTest
    // config across all three tests) -- start every test from the spy's default (call-real-
    // method) behaviour so one test's throwing stub cannot bleed into the next.
    Mockito.reset(authEventRepository);
    Mockito.reset(auditAlertPort);
  }

  /**
   * T-R3 (part 1): the login flow returns its real outcome (401 AUTH_001) despite every {@code
   * auth_events} write failing, and the failed event is buffered rather than lost.
   */
  @Test
  void should_returnRealLoginOutcome_andBufferEvent_when_auditStoreWriteFails() {
    String marker = uniqueMarker("buffer");
    doThrow(new TransientDataAccessResourceException("simulated audit-store outage"))
        .when(authEventRepository)
        .save(any(AuthEvent.class));

    int depthBefore = authEventRetryBuffer.depth(AuditLane.STANDARD);

    var resp = doLoginPost("unknown-" + UUID.randomUUID() + "@example.com", "WrongPassword_99!",
        marker);

    // Per established convention in this test suite (see LoginLockoutIT's T-020a note): a 401
    // application/problem+json body is not reliably readable via RestTemplate as a Map, so only
    // the status code is asserted here — it is the primary contract for "the auth flow returned
    // its real outcome".
    assertThat(resp.getStatusCode().value())
        .as("auth flow must still return its real outcome (401) despite the audit-store outage")
        .isEqualTo(401);

    assertThat(authEventRetryBuffer.depth(AuditLane.STANDARD))
        .as("T-R3: the failed LOGIN_FAILURE write must be buffered (not lost) — standard lane "
            + "depth must have increased by exactly one")
        .isEqualTo(depthBefore + 1);

    boolean persisted = findEventByMarker(marker).isPresent();
    assertThat(persisted)
        .as("while the store is down, the event must NOT yet be persisted — only buffered")
        .isFalse();
  }

  /**
   * T-R3 (part 2): once the simulated outage is lifted, the buffer's drain persists the
   * previously-buffered event to the real {@code auth_events} table, and {@code
   * nexus.audit.retry.success} increments.
   */
  @Test
  void should_drainAndPersistEvent_when_auditStoreRecovers() {
    String marker = uniqueMarker("recover");
    doThrow(new TransientDataAccessResourceException("simulated audit-store outage"))
        .when(authEventRepository)
        .save(any(AuthEvent.class));

    int depthBefore = authEventRetryBuffer.depth(AuditLane.STANDARD);
    double retrySuccessBefore = retrySuccessCount();

    var resp = doLoginPost("unknown-" + UUID.randomUUID() + "@example.com", "WrongPassword_99!",
        marker);
    assertThat(resp.getStatusCode().value()).isEqualTo(401);
    assertThat(authEventRetryBuffer.depth(AuditLane.STANDARD)).isEqualTo(depthBefore + 1);

    // Lift the simulated outage: the spy's default behaviour (call the real repository) is
    // restored, so the next manual drain() genuinely reaches the real Testcontainers MySQL
    // instance.
    Mockito.reset(authEventRepository);

    authEventRetryBuffer.drain();

    assertThat(authEventRetryBuffer.depth(AuditLane.STANDARD))
        .as("drain() must have removed the recovered event from the standard lane")
        .isEqualTo(depthBefore);

    var persisted = findEventByMarker(marker);
    assertThat(persisted)
        .as("T-R3: the buffered event must be genuinely persisted to auth_events on recovery")
        .isPresent();
    assertThat(persisted.get().getEventType()).isEqualTo("LOGIN_FAILURE");

    assertThat(retrySuccessCount())
        .as("nexus.audit.retry.success{lane=standard} must increment on a successful drain")
        .isGreaterThan(retrySuccessBefore);
  }

  /**
   * T-R3 (part 3): if the store never recovers, the event exhausts its retry budget
   * ({@code max-attempts=2}, overridden class-wide), is dropped (never persisted), and an
   * {@code AuditAlertPort.raise(RETRY_EXHAUSTED)} alert is raised with the matching counter
   * incremented.
   */
  @Test
  void should_raiseAlertAndDropEvent_when_retriesExhausted() {
    String marker = uniqueMarker("exhaust");
    doThrow(new TransientDataAccessResourceException("simulated permanent audit-store outage"))
        .when(authEventRepository)
        .save(any(AuthEvent.class));

    double retryExhaustedBefore = retryExhaustedCount();

    var resp = doLoginPost("unknown-" + UUID.randomUUID() + "@example.com", "WrongPassword_99!",
        marker);
    assertThat(resp.getStatusCode().value()).isEqualTo(401);

    int depthAfterEnqueue = authEventRetryBuffer.depth(AuditLane.STANDARD);
    assertThat(depthAfterEnqueue).isGreaterThanOrEqualTo(1);

    // maxAttempts=2, backoff 1ms/1ms -- two manual drain() calls exhaust the event's retry
    // budget deterministically, with no reliance on wall-clock waits (Awaitility is
    // intentionally not introduced for this task).
    sleepMillis(5);
    authEventRetryBuffer.drain();
    sleepMillis(5);
    authEventRetryBuffer.drain();

    assertThat(authEventRetryBuffer.depth(AuditLane.STANDARD))
        .as("the exhausted event must have been dropped from the standard lane")
        .isLessThan(depthAfterEnqueue + 1);

    boolean persisted = findEventByMarker(marker).isPresent();
    assertThat(persisted)
        .as("T-R3: an exhausted event must never end up persisted — it is a genuine drop")
        .isFalse();

    Mockito.verify(auditAlertPort, Mockito.atLeastOnce())
        .raise(org.mockito.ArgumentMatchers.argThat(
            alert -> alert.type() == AuditAlertType.RETRY_EXHAUSTED));

    assertThat(retryExhaustedCount())
        .as("nexus.audit.retry.exhausted{lane=standard} must increment on exhaustion")
        .isGreaterThan(retryExhaustedBefore);
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private String uniqueMarker(String label) {
    return "AuditStoreDownIT-" + label + "-" + UUID.randomUUID();
  }

  private java.util.Optional<AuthEvent> findEventByMarker(String marker) {
    return authEventRepositoryDirect.findAll().stream()
        .filter(e -> e.getMetadata() != null && e.getMetadata().contains(marker))
        .findFirst();
  }

  private double retrySuccessCount() {
    return counterValue("nexus.audit.retry.success", "standard");
  }

  private double retryExhaustedCount() {
    return counterValue("nexus.audit.retry.exhausted", "standard");
  }

  private double counterValue(String metricName, String lane) {
    var counter =
        meterRegistry.find(metricName).tags(List.of(Tag.of("lane", lane))).counter();
    return counter != null ? counter.count() : 0.0;
  }

  private void sleepMillis(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("interrupted while waiting for backoff to elapse", e);
    }
  }

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> doLoginPost(String email, String password, String userAgent) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.add(HttpHeaders.USER_AGENT, userAgent);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/auth/login",
        HttpMethod.POST,
        new HttpEntity<>(Map.of("email", email, "password", password), headers),
        Map.class);
  }
}
