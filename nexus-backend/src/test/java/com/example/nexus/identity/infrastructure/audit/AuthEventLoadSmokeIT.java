package com.example.nexus.identity.infrastructure.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaAuthEventRepository;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestTemplate;

/**
 * US-008 T-08-20, Tier 2 (default-gate smoke variant) — proves the {@link LoadTestHarness}
 * mechanics and the zero-loss/row-count invariants at a small fraction of Tier 1's cost, so the
 * harness itself is validated on every {@code mvn verify} before the expensive 10-minute {@link
 * AuthEventLoadIT} (manual-only, {@code @Tag("perf")}) is ever run.
 *
 * <p><b>Not the full Test Scenario 5 SLA</b> (100 RPS / 10 min) — this is a cheap regression
 * guard: 10 RPS for 10 s (100 total requests), asserting the same three invariants Tier 1 asserts
 * (row count == offered count, {@code buffer.dropped}==0, {@code retry.exhausted}==0). A genuine
 * throughput/loss finding at 100 RPS/10 min would not necessarily reproduce here; that is exactly
 * why Tier 1 exists separately (see its class Javadoc for the two-tier CI-gating rationale).
 *
 * <p><b>Argon2 cost — NOT reduced for this test.</b> Unlike most other {@code *IT}s in this
 * module, this class deliberately does <em>not</em> override {@code nexus.identity.argon2.*}
 * (which {@link TestcontainersConfiguration}'s {@code itProperties()} normally pins to
 * memory-kb=4096/iterations=1 for fast, deterministic ITs). This scenario exists specifically to
 * exercise the audit pipeline under realistic per-request latency, and {@code LoginUseCase}'s
 * Argon2 verify step is deliberately expensive (OWASP 2023 defaults, {@code application.yml}) —
 * shrinking it here would understate how many concurrent in-flight requests are needed to sustain
 * the target RPS and could mask a genuine throughput/latency finding. The virtual-thread client
 * (see {@link LoadTestHarness}) absorbs this cost without needing a hand-tuned platform-thread
 * pool.
 *
 * <p><b>Rate-limit ceiling raised for this class only</b> ({@code ip-max-attempts},
 * {@code ip-window-seconds} inline {@code properties}, matching {@link
 * com.example.nexus.identity.interfaces.rest.AuthAuditIT}'s and {@link
 * AuditStoreDownIT}'s established convention) — {@code LoginRateLimitFilter} keys strictly on
 * {@code request.getRemoteAddr()}, never {@code X-Forwarded-For} (T-1.3, intentional
 * anti-spoofing), so every request in this in-process test originates from one loopback address.
 * Without this override the real rate limiter (correctly) would 429 this test's own offered load
 * long before 10 RPS is reached — this is not a security relaxation of the shipped filter, only
 * of this test's own throwaway Testcontainers context.
 *
 * <p>100% valid-credential logins (no mixed failure traffic) — every offered request records
 * exactly one {@code LOGIN_SUCCESS} event ({@code LoginUseCase.execute} Step 9), keeping the
 * row-count-equals-offered-count invariant exactly 1:1. This scenario proves the audit pipeline's
 * zero-loss/latency behaviour under healthy-DB sustained load (AC4/T-D3), not lockout or
 * credential-failure branch behaviour, which is covered by {@code AuthAuditIT}/{@code
 * LoginLockoutIT} elsewhere.
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "nexus.identity.encryption.password=test-enc-password-32-chars-long!!",
        "nexus.identity.encryption.salt=cafebabecafebabecafebabecafebabe",
        "nexus.identity.hmac-key=test-not-a-secret-hmac-key-min-32-bytes!!",
        "nexus.identity.default-tenant-id=00000000-0000-7000-8000-000000000001",
        "nexus.security.rate-limit.ip-max-attempts=1000000",
        "nexus.security.rate-limit.ip-window-seconds=60",
        "nexus.security.rate-limit.user-max-attempts=1000000",
        "nexus.security.rate-limit.user-window-seconds=900",
        "feature.nexus-us003-auth-login.enabled=true",
        // Default Hikari pool size (10) is sized for a modular-monolith's normal traffic, not a
        // deliberately concurrent load-test client — sized here for the test context only (never
        // touches application.yml/application-prod.*) so the harness measures the audit pipeline's
        // own behaviour rather than an incidental connection-pool bottleneck upstream of it.
        // Each login holds up to 2 simultaneous connections (the outer request-scoped connection
        // plus SecureEventService's REQUIRES_NEW audit write, which opens a second, nested
        // physical connection for the duration of the outer transaction — ADR 0009); sized with
        // headroom above the naive 2x-offered-concurrency estimate. MySQL 8.4's default
        // max_connections (151, unmodified by testcontainers-mysql.cnf) comfortably accommodates
        // this.
        "spring.datasource.hikari.maximum-pool-size=80"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@org.junit.jupiter.api.Tag("IT")
class AuthEventLoadSmokeIT {

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final String STRONG_PASS = "ValidPassphrase_99!";
  private static final int RATE_PER_SECOND = 10;
  private static final Duration TEST_DURATION = Duration.ofSeconds(10);

  @Value("${local.server.port:0}") private int port;

  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private PasswordHasherPort passwordHasher;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private EmailBlindIndexService emailBlindIndexService;
  @Autowired private JpaAuthEventRepository authEventRepository;
  @Autowired private MeterRegistry meterRegistry;

  @Test
  void should_recordEveryEventWithZeroLoss_when_sustaining10RpsFor10Seconds() {
    String email = "loadsmoke-" + UUID.randomUUID() + "@example.com";
    User user = createActiveUser(email);

    double droppedBefore = sumAcrossLanes("nexus.audit.buffer.dropped");
    double exhaustedBefore = sumAcrossLanes("nexus.audit.retry.exhausted");
    long rowCountBefore = countLoginSuccessEvents(user.getId());

    RestTemplate restTemplate = LoadTestHarness.newRestTemplate();
    LoadTestHarness.Result result =
        LoadTestHarness.run(
            restTemplate,
            loginUrl(),
            email,
            STRONG_PASS,
            RATE_PER_SECOND,
            TEST_DURATION);

    assertThat(result.serverErrors())
        .as("no 5xx responses expected under a healthy DB — audit-path activity must never turn"
            + " into a primary-flow failure (AC4)")
        .isZero();
    assertThat(result.succeeded())
        .as("100%% valid-credential traffic must all succeed (200) — offered=%d", result.offered())
        .isEqualTo(result.offered());

    long rowCountAfter = countLoginSuccessEvents(user.getId());
    assertThat(rowCountAfter - rowCountBefore)
        .as("auth_events LOGIN_SUCCESS row count for this run's user must equal the offered"
            + " request count (Test Scenario 5 zero-loss invariant)")
        .isEqualTo(result.offered());

    assertThat(sumAcrossLanes("nexus.audit.buffer.dropped") - droppedBefore)
        .as("nexus.audit.buffer.dropped must stay at 0 under a healthy DB")
        .isZero();
    assertThat(sumAcrossLanes("nexus.audit.retry.exhausted") - exhaustedBefore)
        .as("nexus.audit.retry.exhausted must stay at 0 under a healthy DB")
        .isZero();
  }

  private String loginUrl() {
    return "http://localhost:" + port + "/api/v1/auth/login";
  }

  private User createActiveUser(String email) {
    String hmac = emailBlindIndexService.blindIndex(email);
    String hash = passwordHasher.hash(STRONG_PASS);
    User user =
        new User(uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, hash, null);
    user = userRegistrationPort.save(user);
    user.verify(Instant.now());
    return userRegistrationPort.save(user);
  }

  private long countLoginSuccessEvents(UUID userId) {
    return authEventRepository.findAll().stream()
        .filter(e -> "LOGIN_SUCCESS".equals(e.getEventType()))
        .filter(e -> userId.equals(e.getUserId()))
        .count();
  }

  private double sumAcrossLanes(String metricName) {
    double sum = 0.0;
    for (AuditLane lane : AuditLane.values()) {
      var counter =
          meterRegistry
              .find(metricName)
              .tags(List.of(Tag.of("lane", lane.name().toLowerCase())))
              .counter();
      sum += counter != null ? counter.count() : 0.0;
    }
    return sum;
  }
}
