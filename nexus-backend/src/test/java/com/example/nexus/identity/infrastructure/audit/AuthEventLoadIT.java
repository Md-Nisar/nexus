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
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestTemplate;

/**
 * US-008 T-08-20, Tier 1 (full scenario) — proves Test Scenario 5 / AC4 exactly as specified:
 * 100 RPS sustained login for 10 minutes against a healthy DB results in zero event loss (
 * {@code nexus.audit.buffer.dropped} and {@code nexus.audit.retry.exhausted} stay at 0;
 * {@code auth_events} row count matches the offered-request count).
 *
 * <p><b>Two-tier CI-gating strategy (per approved plan, following the existing {@code
 * UserQueryPerformanceIT} precedent already in this codebase):</b> this class is tagged {@code
 * @Tag("perf")}, which {@code pom.xml}'s {@code maven-failsafe-plugin} config already excludes
 * from the default {@code mvn verify} gate via {@code <excludedGroups>perf</excludedGroups>} — no
 * pom or CI workflow change was needed. Run explicitly with:
 *
 * <pre>{@code ./mvnw failsafe:integration-test -Dgroups=perf}</pre>
 *
 * or target this class directly: {@code ./mvnw failsafe:integration-test -Dit.test=AuthEventLoadIT}.
 * {@link AuthEventLoadSmokeIT} (10 RPS / 10 s, NOT tagged {@code perf}) runs in the default gate
 * and proves the identical {@link LoadTestHarness} mechanics and assertions cheaply on every PR,
 * so a harness bug is caught long before this expensive 10-minute variant is ever run. A dedicated
 * scheduled/manual CI job to run this class automatically is an explicit future decision, not
 * included here (approved scope: manual-only for now).
 *
 * <p><b>Argon2 cost — NOT reduced.</b> See {@link AuthEventLoadSmokeIT}'s class Javadoc for the
 * full rationale; this class deliberately runs at the same OWASP-2023 production Argon2
 * parameters as the smoke tier, for the same reason.
 *
 * <p><b>Rate-limit ceiling and Hikari pool size raised for this class only</b> — see {@link
 * AuthEventLoadSmokeIT}'s class Javadoc; identical rationale applies here at a larger scale (100
 * RPS sustained, not 10).
 *
 * <p><b>100% valid-credential logins</b> (Clarification #2, approved) — every offered request
 * records exactly one {@code LOGIN_SUCCESS} event, keeping the row-count-equals-offered-count
 * invariant exactly 1:1 for the full 10-minute run (expected offered count: 100 * 600 = 60,000).
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "nexus.identity.encryption.password=test-enc-password-32-chars-long!!",
        "nexus.identity.encryption.salt=cafebabecafebabecafebabecafebabe",
        "nexus.identity.hmac-key=test-not-a-secret-hmac-key-min-32-bytes!!",
        "nexus.identity.default-tenant-id=00000000-0000-7000-8000-000000000001",
        "nexus.security.rate-limit.ip-max-attempts=100000000",
        "nexus.security.rate-limit.ip-window-seconds=60",
        "nexus.security.rate-limit.user-max-attempts=100000000",
        "nexus.security.rate-limit.user-window-seconds=900",
        "feature.nexus-us003-auth-login.enabled=true",
        // KNOWN FINDING, resolved (see AuthEventLoadSmokeIT's class Javadoc for the
        // 2-connections-per-login rationale — outer request connection + SecureEventService's
        // REQUIRES_NEW audit write, ADR 0009): the first measured Tier 1 run at pool size 140
        // exhausted the pool (Hikari log: total=140, active=140, waiting=~3100+) because real
        // per-request connection-hold-time under 100 RPS sustained contention is materially
        // higher than a naive 2x-offered-concurrency estimate assumed. Raised in lockstep with
        // testcontainers-mysql.cnf's max_connections=600. If this pool size itself becomes the
        // bottleneck under real measurement (as opposed to the audit pipeline being measured),
        // that is a harness-sizing question to revisit, not a production finding — the pool is a
        // load-test-only override, never shipped.
        "spring.datasource.hikari.maximum-pool-size=400"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("perf")
class AuthEventLoadIT {

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final String STRONG_PASS = "ValidPassphrase_99!";
  private static final int RATE_PER_SECOND = 100;
  private static final Duration TEST_DURATION = Duration.ofMinutes(10);

  @Value("${local.server.port:0}") private int port;

  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private PasswordHasherPort passwordHasher;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private EmailBlindIndexService emailBlindIndexService;
  @Autowired private JpaAuthEventRepository authEventRepository;
  @Autowired private MeterRegistry meterRegistry;

  @Test
  void should_recordEveryEventWithZeroLoss_when_sustaining100RpsFor10Minutes() {
    String email = "loadtest-" + UUID.randomUUID() + "@example.com";
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
            + " request count (Test Scenario 5 zero-loss invariant, 100 RPS x 10 min)")
        .isEqualTo(result.offered());

    assertThat(sumAcrossLanes("nexus.audit.buffer.dropped") - droppedBefore)
        .as("nexus.audit.buffer.dropped must stay at 0 under a healthy DB for the full 10-minute"
            + " run (Test Scenario 5)")
        .isZero();
    assertThat(sumAcrossLanes("nexus.audit.retry.exhausted") - exhaustedBefore)
        .as("nexus.audit.retry.exhausted must stay at 0 under a healthy DB for the full"
            + " 10-minute run (Test Scenario 5)")
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
              .tags(List.of(io.micrometer.core.instrument.Tag.of("lane", lane.name().toLowerCase())))
              .counter();
      sum += counter != null ? counter.count() : 0.0;
    }
    return sum;
  }
}
