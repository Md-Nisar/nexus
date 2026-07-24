package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("perf")
@Tag("IT")
class UserQueryPerformanceIT {

  private static final int ROW_COUNT = 1_000_000;
  private static final int LOOKUP_COUNT = 100;
  private static final long P95_THRESHOLD_MS = 10;
  private static final int BATCH_SIZE = 1_000;

  @Autowired private JpaUserRepository userRepository;
  @Autowired private EmailBlindIndexService blindIndexService;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  @Test
  void should_lookupUnder10msP95_when_1MRowFixture() {
    UUID tenantId = uuidGenerator.newId();
    String lookupEmail = "perf-lookup@example.com";
    String lookupHmac = blindIndexService.blindIndex(lookupEmail);

    // Insert the lookup-target row via JPA (proper encryption, real HMAC)
    userRepository.saveAndFlush(
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(lookupEmail), lookupHmac, "pw-hash", null));

    // Bulk-insert filler rows via JDBC with unique HMACs — bypasses AttributeEncryptor
    String fillSql =
        "INSERT INTO users (id, tenant_id, email_cipher, email_hmac, status,"
            + " token_version, failed_attempt_count) VALUES (?,?,?,?,?,?,?)";
    UUID fillTenant = uuidGenerator.newId();
    List<Object[]> batch = new ArrayList<>(BATCH_SIZE);
    for (int i = 0; i < ROW_COUNT - 1; i++) {
      // UUID string is 36 chars — fits within email_hmac VARCHAR(64)
      batch.add(
          new Object[] {
            toBytes(uuidGenerator.newId()),
            toBytes(fillTenant),
            "filler-cipher",
            UUID.randomUUID().toString(),
            "PENDING",
            0,
            0
          });
      if (batch.size() == BATCH_SIZE) {
        jdbc.batchUpdate(fillSql, batch);
        batch.clear();
      }
    }
    if (!batch.isEmpty()) {
      jdbc.batchUpdate(fillSql, batch);
    }

    // Warm up — avoid JIT cold-start bias in measurements
    for (int i = 0; i < 5; i++) {
      userRepository.findByTenantIdAndEmailHmac(tenantId, lookupHmac);
    }

    // Measure LOOKUP_COUNT queries and record latencies
    long[] latenciesNs = new long[LOOKUP_COUNT];
    for (int i = 0; i < LOOKUP_COUNT; i++) {
      long start = System.nanoTime();
      userRepository.findByTenantIdAndEmailHmac(tenantId, lookupHmac);
      latenciesNs[i] = System.nanoTime() - start;
    }

    // Assert p95 < 10 ms (NFR-001)
    Arrays.sort(latenciesNs);
    long p95Ms = TimeUnit.NANOSECONDS.toMillis(latenciesNs[(int) (LOOKUP_COUNT * 0.95)]);
    assertThat(p95Ms)
        .as("p95 lookup latency must be < %d ms (NFR-001)", P95_THRESHOLD_MS)
        .isLessThan(P95_THRESHOLD_MS);

    // Assert EXPLAIN confirms uq_users_tenant_id_email_hmac index is used
    List<Map<String, Object>> plan =
        jdbc.queryForList(
            "EXPLAIN SELECT * FROM users WHERE tenant_id = ? AND email_hmac = ?",
            toBytes(tenantId),
            lookupHmac);
    boolean usesExpectedIndex =
        plan.stream()
            .anyMatch(
                row ->
                    row.get("key") != null
                        && row.get("key").toString().contains("uq_users_tenant_id_email_hmac"));
    assertThat(usesExpectedIndex)
        .as("EXPLAIN must show uq_users_tenant_id_email_hmac index is used")
        .isTrue();
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
