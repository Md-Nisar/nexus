package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.UserDirectoryService;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

/**
 * US-019 review R2-1: a directory read must not need two pooled connections at once. The audit row
 * is written in its own transaction ({@code REQUIRES_NEW}); if the read's transaction were still
 * open, every concurrent request would hold one connection and wait for a second, and with the
 * pool exhausted the audit write would time out and be lost after a stall. The pool here is two
 * connections with a short acquisition timeout, and more concurrent reads than connections.
 */
@SpringBootTest(
    properties = {
      "nexus.identity.encryption.password=test-enc-password-32-chars-long!!",
      "nexus.identity.encryption.salt=cafebabecafebabecafebabecafebabe",
      "nexus.identity.hmac-key=test-not-a-secret-hmac-key-min-32-bytes!!",
      "nexus.identity.default-tenant-id=00000000-0000-7000-8000-000000000001",
      "spring.datasource.hikari.maximum-pool-size=2",
      "spring.datasource.hikari.minimum-idle=2",
      "spring.datasource.hikari.connection-timeout=2000"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class UserDirectoryConnectionPoolIT {

  private static final int CONCURRENT_READS = 6;

  @Autowired private UserDirectoryService directoryService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  @Test
  void should_writeEveryAuditRowWithoutStalling_when_moreReadsThanPooledConnectionsRunTogether()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    UUID actorId = seedUser(tenantId).getId();
    ExecutorService executor = Executors.newFixedThreadPool(CONCURRENT_READS);
    CyclicBarrier start = new CyclicBarrier(CONCURRENT_READS);
    try {
      long begin = System.nanoTime();
      List<Future<Integer>> reads = new ArrayList<>();
      for (int i = 0; i < CONCURRENT_READS; i++) {
        reads.add(
            executor.submit(
                () -> {
                  start.await(10, TimeUnit.SECONDS);
                  return directoryService.list(tenantId, actorId, null, 0, 10).items().size();
                }));
      }
      for (Future<Integer> read : reads) {
        assertThat(read.get(60, TimeUnit.SECONDS)).isEqualTo(1);
      }
      long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - begin);

      assertThat(auditRows(actorId)).as("no audit row lost").isEqualTo(CONCURRENT_READS);
      assertThat(elapsedMillis)
          .as("no read waited for the pool's 2 s acquisition timeout")
          .isLessThan(2000);
    } finally {
      executor.shutdownNow();
    }
  }

  private User seedUser(UUID tenantId) {
    String email = "pool-" + UUID.randomUUID() + "@example.test";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRepository.save(
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  private int auditRows(UUID actorId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM auth_events WHERE user_id = ? AND event_type = ?",
            Integer.class,
            toBytes(actorId),
            "USER_DIRECTORY_READ");
    return count == null ? 0 : count;
  }

  private static byte[] toBytes(UUID uuid) {
    return ByteBuffer.allocate(16)
        .putLong(uuid.getMostSignificantBits())
        .putLong(uuid.getLeastSignificantBits())
        .array();
  }
}
