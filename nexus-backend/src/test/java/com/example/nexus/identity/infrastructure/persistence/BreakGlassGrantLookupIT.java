package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.UuidGenerator;
import java.nio.ByteBuffer;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

/**
 * US-018 T-008 (RC-37.2, RC-47, T-S11) against real MySQL: the semantics the security review signed
 * off for the allowlisted global replay lookup, which a mocked adapter test cannot prove. Rows are
 * inserted raw (so event type and outcome are controlled exactly) with random references, because
 * {@code auth_events} is append-only and the container may be reused.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class BreakGlassGrantLookupIT {

  @Autowired private JpaAuthEventRepository repository;
  @Autowired private BreakGlassGrantLookupAdapter adapter;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private UuidGenerator uuidGenerator;

  @Test
  void should_findTheReference_when_aSuccessGrantRowInAnyTenantCarriesIt() {
    String ref = freshRef();
    insert("ROLE_BREAK_GLASS_GRANT", "SUCCESS", uuidGenerator.newId(), ref);

    assertThat(adapter.existsSuccessfulGrantWithChangeRef(ref)).isTrue();
  }

  @Test
  void should_notFindTheReference_when_onlyAFailureRowCarriesIt() {
    String ref = freshRef();
    insert("ROLE_BREAK_GLASS_GRANT", "FAILURE", uuidGenerator.newId(), ref);

    assertThat(adapter.existsSuccessfulGrantWithChangeRef(ref)).isFalse();
  }

  @Test
  void should_notFindTheReference_when_anotherEventTypeCarriesItInMetadata() {
    String ref = freshRef();
    insert("ROLE_ASSIGNED", "SUCCESS", uuidGenerator.newId(), ref);

    assertThat(adapter.existsSuccessfulGrantWithChangeRef(ref)).isFalse();
  }

  @Test
  void should_matchExactly_notByPrefixSuperstringOrCase() {
    String ref = freshRef();
    insert("ROLE_BREAK_GLASS_GRANT", "SUCCESS", uuidGenerator.newId(), ref);

    assertThat(adapter.existsSuccessfulGrantWithChangeRef(ref.substring(0, ref.length() - 1)))
        .as("prefix")
        .isFalse();
    assertThat(adapter.existsSuccessfulGrantWithChangeRef(ref + "0")).as("superstring").isFalse();
    assertThat(adapter.existsSuccessfulGrantWithChangeRef(ref.toLowerCase()))
        .as("case variant")
        .isFalse();
  }

  @Test
  void should_treatTheReferenceAsDataOnly_when_itCarriesSqlOrJsonSyntax() {
    insert("ROLE_BREAK_GLASS_GRANT", "SUCCESS", uuidGenerator.newId(), freshRef());

    assertThat(adapter.existsSuccessfulGrantWithChangeRef("' OR '1'='1")).isFalse();
    assertThat(adapter.existsSuccessfulGrantWithChangeRef("\" OR 1=1 --")).isFalse();
    assertThat(adapter.existsSuccessfulGrantWithChangeRef("%")).isFalse();
    assertThat(repository.existsSuccessfulBreakGlassGrantWithChangeRef("")).isZero();
  }

  private void insert(String eventType, String outcome, UUID tenantId, String changeRef) {
    jdbc.update(
        "INSERT INTO auth_events (id, tenant_id, event_type, outcome, metadata)"
            + " VALUES (?, ?, ?, ?, CAST(? AS JSON))",
        toBytes(uuidGenerator.newId()),
        toBytes(tenantId),
        eventType,
        outcome,
        "{\"actorType\":\"BREAK_GLASS_CLI\",\"changeRef\":\"" + changeRef + "\"}");
  }

  /** A random canonical reference, so a reused container never already holds it. */
  private static String freshRef() {
    return "LKUP-" + ThreadLocalRandom.current().nextInt(1, 100_000_000);
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
