package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.UuidGenerator;
import java.nio.ByteBuffer;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class AuthEventsAppendOnlyIT {

  @Autowired private JdbcTemplate jdbc;
  @Autowired private UuidGenerator uuidGenerator;

  @Test
  void should_insertAuthEvent_when_eventDataProvided() {
    byte[] id = toBytes(uuidGenerator.newId());

    int rows =
        jdbc.update(
            "INSERT INTO auth_events (id, event_type, outcome) VALUES (?, ?, ?)",
            id,
            "LOGIN_ATTEMPT",
            "SUCCESS");

    assertThat(rows).isEqualTo(1);
  }

  @Test
  void should_rejectUpdate_when_authEventModified() {
    byte[] id = toBytes(uuidGenerator.newId());
    jdbc.update(
        "INSERT INTO auth_events (id, event_type, outcome) VALUES (?, ?, ?)",
        id,
        "LOGIN_ATTEMPT",
        "SUCCESS");

    // The trigger fires SIGNAL SQLSTATE '45000' on any UPDATE
    assertThatThrownBy(
            () -> jdbc.update("UPDATE auth_events SET outcome = ? WHERE id = ?", "FAILURE", id))
        .isInstanceOf(org.springframework.dao.DataAccessException.class)
        .hasMessageContaining("append-only")
        .satisfies(
            ex -> {
              Throwable cause = ex;
              while (cause != null && !(cause instanceof java.sql.SQLException)) {
                cause = cause.getCause();
              }
              assertThat(cause).isInstanceOf(java.sql.SQLException.class);
              assertThat(((java.sql.SQLException) cause).getSQLState()).isEqualTo("45000");
            });
  }

  @Test
  void should_leaveRowUnchanged_when_updateRejected() {
    byte[] id = toBytes(uuidGenerator.newId());
    jdbc.update(
        "INSERT INTO auth_events (id, event_type, outcome) VALUES (?, ?, ?)",
        id,
        "LOGIN_ATTEMPT",
        "SUCCESS");

    try {
      jdbc.update("UPDATE auth_events SET outcome = ? WHERE id = ?", "FAILURE", id);
    } catch (org.springframework.dao.DataAccessException ignored) {
      // Expected to throw because trigger enforces append-only
    }

    String outcome =
        jdbc.queryForObject("SELECT outcome FROM auth_events WHERE id = ?", String.class, id);
    assertThat(outcome).isEqualTo("SUCCESS");
  }

  @Test
  void should_rejectDelete_when_authEventDeleted() {
    byte[] id = toBytes(uuidGenerator.newId());
    jdbc.update(
        "INSERT INTO auth_events (id, event_type, outcome) VALUES (?, ?, ?)",
        id,
        "TOKEN_REFRESH",
        "SUCCESS");

    // The trigger fires SIGNAL SQLSTATE '45000' on any DELETE
    assertThatThrownBy(() -> jdbc.update("DELETE FROM auth_events WHERE id = ?", id))
        .isInstanceOf(org.springframework.dao.DataAccessException.class)
        .hasMessageContaining("append-only")
        .satisfies(
            ex -> {
              Throwable cause = ex;
              while (cause != null && !(cause instanceof java.sql.SQLException)) {
                cause = cause.getCause();
              }
              assertThat(cause).isInstanceOf(java.sql.SQLException.class);
              assertThat(((java.sql.SQLException) cause).getSQLState()).isEqualTo("45000");
            });
  }

  @Test
  void should_allowNullableFields_when_insertingWithMinimalData() {
    byte[] id = toBytes(uuidGenerator.newId());

    // user_id, tenant_id, ip_address, metadata are nullable
    int rows =
        jdbc.update(
            "INSERT INTO auth_events (id, event_type, outcome, user_id, tenant_id) VALUES (?, ?, ?, NULL, NULL)",
            id,
            "SYSTEM_EVENT",
            "INFO");

    assertThat(rows).isEqualTo(1);
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
