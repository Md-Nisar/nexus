package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import java.nio.ByteBuffer;
import java.sql.SQLException;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * US-009 T-09-04 (AC4; Scenarios 4, 9): {@code user_roles} is append-only via a {@code BEFORE
 * DELETE} trigger. Single- and multi-row DELETE are both rejected with {@code SQLSTATE '45000'},
 * and the deliberate asymmetry -- {@code UPDATE revoked_at} remains permitted -- is proven
 * separately (T-R2 positive control). Mirrors {@code AuthEventsAppendOnlyIT}'s structure exactly:
 * raw {@code JdbcTemplate} against the trigger, cause-chain walk to the underlying {@code
 * SQLException}, fresh fixtures per test method (no shared/reused rows across tests).
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class UserRolesAppendOnlyIT {

  @Autowired private JdbcTemplate jdbc;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");

  private User seedUser(String tag) {
    String email = "urao-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }

  private Role seedRole(String tag) {
    // is_system_role=false: keeps RbacSchemaMigrationIT's scoped seed-role count stable
    // regardless of test execution order (see that class's Javadoc).
    return roleRepository.save(
        new Role(
            uuidGenerator.newId(),
            uuidGenerator.newId(),
            "URAO-" + tag + "-" + UUID.randomUUID(),
            null,
            false));
  }

  private UUID insertActiveUserRole(UUID userId, UUID roleId, UUID assignedById) {
    UUID id = uuidGenerator.newId();
    jdbc.update(
        "INSERT INTO user_roles (id, user_id, role_id, tenant_id, assigned_by) "
            + "VALUES (?, ?, ?, ?, ?)",
        toBytes(id),
        toBytes(userId),
        toBytes(roleId),
        toBytes(TENANT_ID),
        toBytes(assignedById));
    return id;
  }

  @Test
  void should_rejectSingleRowDelete_when_userRoleDeleted() {
    User assignee = seedUser("single");
    User assigner = seedUser("single-by");
    Role role = seedRole("SINGLE-DEL");
    UUID rowId = insertActiveUserRole(assignee.getId(), role.getId(), assigner.getId());

    // The trigger fires SIGNAL SQLSTATE '45000' on any DELETE.
    assertThatThrownBy(() -> jdbc.update("DELETE FROM user_roles WHERE id = ?", toBytes(rowId)))
        .isInstanceOf(DataAccessException.class)
        .hasMessageContaining("append-only")
        .satisfies(UserRolesAppendOnlyIT::assertSqlState45000);
  }

  @Test
  void should_rejectMultiRowDelete_andLeaveAllRowsIntact_when_bulkDeleteMatchesSeveralRows() {
    User assignee = seedUser("multi");
    User assigner = seedUser("multi-by");
    Role roleA = seedRole("MULTI-DEL-A");
    Role roleB = seedRole("MULTI-DEL-B");
    insertActiveUserRole(assignee.getId(), roleA.getId(), assigner.getId());
    insertActiveUserRole(assignee.getId(), roleB.getId(), assigner.getId());

    // Whole-statement abort: the trigger fires on the first row evaluated and the entire
    // statement rolls back -- zero rows deleted, not "all but the failing one" (Scenario 9).
    assertThatThrownBy(
            () ->
                jdbc.update("DELETE FROM user_roles WHERE user_id = ?", toBytes(assignee.getId())))
        .isInstanceOf(DataAccessException.class)
        .hasMessageContaining("append-only")
        .satisfies(UserRolesAppendOnlyIT::assertSqlState45000);

    Integer remaining =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = ?",
            Integer.class,
            toBytes(assignee.getId()));
    assertThat(remaining).as("whole-statement abort must leave zero rows deleted").isEqualTo(2);
  }

  @Test
  void should_allowUpdateRevokedAt_when_revokingAssignment() {
    User assignee = seedUser("revoke");
    User assigner = seedUser("revoke-by");
    Role role = seedRole("REVOKE-OK");
    UUID rowId = insertActiveUserRole(assignee.getId(), role.getId(), assigner.getId());

    int updated =
        jdbc.update("UPDATE user_roles SET revoked_at = NOW(6) WHERE id = ?", toBytes(rowId));

    assertThat(updated)
        .as("UPDATE revoked_at must remain permitted -- deliberate asymmetry vs. auth_events")
        .isEqualTo(1);
  }

  private static void assertSqlState45000(Throwable ex) {
    Throwable cause = ex;
    while (cause != null && !(cause instanceof SQLException)) {
      cause = cause.getCause();
    }
    assertThat(cause).isInstanceOf(SQLException.class);
    assertThat(((SQLException) cause).getSQLState()).isEqualTo("45000");
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
