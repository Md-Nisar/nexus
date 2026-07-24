package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
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
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * US-009 T-09-06 (AC6; Scenarios 7, 8, 10, 11 / T-T3): {@code active_key} collision on a second
 * active {@code (user_id, role_id)} row, revoke-then-reassign, exactly-one-winner under
 * concurrency, and the generated-column write rejection.
 *
 * <p><strong>Concurrency-harness discrepancy (flagged, not silently fixed):</strong>
 * {@code 03-design.md} S8.3 and {@code 04-tasks.md} both direct this test to "mirror {@code
 * SecureEventServiceConcurrencyTest}" -- that class, read directly, is a single-threaded Mockito
 * unit test with no {@code ExecutorService}/{@code CyclicBarrier} and no Testcontainers; it is not
 * an actual concurrency harness, and mirroring it literally would not exercise the DB. The harness
 * below instead mirrors {@code RefreshTokenRotationIT#concurrent_rotation_single_winner} -- the
 * pattern that actually exists in this codebase (ExecutorService + CyclicBarrier + Future
 * collection against a live Testcontainers MySQL instance) -- using the same 8-thread pool, 5s
 * barrier wait, and 15s executor-termination timeout.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class ActiveAssignmentIT {

  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");

  private User seedUser(String tag) {
    String email = "aa-" + tag + "-" + UUID.randomUUID() + "@example.com";
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
            "AA-" + tag + "-" + UUID.randomUUID(),
            null,
            false));
  }

  @Test
  void should_rejectSecondActiveAssignment_when_sameUserAndRoleAlreadyActive() {
    User assignee = seedUser("collision");
    User assigner = seedUser("collision-by");
    Role role = seedRole("COLLISION");

    userRoleRepository.save(
        new UserRole(
            uuidGenerator.newId(), assignee.getId(), role.getId(), TENANT_ID, assigner.getId()));

    assertThatThrownBy(
            () ->
                userRoleRepository.save(
                    new UserRole(
                        uuidGenerator.newId(),
                        assignee.getId(),
                        role.getId(),
                        TENANT_ID,
                        assigner.getId())))
        .isInstanceOf(DataIntegrityViolationException.class);
  }

  @Test
  void should_allowReassignment_afterRevocation_leavingOriginalRowUnchanged() {
    User assignee = seedUser("reassign");
    User assigner = seedUser("reassign-by");
    Role role = seedRole("REASSIGN");

    UserRole original =
        userRoleRepository.save(
            new UserRole(
                uuidGenerator.newId(), assignee.getId(), role.getId(), TENANT_ID, assigner.getId()));

    // Revocation is a targeted UPDATE, never load-mutate-save (UserRole Javadoc / 03-design.md
    // S4.6) -- raw JdbcTemplate here matches that production intent exactly; it is not
    // inconsistent test style relative to the JPA-repository calls elsewhere in this class.
    jdbc.update(
        "UPDATE user_roles SET revoked_at = NOW(6) WHERE id = ?", toBytes(original.getId()));

    UserRole reassigned =
        userRoleRepository.save(
            new UserRole(
                uuidGenerator.newId(), assignee.getId(), role.getId(), TENANT_ID, assigner.getId()));

    assertThat(reassigned.getId()).isNotEqualTo(original.getId());

    Integer revokedCount =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE id = ? AND revoked_at IS NOT NULL",
            Integer.class,
            toBytes(original.getId()));
    assertThat(revokedCount).as("original revoked row must remain untouched").isEqualTo(1);

    Integer rowCount =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ?",
            Integer.class,
            toBytes(assignee.getId()),
            toBytes(role.getId()));
    assertThat(rowCount).isEqualTo(2);
  }

  @Test
  void should_allowExactlyOneWinner_when_eightConcurrentActiveInsertsRace() throws Exception {
    User assignee = seedUser("conc");
    User assigner = seedUser("conc-by");
    Role role = seedRole("CONC");

    int threadCount = 8;
    CyclicBarrier barrier = new CyclicBarrier(threadCount);
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    List<Future<UserRole>> futures = new ArrayList<>();

    for (int i = 0; i < threadCount; i++) {
      futures.add(
          executor.submit(
              () -> {
                barrier.await(5, TimeUnit.SECONDS);
                return userRoleRepository.save(
                    new UserRole(
                        uuidGenerator.newId(),
                        assignee.getId(),
                        role.getId(),
                        TENANT_ID,
                        assigner.getId()));
              }));
    }

    executor.shutdown();
    boolean terminated = executor.awaitTermination(15, TimeUnit.SECONDS);
    assertThat(terminated).as("all 8 threads must complete within the timeout").isTrue();

    int successCount = 0;
    List<Throwable> failures = new ArrayList<>();
    for (Future<UserRole> future : futures) {
      try {
        future.get();
        successCount++;
      } catch (Exception e) {
        // ExecutionException wrapping DataIntegrityViolationException on uq_user_role_active.
        failures.add(e);
      }
    }

    assertThat(successCount).as("exactly one concurrent active insert should win").isEqualTo(1);
    assertThat(successCount + failures.size()).isEqualTo(threadCount);
    // Code review Low finding (06-code-review.md): a losing thread could in principle fail for
    // an unrelated reason (e.g. connection pool exhaustion, an unrelated deadlock); asserting only
    // successCount == 1 would not catch that. Unwrap every loss to prove it is specifically the
    // uq_user_role_active unique index rejecting the race, not some other failure.
    failures.forEach(ActiveAssignmentIT::assertLostRaceOnActiveKeyUniqueIndex);
  }

  private static void assertLostRaceOnActiveKeyUniqueIndex(Throwable executionException) {
    Throwable dive = executionException;
    while (dive != null && !(dive instanceof DataIntegrityViolationException)) {
      dive = dive.getCause();
    }
    assertThat(dive)
        .as("a losing concurrent insert must fail with DataIntegrityViolationException")
        .isInstanceOf(DataIntegrityViolationException.class);

    Throwable sqlCause = dive;
    while (sqlCause != null && !(sqlCause instanceof SQLException)) {
      sqlCause = sqlCause.getCause();
    }
    assertThat(sqlCause).isInstanceOf(SQLException.class);
    assertThat(sqlCause.getMessage())
        .as("the violated constraint must specifically be uq_user_role_active")
        .containsIgnoringCase("uq_user_role_active");
  }

  @Test
  void should_rejectExplicitActiveKeyInsert_when_generatedColumnValueSuppliedDirectly() {
    User assignee = seedUser("tt3");
    User assigner = seedUser("tt3-by");
    Role role = seedRole("TT3");
    byte[] fakeActiveKey = new byte[32];

    assertThatThrownBy(
            () ->
                jdbc.update(
                    "INSERT INTO user_roles (id, user_id, role_id, tenant_id, assigned_by,"
                        + " active_key) VALUES (?, ?, ?, ?, ?, ?)",
                    toBytes(uuidGenerator.newId()),
                    toBytes(assignee.getId()),
                    toBytes(role.getId()),
                    toBytes(TENANT_ID),
                    toBytes(assigner.getId()),
                    fakeActiveKey))
        .isInstanceOf(DataAccessException.class)
        .satisfies(ActiveAssignmentIT::assertMessageMentionsActiveKey);
  }

  private static void assertMessageMentionsActiveKey(Throwable ex) {
    Throwable cause = ex;
    while (cause != null && !(cause instanceof SQLException)) {
      cause = cause.getCause();
    }
    assertThat(cause).isInstanceOf(SQLException.class);
    assertThat(cause.getMessage()).containsIgnoringCase("active_key");
  }

  /**
   * Gap identified in Phase 8 test-validate (T-T2, {@code
   * chk_user_roles_revoked_not_before_assigned}): no existing test exercised this CHECK
   * constraint at all. {@code revoked_at} strictly before {@code assigned_at} must be rejected --
   * this is the invariant {@code active_key}'s "active = revoked_at IS NULL" definition depends
   * on (V5 migration comment, lines 78-81).
   *
   * <p>Asserts {@code DataAccessException} (not the narrower {@code
   * DataIntegrityViolationException}), matching {@code
   * should_rejectExplicitActiveKeyInsert_when_generatedColumnValueSuppliedDirectly} above: MySQL
   * 8's CHECK-violation error code (3819) is not present in Spring's {@code
   * SQLErrorCodeSQLExceptionTranslator} mysql error-code table (empirically confirmed -- it
   * surfaces as {@code UncategorizedSQLException} via raw {@code JdbcTemplate}, unlike the same
   * constraint violated through the Hibernate/JPA path, which does translate cleanly). This is a
   * genuine Spring/MySQL-driver limitation, not a bug in this codebase.
   */
  @Test
  void should_rejectInsert_when_revokedAtBeforeAssignedAt() {
    User assignee = seedUser("chk-violate");
    User assigner = seedUser("chk-violate-by");
    Role role = seedRole("CHK-VIOLATE");
    LocalDateTime assignedAt = LocalDateTime.now();
    LocalDateTime revokedBeforeAssigned = assignedAt.minusSeconds(1);

    assertThatThrownBy(
            () ->
                jdbc.update(
                    "INSERT INTO user_roles (id, user_id, role_id, tenant_id, assigned_by,"
                        + " assigned_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    toBytes(uuidGenerator.newId()),
                    toBytes(assignee.getId()),
                    toBytes(role.getId()),
                    toBytes(TENANT_ID),
                    toBytes(assigner.getId()),
                    Timestamp.valueOf(assignedAt),
                    Timestamp.valueOf(revokedBeforeAssigned)))
        .isInstanceOf(DataAccessException.class)
        .satisfies(ActiveAssignmentIT::assertMessageMentionsRevokedNotBeforeAssignedCheck);
  }

  /**
   * Boundary companion to {@link #should_rejectInsert_when_revokedAtBeforeAssignedAt()}: the
   * CHECK is {@code revoked_at IS NULL OR revoked_at >= assigned_at} (note {@code >=}, not
   * {@code >}) -- a row revoked in the same instant it was assigned is a valid edge case, not a
   * violation, and must be allowed.
   */
  @Test
  void should_allowInsert_when_revokedAtEqualsAssignedAt() {
    User assignee = seedUser("chk-boundary");
    User assigner = seedUser("chk-boundary-by");
    Role role = seedRole("CHK-BOUNDARY");
    UUID rowId = uuidGenerator.newId();
    LocalDateTime sameInstant = LocalDateTime.now();

    int inserted =
        jdbc.update(
            "INSERT INTO user_roles (id, user_id, role_id, tenant_id, assigned_by,"
                + " assigned_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            toBytes(rowId),
            toBytes(assignee.getId()),
            toBytes(role.getId()),
            toBytes(TENANT_ID),
            toBytes(assigner.getId()),
            Timestamp.valueOf(sameInstant),
            Timestamp.valueOf(sameInstant));

    assertThat(inserted)
        .as("revoked_at == assigned_at is the CHECK's allowed boundary, not a violation")
        .isEqualTo(1);
  }

  private static void assertMessageMentionsRevokedNotBeforeAssignedCheck(Throwable ex) {
    Throwable cause = ex;
    while (cause != null && !(cause instanceof SQLException)) {
      cause = cause.getCause();
    }
    assertThat(cause).isInstanceOf(SQLException.class);
    assertThat(cause.getMessage())
        .containsIgnoringCase("chk_user_roles_revoked_not_before_assigned");
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
