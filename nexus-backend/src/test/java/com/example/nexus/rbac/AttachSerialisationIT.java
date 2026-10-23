package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.autoconfigure.JdbcConnectionDetails;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.containers.MySQLContainer;

/**
 * US-019 T-020, the RC-64 harness (design §10.4 "attach ∥ attach on R", §10.8; T-D28): two
 * attaches of different, non-completing permissions on one role, 50 iterations, with the
 * application <b>connected as {@code nexus_app}</b> (never the Testcontainers user, the US-016 D5
 * trap). Attach takes R's row X lock before its insert and runs a {@code FOR SHARE} current read of
 * R's {@code role_permissions} after it (RC-56.3). Without the row lock, each attach would insert
 * and then scan R's range while the other's insert is uncommitted, and every pair would deadlock
 * (1213). With it, the second attach queues on the row and its current read sees the first's
 * committed row: both succeed.
 *
 * <p>Two shapes: a gate transaction X-locks R's row (the statement attach uses) until both attaches
 * are observed queued in {@code performance_schema.data_lock_waits}, so they always contend; and a
 * plain barrier start. Any exception from an attach, a 1213 above all, fails the run.
 */
@SpringBootTest
@Import({TestcontainersConfiguration.class, AttachSerialisationIT.NexusAppConnection.class})
@ActiveProfiles("test")
@Tag("IT")
class AttachSerialisationIT {

  private static final int ITERATIONS = 50;
  private static final String NEXUS_APP_USER = "nexus_app";
  private static final String NEXUS_APP_PASSWORD = "nexus_app_test_only";
  private static final UUID ROLE_READ = RbacSeededPermissionIds.ROLE_READ;
  private static final UUID ROLE_WRITE = RbacSeededPermissionIds.ROLE_WRITE;
  private static final UUID USER_READ = RbacSeededPermissionIds.USER_READ;
  private static final UUID USER_WRITE = RbacSeededPermissionIds.USER_WRITE;
  private static final UUID AUDIT_READ = RbacSeededPermissionIds.AUDIT_READ;

  /** The application's datasource connects as nexus_app; Flyway's own details are untouched. */
  @TestConfiguration(proxyBeanMethods = false)
  static class NexusAppConnection {

    @Bean
    @Primary
    JdbcConnectionDetails nexusAppJdbcConnectionDetails(MySQLContainer<?> mysqlContainer) {
      return new JdbcConnectionDetails() {
        @Override
        public String getUsername() {
          return NEXUS_APP_USER;
        }

        @Override
        public String getPassword() {
          return NEXUS_APP_PASSWORD;
        }

        @Override
        public String getJdbcUrl() {
          return mysqlContainer.getJdbcUrl();
        }
      };
    }
  }

  @Autowired private RoleManagementService roleManagementService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private MySQLContainer<?> mysqlContainer;

  private ExecutorService executor;
  private UUID tenantId;
  private RoleChangeActor editor;

  @BeforeEach
  void setUp() {
    executor = Executors.newFixedThreadPool(2);
    tenantId = uuidGenerator.newId();
    editor = seedEditor(ROLE_READ, ROLE_WRITE, USER_READ, USER_WRITE, AUDIT_READ);
  }

  @AfterEach
  void tearDown() throws InterruptedException {
    executor.shutdownNow();
    assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
  }

  @Test
  void should_runTheApplicationAsNexusApp_when_thisContextStarts() {
    assertThat(jdbc.queryForObject("SELECT CURRENT_USER()", String.class))
        .startsWith(NEXUS_APP_USER + "@");
  }

  @Test
  void should_queueAndBothSucceedWithoutDeadlock_when_twoAttachesWaitOnTheSameRoleRow()
      throws Exception {
    for (int i = 0; i < ITERATIONS; i++) {
      Role role = seedRole(USER_READ);

      Future<Void> first;
      Future<Void> second;
      try (Connection gate = lockRoleRowAsNexusApp(role)) {
        first = executor.submit(attach(role, AUDIT_READ));
        second = executor.submit(attach(role, USER_WRITE));
        awaitLockWaiters(2);
        gate.commit();
      }
      await(first);
      await(second);

      assertThat(rolePermissionIds(role))
          .as("iteration %d: both attaches applied", i)
          .isEqualTo(Set.of(USER_READ, AUDIT_READ, USER_WRITE));
      assertThat(grantedAuditRows(role)).as("iteration %d", i).isEqualTo(2);
    }
  }

  @Test
  void should_bothSucceedWithoutDeadlock_when_twoAttachesStartTogether() throws Exception {
    for (int i = 0; i < ITERATIONS; i++) {
      Role role = seedRole(USER_READ);
      CyclicBarrier start = new CyclicBarrier(2);

      Future<Void> first = executor.submit(barrier(start, attach(role, AUDIT_READ)));
      Future<Void> second = executor.submit(barrier(start, attach(role, USER_WRITE)));
      await(first);
      await(second);

      assertThat(rolePermissionIds(role))
          .as("iteration %d: both attaches applied", i)
          .isEqualTo(Set.of(USER_READ, AUDIT_READ, USER_WRITE));
    }
  }

  // ── Racers ───────────────────────────────────────────────────────────────────────────

  private Callable<Void> attach(Role role, UUID permissionId) {
    return () -> {
      roleManagementService.attachPermission(
          editor, role.getId(), permissionId, RequestContext.UNKNOWN);
      return null;
    };
  }

  private static Callable<Void> barrier(CyclicBarrier start, Callable<Void> racer) {
    return () -> {
      start.await(10, TimeUnit.SECONDS);
      return racer.call();
    };
  }

  private static void await(Future<Void> future) throws InterruptedException, TimeoutException {
    try {
      future.get(60, TimeUnit.SECONDS);
    } catch (ExecutionException e) {
      throw new AssertionError("an attach failed: " + e.getCause(), e.getCause());
    }
  }

  // ── Gate and observer ────────────────────────────────────────────────────────────────

  /** A nexus_app transaction holding the role row's X lock, with the statement attach uses. */
  private Connection lockRoleRowAsNexusApp(Role role) throws SQLException {
    Connection gate =
        DriverManager.getConnection(mysqlContainer.getJdbcUrl(), NEXUS_APP_USER, NEXUS_APP_PASSWORD);
    gate.setAutoCommit(false);
    try (PreparedStatement lock =
        gate.prepareStatement(
            "SELECT id FROM roles WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL FOR UPDATE")) {
      lock.setBytes(1, toBytes(role.getId()));
      lock.setBytes(2, toBytes(tenantId));
      try (ResultSet rs = lock.executeQuery()) {
        assertThat(rs.next()).isTrue();
      }
    }
    return gate;
  }

  /**
   * Waits (bounded) until at least {@code transactions} distinct transactions are queued on a lock.
   * performance_schema is not readable by nexus_app (least privilege), so this observer is root.
   */
  private void awaitLockWaiters(int transactions) throws SQLException, InterruptedException {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
    try (Connection observer =
            DriverManager.getConnection(
                mysqlContainer.getJdbcUrl(), "root", mysqlContainer.getPassword());
        Statement statement = observer.createStatement()) {
      while (System.nanoTime() < deadline) {
        try (ResultSet rs =
            statement.executeQuery(
                "SELECT COUNT(DISTINCT REQUESTING_ENGINE_TRANSACTION_ID)"
                    + " FROM performance_schema.data_lock_waits")) {
          if (rs.next() && rs.getInt(1) >= transactions) {
            return;
          }
        }
        Thread.sleep(5);
      }
    }
    throw new AssertionError("fewer than " + transactions + " transactions queued on a lock");
  }

  // ── Fixtures and reads (all as nexus_app) ────────────────────────────────────────────

  private User seedUser() {
    String email = "atser-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRepository.save(
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  private RoleChangeActor seedEditor(UUID... permissionIds) {
    User user = seedUser();
    Role editorRole = seedRole(permissionIds);
    userRoleRepository.save(
        new UserRole(
            uuidGenerator.newId(), user.getId(), editorRole.getId(), tenantId, user.getId()));
    return new RoleChangeActor(user.getId(), tenantId);
  }

  private Role seedRole(UUID... permissionIds) {
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, "ATSER-" + UUID.randomUUID(), null, false));
    for (UUID permissionId : permissionIds) {
      rolePermissionRepository.save(new RolePermission(role.getId(), permissionId));
    }
    return role;
  }

  private Set<UUID> rolePermissionIds(Role role) {
    return new HashSet<>(
        jdbc
            .queryForList(
                "SELECT permission_id FROM role_permissions WHERE role_id = ?",
                byte[].class,
                (Object) toBytes(role.getId()))
            .stream()
            .map(AttachSerialisationIT::fromBytes)
            .toList());
  }

  private int grantedAuditRows(Role role) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM auth_events WHERE tenant_id = ? AND event_type = ?"
                + " AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.roleId')) = ?",
            Integer.class,
            toBytes(tenantId),
            "ROLE_PERMISSION_GRANTED",
            role.getId().toString());
    return count == null ? 0 : count;
  }

  private static byte[] toBytes(UUID uuid) {
    return ByteBuffer.allocate(16)
        .putLong(uuid.getMostSignificantBits())
        .putLong(uuid.getLeastSignificantBits())
        .array();
  }

  private static UUID fromBytes(byte[] bytes) {
    ByteBuffer buf = ByteBuffer.wrap(bytes);
    return new UUID(buf.getLong(), buf.getLong());
  }
}
