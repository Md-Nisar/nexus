package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.PreconditionFailedException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.AttachProvenanceConflictException;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.RolePermissionSetVersion;
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
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
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
 * US-019 T-018 and T-019 (design §10.4, §10.8 cases (a) to (g); RC-55.4, RC-63(a), T-T24,
 * RC-57.1): the B8 replace races on the role-row path ((a), (b), (c), (g)) and the set-lock path
 * ((d) promotion versus delete, (e) demotion versus assign, (f) promotion versus revoke), 50
 * iterations each, with the <b>application connected as
 * {@code nexus_app}</b>, never the Testcontainers user (the US-016 D5 trap): {@link
 * NexusAppConnection} makes {@code nexus_app} the primary datasource's credentials while Flyway
 * keeps migrating as the container user through its own connection details. Fixtures are seeded
 * through the repositories, so as {@code nexus_app} too.
 *
 * <p>Arrival order is forced, not hoped for: a "gate" connection X-locks the role row, the racers
 * are started one at a time and each is observed queued in {@code
 * performance_schema.data_lock_waits} (read as root, which nexus_app cannot) before the next starts
 * or the gate commits. The set-lock cases flip R's class only inside the B8 that holds R's locks,
 * and no racer here classifies R from a state another racer flips mid-flight on a different lock
 * order, so RES-45 does not apply: any exception other than each case's expected outcomes (a 1213
 * deadlock above all) fails the run.
 */
@SpringBootTest(properties = "spring.datasource.hikari.maximum-pool-size=15")
@Import({
  TestcontainersConfiguration.class,
  RolePermissionReplaceConcurrencyIT.NexusAppConnection.class
})
@ActiveProfiles("test")
@Tag("IT")
class RolePermissionReplaceConcurrencyIT {

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
  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private MySQLContainer<?> mysqlContainer;

  private ExecutorService executor;
  private UUID tenantId;
  private RoleChangeActor actor;

  @BeforeEach
  void setUp() {
    executor = Executors.newFixedThreadPool(2);
    tenantId = uuidGenerator.newId();
    actor = seedEditor(ROLE_READ, ROLE_WRITE, USER_READ, USER_WRITE, AUDIT_READ);
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

  /** (a) Two editors with the same If-Match: exactly one 200 and one 412, never a lost update. */
  @Test
  void should_succeedExactlyOnce_when_twoReplacesCarryTheSameIfMatch() throws Exception {
    for (int i = 0; i < ITERATIONS; i++) {
      Role role = seedRole(USER_READ);
      String v0 = version(role, USER_READ);
      Set<UUID> first = Set.of(USER_READ, AUDIT_READ);
      Set<UUID> second = Set.of(USER_READ, USER_WRITE);
      CyclicBarrier start = new CyclicBarrier(2);

      Future<Outcome> a = executor.submit(barrier(start, () -> replace(role, first, v0)));
      Future<Outcome> b = executor.submit(barrier(start, () -> replace(role, second, v0)));
      Outcome outcomeA = await(a);
      Outcome outcomeB = await(b);

      assertThat(Set.of(outcomeA, outcomeB))
          .as("iteration %d", i)
          .containsExactlyInAnyOrder(Outcome.OK, Outcome.PRECONDITION_FAILED);
      assertThat(rolePermissionIds(role))
          .as("iteration %d: the winner's set, untouched by the loser", i)
          .isEqualTo(outcomeA == Outcome.OK ? first : second);
      assertThat(grantedAuditRows(role)).as("iteration %d", i).isEqualTo(1);
    }
  }

  /**
   * (b) RC-63(a), T-T24: a replace and an attach on one role, queued behind the gate in both
   * arrival orders. Whichever goes first, the result is one of the two serial orders: the replace
   * applies and the attach lands on top (200 + attach), or the attach lands and the replace sees it
   * in its current read (412 + attach). Never a deadlock.
   */
  @Test
  void should_serialiseWithoutDeadlock_when_aReplaceAndAnAttachQueueInEitherOrder()
      throws Exception {
    Set<Outcome> replaceOutcomes = new HashSet<>();
    for (int i = 0; i < ITERATIONS; i++) {
      boolean replaceArrivesFirst = i % 2 == 0;
      Role role = seedRole(USER_READ);
      String v0 = version(role, USER_READ);
      Set<UUID> target = Set.of(USER_READ, AUDIT_READ);
      Callable<Outcome> replace = () -> replace(role, target, v0);
      Callable<Outcome> attach = () -> attach(role, USER_WRITE);

      Future<Outcome> replaced;
      Future<Outcome> attached;
      try (Connection gate = lockRoleRowAsNexusApp(role)) {
        if (replaceArrivesFirst) {
          replaced = executor.submit(replace);
          awaitLockWaiters(1);
          attached = executor.submit(attach);
        } else {
          attached = executor.submit(attach);
          awaitLockWaiters(1);
          replaced = executor.submit(replace);
        }
        awaitLockWaiters(2);
        gate.commit();
      }
      Outcome replaceOutcome = await(replaced);
      Outcome attachOutcome = await(attached);

      assertThat(attachOutcome).as("iteration %d: the attach always applies", i)
          .isEqualTo(Outcome.OK);
      assertThat(replaceOutcome).as("iteration %d", i).isIn(Outcome.OK, Outcome.PRECONDITION_FAILED);
      assertThat(rolePermissionIds(role))
          .as("iteration %d (replace first: %s): a serial order", i, replaceArrivesFirst)
          .isEqualTo(
              replaceOutcome == Outcome.OK
                  ? Set.of(USER_READ, AUDIT_READ, USER_WRITE)
                  : Set.of(USER_READ, USER_WRITE));
      replaceOutcomes.add(replaceOutcome);
    }
    assertThat(replaceOutcomes).as("both serial orders occurred").hasSize(2);
  }

  /**
   * (c) A replace that adds, racing a detach of a permission the replace keeps. Either the detach
   * is seen by the replace's snapshot or current read (412, the detach stands), or the detach waits
   * for the replace's shared locks and lands after it (200, then the detach). Never a deadlock.
   */
  @Test
  void should_serialiseWithoutDeadlock_when_aReplaceRacesADetach() throws Exception {
    for (int i = 0; i < ITERATIONS; i++) {
      Role role = seedRole(USER_READ, AUDIT_READ);
      String v0 = version(role, USER_READ, AUDIT_READ);
      Set<UUID> target = Set.of(USER_READ, AUDIT_READ, USER_WRITE);
      CyclicBarrier start = new CyclicBarrier(2);

      Future<Outcome> replaced = executor.submit(barrier(start, () -> replace(role, target, v0)));
      Future<Outcome> detached = executor.submit(barrier(start, () -> detach(role, AUDIT_READ)));
      Outcome replaceOutcome = await(replaced);
      Outcome detachOutcome = await(detached);

      assertThat(detachOutcome).as("iteration %d: the detach always applies", i)
          .isEqualTo(Outcome.OK);
      assertThat(replaceOutcome).as("iteration %d", i).isIn(Outcome.OK, Outcome.PRECONDITION_FAILED);
      assertThat(rolePermissionIds(role))
          .as("iteration %d: a serial order", i)
          .isEqualTo(
              replaceOutcome == Outcome.OK ? Set.of(USER_READ, USER_WRITE) : Set.of(USER_READ));
    }
  }

  /**
   * (g) RC-55.4: the replace takes its snapshot, then waits on the role row; meanwhile an attach
   * commits (the gate inserts the row, as attach does, and commits). The replace's current read
   * sees it: 412, and the replace changes nothing and audits nothing.
   */
  @Test
  void should_return412AndChangeNothing_when_anAttachCommitsBetweenSnapshotAndLock()
      throws Exception {
    for (int i = 0; i < ITERATIONS; i++) {
      Role role = seedRole(USER_READ);
      String v0 = version(role, USER_READ);

      Future<Outcome> replaced;
      try (Connection gate = lockRoleRowAsNexusApp(role)) {
        replaced = executor.submit(() -> replace(role, Set.of(USER_READ, USER_WRITE), v0));
        awaitLockWaiters(1);
        try (PreparedStatement insert =
            gate.prepareStatement(
                "INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)")) {
          insert.setBytes(1, toBytes(role.getId()));
          insert.setBytes(2, toBytes(AUDIT_READ));
          insert.executeUpdate();
        }
        gate.commit();
      }

      assertThat(await(replaced)).as("iteration %d", i).isEqualTo(Outcome.PRECONDITION_FAILED);
      assertThat(rolePermissionIds(role))
          .as("iteration %d: only the concurrent attach", i)
          .isEqualTo(Set.of(USER_READ, AUDIT_READ));
      assertThat(grantedAuditRows(role) + revokedAuditRows(role)).as("iteration %d", i).isZero();
    }
  }

  // ── Set-lock path (T-019, design §10.4, §10.8 cases (d), (e), (f)) ───────────────────

  /**
   * (d) A PUT promoting R and a DELETE of R, queued behind the gate in both arrival orders. Both
   * start at R's row (the promotion: row, then set lock; the delete of a non-admin-defining role:
   * row, then its holder read), so they serialise there: the promotion applies and the delete
   * follows, or the delete wins and the PUT finds the row gone (404). Never a deadlock.
   */
  @Test
  void should_serialiseWithoutDeadlock_when_aPromotionAndADeleteOfTheRoleQueueInEitherOrder()
      throws Exception {
    List<UUID> catalogue = catalogueIds();
    RoleChangeActor admin = seedEditor(catalogue.toArray(UUID[]::new));
    UUID[] allButOne = catalogue.subList(1, catalogue.size()).toArray(UUID[]::new);
    Set<Outcome> replaceOutcomes = new HashSet<>();
    for (int i = 0; i < ITERATIONS; i++) {
      boolean replaceArrivesFirst = i % 2 == 0;
      Role role = seedRole(allButOne);
      String v0 = version(role, allButOne);
      Callable<Outcome> promote = () -> replace(admin, role, Set.copyOf(catalogue), v0);
      Callable<Outcome> delete = () -> softDelete(admin, role);

      Future<Outcome> replaced;
      Future<Outcome> deleted;
      try (Connection gate = lockRoleRowAsNexusApp(role)) {
        if (replaceArrivesFirst) {
          replaced = executor.submit(promote);
          awaitLockWaiters(1);
          deleted = executor.submit(delete);
        } else {
          deleted = executor.submit(delete);
          awaitLockWaiters(1);
          replaced = executor.submit(promote);
        }
        awaitLockWaiters(2);
        gate.commit();
      }
      Outcome replaceOutcome = await(replaced);
      Outcome deleteOutcome = await(deleted);

      assertThat(deleteOutcome).as("iteration %d: the delete always applies", i)
          .isEqualTo(Outcome.OK);
      assertThat(replaceOutcome).as("iteration %d", i).isIn(Outcome.OK, Outcome.NOT_FOUND);
      assertThat(isDeleted(role)).as("iteration %d", i).isTrue();
      assertThat(rolePermissionIds(role))
          .as("iteration %d (replace first: %s): a serial order", i, replaceArrivesFirst)
          .isEqualTo(replaceOutcome == Outcome.OK ? Set.copyOf(catalogue) : Set.of(allButOne));
      replaceOutcomes.add(replaceOutcome);
    }
    assertThat(replaceOutcomes).as("both serial orders occurred").hasSize(2);
  }

  /**
   * (e) A PUT demoting an admin-defining R races an assign of R. Both take the set lock first, so
   * they serialise on it: both always succeed and the final state is the demoted set with the new
   * holder. Never a deadlock.
   */
  @Test
  void should_serialiseOnTheSetLock_when_aDemotionRacesAnAssignOfTheRole() throws Exception {
    List<UUID> catalogue = catalogueIds();
    RoleChangeActor admin = seedEditor(catalogue.toArray(UUID[]::new));
    Set<UUID> demoted = new HashSet<>(catalogue);
    demoted.remove(AUDIT_READ);
    for (int i = 0; i < ITERATIONS; i++) {
      Role role = seedRole(catalogue.toArray(UUID[]::new));
      String v0 = version(role, catalogue.toArray(UUID[]::new));
      User assignee = seedUser();
      CyclicBarrier start = new CyclicBarrier(2);

      Future<Outcome> replaced =
          executor.submit(barrier(start, () -> replace(admin, role, demoted, v0)));
      Future<Outcome> assigned =
          executor.submit(barrier(start, () -> assign(admin, assignee.getId(), role)));

      assertThat(await(replaced)).as("iteration %d", i).isEqualTo(Outcome.OK);
      assertThat(await(assigned)).as("iteration %d", i).isEqualTo(Outcome.OK);
      assertThat(rolePermissionIds(role)).as("iteration %d", i).isEqualTo(demoted);
      assertThat(activeHolderAssigners(role)).as("iteration %d", i).hasSize(1);
    }
  }

  /**
   * (f) A PUT promoting R, whose one holder was assigned by a non-administrator, races a revoke of
   * that holder. The promotion's set lock reads the holder row current: either the revoke
   * committed first and the promotion applies, or the promotion sees the holder and is 409 {@code
   * RBAC_010} while the revoke then applies. Never an admin-defining R with a non-administrator-
   * assigned holder, never a deadlock.
   */
  @Test
  void should_neverLeaveANonAdministratorAssignedHolderOnAPromotedRole_when_aPromotionRacesARevoke()
      throws Exception {
    List<UUID> catalogue = catalogueIds();
    RoleChangeActor admin = seedEditor(catalogue.toArray(UUID[]::new));
    User nonAdministrator = seedUser();
    UUID[] allButOne = catalogue.subList(1, catalogue.size()).toArray(UUID[]::new);
    for (int i = 0; i < ITERATIONS; i++) {
      Role role = seedRole(allButOne);
      String v0 = version(role, allButOne);
      User holder = seedUser();
      userRoleRepository.save(
          new UserRole(
              uuidGenerator.newId(), holder.getId(), role.getId(), tenantId,
              nonAdministrator.getId()));
      CyclicBarrier start = new CyclicBarrier(2);

      Future<Outcome> replaced =
          executor.submit(barrier(start, () -> replace(admin, role, Set.copyOf(catalogue), v0)));
      Future<Outcome> revoked =
          executor.submit(barrier(start, () -> revoke(admin, holder.getId(), role)));
      Outcome replaceOutcome = await(replaced);

      assertThat(await(revoked)).as("iteration %d: the revoke always applies", i)
          .isEqualTo(Outcome.OK);
      assertThat(replaceOutcome).as("iteration %d", i)
          .isIn(Outcome.OK, Outcome.PROVENANCE_CONFLICT);
      assertThat(rolePermissionIds(role))
          .as("iteration %d", i)
          .isEqualTo(replaceOutcome == Outcome.OK ? Set.copyOf(catalogue) : Set.of(allButOne));
      assertThat(activeHolderAssigners(role)).as("iteration %d", i).isEmpty();
    }
  }

  // ── Racers ───────────────────────────────────────────────────────────────────────────

  private enum Outcome {
    OK,
    PRECONDITION_FAILED,
    NOT_FOUND,
    PROVENANCE_CONFLICT
  }

  private Outcome replace(Role role, Set<UUID> target, String ifMatch) {
    return replace(actor, role, target, ifMatch);
  }

  /**
   * Anything but success, the 412, the 404 of a role deleted first or the 409 {@code RBAC_010}
   * propagates and fails the test (a 1213 above all).
   */
  private Outcome replace(RoleChangeActor caller, Role role, Set<UUID> target, String ifMatch) {
    try {
      roleManagementService.replaceRolePermissions(
          caller, role.getId(), target, ifMatch, RequestContext.UNKNOWN);
      return Outcome.OK;
    } catch (PreconditionFailedException e) {
      return Outcome.PRECONDITION_FAILED;
    } catch (ResourceNotFoundException e) {
      return Outcome.NOT_FOUND;
    } catch (AttachProvenanceConflictException e) {
      return Outcome.PROVENANCE_CONFLICT;
    }
  }

  private Outcome softDelete(RoleChangeActor caller, Role role) {
    roleManagementService.softDeleteRole(caller, role.getId(), RequestContext.UNKNOWN);
    return Outcome.OK;
  }

  private Outcome assign(RoleChangeActor caller, UUID userId, Role role) {
    roleAssignmentService.assign(caller, userId, role.getId(), RequestContext.UNKNOWN);
    return Outcome.OK;
  }

  private Outcome revoke(RoleChangeActor caller, UUID userId, Role role) {
    roleAssignmentService.revoke(caller, userId, role.getId(), RequestContext.UNKNOWN);
    return Outcome.OK;
  }

  private Outcome attach(Role role, UUID permissionId) {
    roleManagementService.attachPermission(actor, role.getId(), permissionId, RequestContext.UNKNOWN);
    return Outcome.OK;
  }

  private Outcome detach(Role role, UUID permissionId) {
    roleManagementService.detachPermission(actor, role.getId(), permissionId, RequestContext.UNKNOWN);
    return Outcome.OK;
  }

  private static Callable<Outcome> barrier(CyclicBarrier start, Callable<Outcome> racer) {
    return () -> {
      start.await(10, TimeUnit.SECONDS);
      return racer.call();
    };
  }

  private static Outcome await(Future<Outcome> future)
      throws InterruptedException, java.util.concurrent.TimeoutException {
    try {
      return future.get(60, TimeUnit.SECONDS);
    } catch (ExecutionException e) {
      throw new AssertionError("a racer failed: " + e.getCause(), e.getCause());
    }
  }

  // ── Gate and observer ────────────────────────────────────────────────────────────────

  /** A nexus_app transaction holding the role row's X lock, with the statement B8 uses. */
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
    String email = "rprc-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRepository.save(
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  private RoleChangeActor seedEditor(UUID... permissionIds) {
    User editor = seedUser();
    Role editorRole = seedRole(permissionIds);
    userRoleRepository.save(
        new UserRole(
            uuidGenerator.newId(), editor.getId(), editorRole.getId(), tenantId, editor.getId()));
    return new RoleChangeActor(editor.getId(), tenantId);
  }

  private Role seedRole(UUID... permissionIds) {
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, "RPRC-" + UUID.randomUUID(), null, false));
    for (UUID permissionId : permissionIds) {
      rolePermissionRepository.save(new RolePermission(role.getId(), permissionId));
    }
    return role;
  }

  private static String version(Role role, UUID... permissionIds) {
    return RolePermissionSetVersion.of(role.getId(), List.of(permissionIds));
  }

  private Set<UUID> rolePermissionIds(Role role) {
    return new HashSet<>(
        jdbc
            .queryForList(
                "SELECT permission_id FROM role_permissions WHERE role_id = ?",
                byte[].class,
                (Object) toBytes(role.getId()))
            .stream()
            .map(RolePermissionReplaceConcurrencyIT::fromBytes)
            .toList());
  }

  private List<UUID> catalogueIds() {
    return jdbc.queryForList("SELECT id FROM permissions ORDER BY name", byte[].class).stream()
        .map(RolePermissionReplaceConcurrencyIT::fromBytes)
        .toList();
  }

  private boolean isDeleted(Role role) {
    Integer live =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM roles WHERE id = ? AND deleted_at IS NULL",
            Integer.class,
            (Object) toBytes(role.getId()));
    return live != null && live == 0;
  }

  /** The assigners of R's active holders, ids only. */
  private List<UUID> activeHolderAssigners(Role role) {
    return jdbc
        .queryForList(
            "SELECT assigned_by FROM user_roles WHERE role_id = ? AND revoked_at IS NULL",
            byte[].class,
            (Object) toBytes(role.getId()))
        .stream()
        .map(RolePermissionReplaceConcurrencyIT::fromBytes)
        .toList();
  }

  private int grantedAuditRows(Role role) {
    return auditRows(role, "ROLE_PERMISSION_GRANTED");
  }

  private int revokedAuditRows(Role role) {
    return auditRows(role, "ROLE_PERMISSION_REVOKED");
  }

  private int auditRows(Role role, String eventType) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM auth_events WHERE tenant_id = ? AND event_type = ?"
                + " AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.roleId')) = ?",
            Integer.class,
            toBytes(tenantId),
            eventType,
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
