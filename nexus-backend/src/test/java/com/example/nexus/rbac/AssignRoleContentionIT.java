package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.RoleManagementService;
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
import java.util.ArrayList;
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
import java.util.concurrent.TimeoutException;
import java.util.function.Function;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
 * US-019 T-020, RC-67(a) (T-D29; design §10.8, §10.9): the non-admin-defining assign now ends with a
 * {@code FOR SHARE} current read of R's {@code role_permissions} (RC-56.2) and holds those S locks
 * until it commits. This proves, with the application <b>connected as {@code nexus_app}</b>, that
 * assign racing each {@code role_permissions} writer on the same R (attach, detach, and a B8 replace
 * on the role-row path) never deadlocks and never fails, 50 iterations each, and logs (does not
 * assert) the wait the assign adds to the writer: the writer's p95 duration when started together
 * with an assign, minus its p95 alone.
 *
 * <p>Lock orders (design §10.4): assign takes R's row S (its {@code INSERT … SELECT}), its new
 * {@code user_roles} row, then the {@code FOR SHARE} read. Attach and B8 take R's row X first, so
 * they serialise with assign on the row; detach takes only its {@code role_permissions} record and
 * waits on nothing assign holds. Any exception from either racer, a 1213 above all, fails the run.
 */
@SpringBootTest
@Import({TestcontainersConfiguration.class, AssignRoleContentionIT.NexusAppConnection.class})
@ActiveProfiles("test")
@Tag("IT")
class AssignRoleContentionIT {

  private static final int ITERATIONS = 50;
  private static final int WARM_UP = 10;
  private static final Logger log = LoggerFactory.getLogger(AssignRoleContentionIT.class);
  private static final String NEXUS_APP_USER = "nexus_app";
  private static final String NEXUS_APP_PASSWORD = "nexus_app_test_only";
  private static final UUID ROLE_READ = RbacSeededPermissionIds.ROLE_READ;
  private static final UUID ROLE_WRITE = RbacSeededPermissionIds.ROLE_WRITE;
  private static final UUID USER_READ = RbacSeededPermissionIds.USER_READ;
  private static final UUID USER_WRITE = RbacSeededPermissionIds.USER_WRITE;
  private static final UUID AUDIT_READ = RbacSeededPermissionIds.AUDIT_READ;
  private static final UUID USER_ROLE_ASSIGN = RbacSeededPermissionIds.USER_ROLE_ASSIGN;

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

  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private RoleManagementService roleManagementService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  private ExecutorService executor;
  private UUID tenantId;
  private RoleChangeActor editor;

  @BeforeEach
  void setUp() {
    executor = Executors.newFixedThreadPool(2);
    tenantId = uuidGenerator.newId();
    editor = seedEditor(ROLE_READ, ROLE_WRITE, USER_READ, USER_WRITE, AUDIT_READ, USER_ROLE_ASSIGN);
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
  void should_neverDeadlockOrFail_when_anAssignRacesAnAttachOnTheSameRole()
      throws Exception {
    Function<Role, Callable<Void>> attach = role -> attach(role, USER_WRITE);
    measureAgainstAssign(() -> seedRole(USER_READ), attach, Set.of(USER_READ, USER_WRITE));
  }

  @Test
  void should_neverDeadlockOrFail_when_anAssignRacesADetachOnTheSameRole()
      throws Exception {
    Function<Role, Callable<Void>> detach = role -> detach(role, AUDIT_READ);
    measureAgainstAssign(() -> seedRole(USER_READ, AUDIT_READ), detach, Set.of(USER_READ));
  }

  @Test
  void should_neverDeadlockOrFail_when_anAssignRacesAReplaceOnTheSameRole()
      throws Exception {
    Function<Role, Callable<Void>> replace =
        role ->
            replace(
                role,
                Set.of(USER_READ, USER_WRITE),
                RolePermissionSetVersion.of(role.getId(), List.of(USER_READ)));
    measureAgainstAssign(() -> seedRole(USER_READ), replace, Set.of(USER_READ, USER_WRITE));
  }

  /**
   * Runs {@code writer} alone ({@link #ITERATIONS} times after {@link #WARM_UP}) and then started
   * together with an assign of the same fresh role ({@link #ITERATIONS} times), asserting that both
   * racers always succeed and that the role ends at {@code expectedSet} with the assignee holding
   * it; the writer's p95 alone and contended are logged, not asserted.
   */
  private void measureAgainstAssign(
      Supplier<Role> freshRole,
      Function<Role, Callable<Void>> writer,
      Set<UUID> expectedSet)
      throws Exception {
    List<Long> alone = new ArrayList<>();
    for (int i = 0; i < WARM_UP + ITERATIONS; i++) {
      Role role = freshRole.get();
      long elapsed = timed(writer.apply(role)).call();
      if (i >= WARM_UP) {
        alone.add(elapsed);
      }
    }

    List<Long> contended = new ArrayList<>();
    for (int i = 0; i < ITERATIONS; i++) {
      Role role = freshRole.get();
      User assignee = seedUser();
      CyclicBarrier start = new CyclicBarrier(2);

      Future<Long> written = executor.submit(barrier(start, timed(writer.apply(role))));
      Future<Long> assigned = executor.submit(barrier(start, timed(assign(assignee, role))));
      contended.add(await(written));
      await(assigned);

      assertThat(rolePermissionIds(role)).as("iteration %d", i).isEqualTo(expectedSet);
      assertThat(activeHolders(role)).as("iteration %d", i).containsExactly(assignee.getId());
    }

    // Timing is reported, not asserted (US-019 review R1-4): a latency delta on a shared CI runner
    // is noise, and the invariants (no deadlock, no failure, the right end state) are asserted above.
    log.info(
        "ASSIGN_CONTENTION_P95 writer p95 alone={} ns, against a concurrent assign={} ns, added={} ms",
        p95(alone),
        p95(contended),
        (p95(contended) - p95(alone)) / 1_000_000);
  }

  // ── Racers ───────────────────────────────────────────────────────────────────────────

  private Callable<Void> assign(User assignee, Role role) {
    return () -> {
      roleAssignmentService.assign(editor, assignee.getId(), role.getId(), RequestContext.UNKNOWN);
      return null;
    };
  }

  private Callable<Void> attach(Role role, UUID permissionId) {
    return () -> {
      roleManagementService.attachPermission(
          editor, role.getId(), permissionId, RequestContext.UNKNOWN);
      return null;
    };
  }

  private Callable<Void> detach(Role role, UUID permissionId) {
    return () -> {
      roleManagementService.detachPermission(
          editor, role.getId(), permissionId, RequestContext.UNKNOWN);
      return null;
    };
  }

  private Callable<Void> replace(Role role, Set<UUID> target, String ifMatch) {
    return () -> {
      roleManagementService.replaceRolePermissions(
          editor, role.getId(), target, ifMatch, RequestContext.UNKNOWN);
      return null;
    };
  }

  /** Wraps {@code racer} so it returns its own duration in nanoseconds. */
  private static Callable<Long> timed(Callable<Void> racer) {
    return () -> {
      long started = System.nanoTime();
      racer.call();
      return System.nanoTime() - started;
    };
  }

  private static Callable<Long> barrier(CyclicBarrier start, Callable<Long> racer) {
    return () -> {
      start.await(10, TimeUnit.SECONDS);
      return racer.call();
    };
  }

  private static long await(Future<Long> future) throws InterruptedException, TimeoutException {
    try {
      return future.get(60, TimeUnit.SECONDS);
    } catch (ExecutionException e) {
      throw new AssertionError("a racer failed: " + e.getCause(), e.getCause());
    }
  }

  private static long p95(List<Long> samples) {
    List<Long> sorted = samples.stream().sorted().toList();
    return sorted.get((int) Math.ceil(0.95 * sorted.size()) - 1);
  }

  // ── Fixtures and reads (all as nexus_app) ────────────────────────────────────────────

  private User seedUser() {
    String email = "arc-" + UUID.randomUUID() + "@example.com";
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
            new Role(uuidGenerator.newId(), tenantId, "ARC-" + UUID.randomUUID(), null, false));
    for (UUID permissionId : permissionIds) {
      rolePermissionRepository.save(new RolePermission(role.getId(), permissionId));
    }
    return role;
  }

  private Set<UUID> rolePermissionIds(Role role) {
    return new HashSet<>(idsWhere("SELECT permission_id FROM role_permissions WHERE role_id = ?", role));
  }

  private List<UUID> activeHolders(Role role) {
    return idsWhere("SELECT user_id FROM user_roles WHERE role_id = ? AND revoked_at IS NULL", role);
  }

  private List<UUID> idsWhere(String sql, Role role) {
    return jdbc.queryForList(sql, byte[].class, (Object) toBytes(role.getId())).stream()
        .map(AssignRoleContentionIT::fromBytes)
        .toList();
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
