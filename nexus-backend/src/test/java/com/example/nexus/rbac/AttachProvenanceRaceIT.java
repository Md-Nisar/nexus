package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.AttachProvenanceConflictException;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaPermissionCatalogueRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
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
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.testcontainers.containers.MySQLContainer;

/**
 * US-019 review R1-1 (T-E48, RES-26): an attach that completes the catalogue must still refuse
 * (409 {@code RBAC_010}) when a non-administrator's assign to the role committed after the
 * attach's pre-lock provenance read and before it got the role row. The order is forced, not
 * raced: the attach thread is parked right after its pre-lock holder read (which sees no holder),
 * the assign runs to commit, then the attach resumes, takes the role row and must re-judge the
 * holders from locked rows (REPEATABLE READ would hide the new row from a plain re-read). The
 * application <b>connects as {@code nexus_app}</b> (never the Testcontainers user).
 */
@SpringBootTest
@Import({TestcontainersConfiguration.class, AttachProvenanceRaceIT.NexusAppConnection.class})
@ActiveProfiles("test")
@Tag("IT")
class AttachProvenanceRaceIT {

  private static final String NEXUS_APP_USER = "nexus_app";
  private static final String NEXUS_APP_PASSWORD = "nexus_app_test_only";
  private static final int ITERATIONS = 5;
  private static final UUID MISSING = RbacSeededPermissionIds.USER_DIRECTORY_READ;

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

  @MockitoSpyBean private UserRoleAssignmentPort userRoleAssignmentPort;
  @Autowired private RoleManagementService roleManagementService;
  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaPermissionCatalogueRepository permissionCatalogueRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  private final ExecutorService executor = Executors.newSingleThreadExecutor();

  @AfterEach
  void tearDown() throws InterruptedException {
    executor.shutdownNow();
    assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
  }

  @Test
  void should_refuseTheAttachWithRbac010_when_aNonAdministratorAssignCommittedAfterItsPreLockRead()
      throws Exception {
    for (int i = 0; i < ITERATIONS; i++) {
      Fixture fixture = seedFixture();

      String attach = attachParkedAfterItsHolderReadWhile(fixture, () -> assign(fixture.assigner(), fixture));

      assertThat(attach).as("iteration %d", i).isEqualTo("RBAC_010");
      assertThat(rolePermissionIds(fixture.role()))
          .as("iteration %d: the role stayed one short, so the tenant gained no administrator", i)
          .doesNotContain(MISSING);
      assertThat(activeHolders(fixture.role())).as("iteration %d", i).isEqualTo(1);
    }
  }

  @Test
  void should_completeTheAttach_when_anAdministratorAssignCommittedAfterItsPreLockRead()
      throws Exception {
    for (int i = 0; i < ITERATIONS; i++) {
      Fixture fixture = seedFixture();

      String attach = attachParkedAfterItsHolderReadWhile(fixture, () -> assign(fixture.admin(), fixture));

      assertThat(attach).as("iteration %d", i).isEqualTo("OK");
      assertThat(rolePermissionIds(fixture.role())).as("iteration %d", i).contains(MISSING);
    }
  }

  // ── Forced order ─────────────────────────────────────────────────────────────────────

  /**
   * Starts the administrator's attach of the missing permission, parks it right after its pre-lock
   * holder read, runs {@code concurrentWrite} to commit on this thread, resumes the attach and
   * returns its outcome.
   */
  private String attachParkedAfterItsHolderReadWhile(Fixture fixture, Runnable concurrentWrite)
      throws Exception {
    CountDownLatch parked = new CountDownLatch(1);
    CountDownLatch resume = new CountDownLatch(1);
    AtomicReference<Thread> attachThread = new AtomicReference<>();
    doAnswer(
            invocation -> {
              Object holders = invocation.callRealMethod();
              if (Thread.currentThread() == attachThread.get()) {
                parked.countDown();
                if (!resume.await(30, TimeUnit.SECONDS)) {
                  throw new AssertionError("the attach was never resumed");
                }
              }
              return holders;
            })
        .when(userRoleAssignmentPort)
        .findActiveHoldersForRole(any(), any());

    Future<String> attach =
        executor.submit(
            () -> {
              attachThread.set(Thread.currentThread());
              try {
                roleManagementService.attachPermission(
                    fixture.admin(), fixture.role().getId(), MISSING, RequestContext.UNKNOWN);
                return "OK";
              } catch (AttachProvenanceConflictException e) {
                return e.code();
              }
            });
    assertThat(parked.await(30, TimeUnit.SECONDS)).as("attach parked after its read").isTrue();
    try {
      concurrentWrite.run();
    } finally {
      resume.countDown();
    }
    return attach.get(60, TimeUnit.SECONDS);
  }

  private void assign(RoleChangeActor assigner, Fixture fixture) {
    roleAssignmentService.assign(
        assigner, fixture.sockPuppetId(), fixture.role().getId(), RequestContext.UNKNOWN);
  }

  // ── Fixtures ─────────────────────────────────────────────────────────────────────────

  /**
   * An administrator (whole catalogue), a custom role R with every permission but {@link #MISSING}
   * and no holder, an assigner who holds exactly R's permissions (so A2 passes and is not an
   * administrator), and the account the assigner will promote. The missing permission is
   * {@code user:directory:read}: every other one is non-PII, so the assigner may hand R out.
   */
  private Fixture seedFixture() {
    UUID tenantId = uuidGenerator.newId();
    List<UUID> catalogue = List.copyOf(permissionCatalogueRepository.findCatalogueIds());

    Role adminRole = seedRole(tenantId, "TENANT_ADMIN");
    catalogue.forEach(id -> grant(adminRole.getId(), id));
    User admin = seedUser(tenantId);
    seedAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());

    Role role = seedRole(tenantId, "PRORACE-R-" + UUID.randomUUID());
    Role assignerRole = seedRole(tenantId, "PRORACE-ASSIGNER-" + UUID.randomUUID());
    catalogue.stream()
        .filter(id -> !id.equals(MISSING))
        .forEach(
            id -> {
              grant(role.getId(), id);
              grant(assignerRole.getId(), id);
            });
    User assigner = seedUser(tenantId);
    seedAssignment(tenantId, assignerRole.getId(), assigner.getId(), admin.getId());
    User sockPuppet = seedUser(tenantId);

    return new Fixture(
        role,
        new RoleChangeActor(admin.getId(), tenantId),
        new RoleChangeActor(assigner.getId(), tenantId),
        sockPuppet.getId());
  }

  private record Fixture(
      Role role, RoleChangeActor admin, RoleChangeActor assigner, UUID sockPuppetId) {}

  private User seedUser(UUID tenantId) {
    String email = "prorace-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRepository.save(
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  private Role seedRole(UUID tenantId, String name) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, name, null, false));
  }

  private void grant(UUID roleId, UUID permissionId) {
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
        toBytes(roleId),
        toBytes(permissionId));
  }

  private void seedAssignment(UUID tenantId, UUID roleId, UUID userId, UUID assignedBy) {
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), userId, roleId, tenantId, assignedBy));
  }

  private Set<UUID> rolePermissionIds(Role role) {
    return new HashSet<>(
        jdbc
            .queryForList(
                "SELECT permission_id FROM role_permissions WHERE role_id = ?",
                byte[].class,
                (Object) toBytes(role.getId()))
            .stream()
            .map(AttachProvenanceRaceIT::fromBytes)
            .toList());
  }

  private int activeHolders(Role role) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE role_id = ? AND revoked_at IS NULL",
            Integer.class,
            toBytes(role.getId()));
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
