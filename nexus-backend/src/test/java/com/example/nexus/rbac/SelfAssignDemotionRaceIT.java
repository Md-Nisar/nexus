package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermissionSetVersion;
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
 * US-019 review R1-2 / S1-Medium (RC-57.2, T-E49): a self-assign of an admin-defining role must
 * classify the caller from a current read under the set lock. The caller's only administrator role
 * D is demoted (a committed B8 replace) after the assign read the tenant's roles (M10', which still
 * lists D as admin-defining) and before it took the set lock, the state a request queued behind the
 * demotion wakes up in. The order is forced, not raced: the assign thread is parked right after its
 * M10' read. A stale classification would let the demoted caller self-assign; the current read must
 * deny it (403 {@code SELF_ASSIGNMENT}). The application <b>connects as {@code nexus_app}</b>.
 */
@SpringBootTest
@Import({TestcontainersConfiguration.class, SelfAssignDemotionRaceIT.NexusAppConnection.class})
@ActiveProfiles("test")
@Tag("IT")
class SelfAssignDemotionRaceIT {

  private static final String NEXUS_APP_USER = "nexus_app";
  private static final String NEXUS_APP_PASSWORD = "nexus_app_test_only";
  private static final int ITERATIONS = 5;
  private static final UUID DEMOTED_PERMISSION = RbacSeededPermissionIds.AUDIT_READ;

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
  void should_denyTheSelfAssignWithSelfAssignment_when_theCallersAdminRoleWasDemotedAfterItsPreLockRead()
      throws Exception {
    for (int i = 0; i < ITERATIONS; i++) {
      Fixture fixture = seedFixture();
      Set<UUID> demoted = new HashSet<>(fixture.catalogue());
      demoted.remove(DEMOTED_PERMISSION);

      Future<String> selfAssign = startSelfAssignParkedAfterItsRoleRead(fixture);
      assertThat(parked.await(30, TimeUnit.SECONDS)).as("self-assign parked").isTrue();
      try {
        roleManagementService.replaceRolePermissions(
            fixture.admin(),
            fixture.callersRoleId(),
            demoted,
            RolePermissionSetVersion.of(fixture.callersRoleId(), fixture.catalogue()),
            RequestContext.UNKNOWN);
      } finally {
        resume.countDown();
      }

      assertThat(selfAssign.get(60, TimeUnit.SECONDS))
          .as("iteration %d", i)
          .isEqualTo("DENIED_" + DenialReason.SELF_ASSIGNMENT);
      assertThat(activeHolders(fixture.targetRoleId()))
          .as("iteration %d: the demoted caller did not gain the administrator role", i)
          .isZero();
    }
  }

  // ── Forced order ─────────────────────────────────────────────────────────────────────

  private volatile CountDownLatch parked;
  private volatile CountDownLatch resume;

  /**
   * Starts the caller's self-assign of the admin-defining role and parks it right after the
   * tenant's roles were read (M10'), before it asks for the set lock.
   */
  private Future<String> startSelfAssignParkedAfterItsRoleRead(Fixture fixture) {
    parked = new CountDownLatch(1);
    resume = new CountDownLatch(1);
    AtomicReference<Thread> assignThread = new AtomicReference<>();
    doAnswer(
            invocation -> {
              Object roles = invocation.callRealMethod();
              if (Thread.currentThread() == assignThread.get()) {
                parked.countDown();
                if (!resume.await(30, TimeUnit.SECONDS)) {
                  throw new AssertionError("the self-assign was never resumed");
                }
              }
              return roles;
            })
        .when(userRoleAssignmentPort)
        .findRolePermissionIdsForTenantRoles(any());

    return executor.submit(
        () -> {
          assignThread.set(Thread.currentThread());
          try {
            roleAssignmentService.assign(
                fixture.caller(),
                fixture.caller().userId(),
                fixture.targetRoleId(),
                RequestContext.UNKNOWN);
            return "OK";
          } catch (InsufficientPermissionException e) {
            return "DENIED_" + e.getReason();
          }
        });
  }

  // ── Fixtures ─────────────────────────────────────────────────────────────────────────

  /**
   * A tenant administrator B (the whole catalogue), the caller U whose only administrator role is
   * the custom role D (the whole catalogue), and a second admin-defining custom role R that U will
   * try to self-assign.
   */
  private Fixture seedFixture() {
    UUID tenantId = uuidGenerator.newId();
    List<UUID> catalogue = List.copyOf(permissionCatalogueRepository.findCatalogueIds());

    Role adminRole = seedRole(tenantId, "TENANT_ADMIN");
    Role callersRole = seedRole(tenantId, "SADEMO-D-" + UUID.randomUUID());
    Role targetRole = seedRole(tenantId, "SADEMO-R-" + UUID.randomUUID());
    for (Role role : List.of(adminRole, callersRole, targetRole)) {
      catalogue.forEach(id -> grant(role.getId(), id));
    }
    User admin = seedUser(tenantId);
    seedAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());
    User caller = seedUser(tenantId);
    seedAssignment(tenantId, callersRole.getId(), caller.getId(), admin.getId());

    return new Fixture(
        new RoleChangeActor(admin.getId(), tenantId),
        new RoleChangeActor(caller.getId(), tenantId),
        callersRole.getId(),
        targetRole.getId(),
        Set.copyOf(catalogue));
  }

  private record Fixture(
      RoleChangeActor admin,
      RoleChangeActor caller,
      UUID callersRoleId,
      UUID targetRoleId,
      Set<UUID> catalogue) {}

  private User seedUser(UUID tenantId) {
    String email = "sademo-" + UUID.randomUUID() + "@example.com";
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

  private int activeHolders(UUID roleId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE role_id = ? AND revoked_at IS NULL",
            Integer.class,
            toBytes(roleId));
    return count == null ? 0 : count;
  }

  private static byte[] toBytes(UUID uuid) {
    return ByteBuffer.allocate(16)
        .putLong(uuid.getMostSignificantBits())
        .putLong(uuid.getLeastSignificantBits())
        .array();
  }
}
