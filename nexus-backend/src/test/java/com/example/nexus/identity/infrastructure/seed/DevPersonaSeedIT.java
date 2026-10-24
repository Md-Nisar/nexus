package com.example.nexus.identity.infrastructure.seed;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.rbac.domain.RbacAdministrators;
import com.example.nexus.rbac.domain.RolePermissionRef;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

/**
 * US-019 T-023 against a real MySQL: the {@code dev} profile seeds every persona, the fixture-only
 * second tenant's administrator counts as an administrator under {@link RbacAdministrators}, no
 * tenant of the seed is left without an active administrator, persona assignments are never
 * self-assigned, and the seed logs no email.
 *
 * <p>US-020 T-014 (design §19.4): the role-reader user manager and the auditor hold exactly their
 * designed permissions and neither is an administrator; both assignment targets are ACTIVE, target
 * A holds no role and target B holds its one custom role, assigned by the seeded administrator.
 * Their absence under {@code dev,prod} (RC-77) is proved in {@link DevSeedProfileGuardTest}.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("dev")
@Tag("IT")
class DevPersonaSeedIT {

  private static final List<String> BOOTSTRAP_PERSONAS =
      List.of(
          DevUserSeeder.E2E_EMAIL,
          DevUserSeeder.SECOND_ADMIN_EMAIL,
          DevUserSeeder.MEMBER_EMAIL,
          DevUserSeeder.ROLE_MANAGER_EMAIL,
          DevUserSeeder.USER_MANAGER_EMAIL,
          DevUserSeeder.LOCKED_EMAIL,
          DevUserSeeder.PENDING_EMAIL,
          DevUserSeeder.ROLE_READER_USER_MANAGER_EMAIL,
          DevUserSeeder.AUDITOR_EMAIL,
          DevUserSeeder.TARGET_A_EMAIL,
          DevUserSeeder.TARGET_B_EMAIL);

  @Autowired private DevDataInitializer initializer;
  @Autowired private EmailBlindIndexService blindIndex;
  @Autowired private UserRoleAssignmentPort userRoleAssignmentPort;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JdbcTemplate jdbc;

  @Value("${nexus.identity.default-tenant-id}")
  private UUID defaultTenantId;

  private ListAppender<ILoggingEvent> appender;
  private Logger seedLogger;

  @BeforeEach
  void captureLogs() {
    seedLogger = (Logger) LoggerFactory.getLogger(DevDataInitializer.class);
    appender = new ListAppender<>();
    appender.start();
    seedLogger.addAppender(appender);
  }

  @AfterEach
  void detachAppender() {
    seedLogger.detachAppender(appender);
  }

  @Test
  void should_createEveryPersona_when_devProfileStarts() {
    for (String email : BOOTSTRAP_PERSONAS) {
      assertThat(userCount(defaultTenantId, email)).as(email).isEqualTo(1);
    }
    assertThat(userCount(DevUserSeeder.SECOND_TENANT_ID, DevUserSeeder.SECOND_TENANT_ADMIN_EMAIL))
        .isEqualTo(1);
  }

  @Test
  void should_treatSecondTenantAdminAsAdministrator_when_checkedAgainstTheCatalogue() {
    List<RolePermissionRef> held =
        userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(
            DevUserSeeder.SECOND_TENANT_ADMIN_ID, DevUserSeeder.SECOND_TENANT_ID);
    Set<UUID> catalogue = userRoleAssignmentPort.findCatalogueIds();

    assertThat(RbacAdministrators.isAdministrator(held, catalogue)).isTrue();
  }

  @Test
  void should_leaveNoSeededTenantWithoutAnActiveAdministrator_when_seeded() {
    Set<UUID> withAdminRole = new HashSet<>(userRoleRepository.findTenantsWithAnAdminDefiningRole());
    withAdminRole.removeAll(userRoleRepository.findTenantsWithActiveAdminDefiningHolders());

    assertThat(withAdminRole).doesNotContain(defaultTenantId, DevUserSeeder.SECOND_TENANT_ID);
  }

  @Test
  void should_neverSelfAssignAPersona_when_seeded() {
    Integer selfAssigned =
        jdbc.queryForObject(
            """
            SELECT COUNT(*) FROM user_roles ur JOIN users u ON u.id = ur.user_id
            WHERE ur.assigned_by = ur.user_id AND u.tenant_id = ?
              AND u.email_hmac <> ?
            """,
            Integer.class,
            uuidBytes(defaultTenantId),
            blindIndex.blindIndex(DevUserSeeder.E2E_EMAIL));

    assertThat(selfAssigned).isZero();
  }

  @Test
  void should_grantExactlyTheDesignedPermissions_when_newPersonasSeeded() {
    assertThat(effectivePermissionNames(DevUserSeeder.ROLE_READER_USER_MANAGER_EMAIL))
        .containsExactlyInAnyOrder(
            "role:read", "user:read", "user:role:assign", "user:directory:read");
    assertThat(effectivePermissionNames(DevUserSeeder.AUDITOR_EMAIL))
        .containsExactlyInAnyOrder("role:read", "audit:read");
    assertThat(effectivePermissionNames(DevUserSeeder.TARGET_A_EMAIL)).isEmpty();
    assertThat(effectivePermissionNames(DevUserSeeder.TARGET_B_EMAIL)).containsExactly("role:read");
  }

  @Test
  void should_notTreatTheNewPersonasAsAdministrators_when_checkedAgainstTheCatalogue() {
    Set<UUID> catalogue = userRoleAssignmentPort.findCatalogueIds();

    for (String email :
        List.of(DevUserSeeder.ROLE_READER_USER_MANAGER_EMAIL, DevUserSeeder.AUDITOR_EMAIL)) {
      List<RolePermissionRef> held =
          userRoleAssignmentPort.findHeldRolePermissionIdsForAuthorization(
              userId(email), defaultTenantId);
      assertThat(held).isNotEmpty();
      assertThat(RbacAdministrators.isAdministrator(held, catalogue)).isFalse();
    }
  }

  @Test
  void should_seedBothTargetsActive_when_devProfileStarts() {
    for (String email : List.of(DevUserSeeder.TARGET_A_EMAIL, DevUserSeeder.TARGET_B_EMAIL)) {
      String status =
          jdbc.queryForObject(
              "SELECT status FROM users WHERE tenant_id = ? AND email_hmac = ?",
              String.class,
              uuidBytes(defaultTenantId),
              blindIndex.blindIndex(email));
      assertThat(status).isEqualTo("ACTIVE");
    }
  }

  @Test
  void should_recordTheSeededAdministratorAsAssigner_when_targetBHoldsItsRole() {
    List<byte[]> assigners =
        jdbc.queryForList(
            """
            SELECT ur.assigned_by FROM user_roles ur JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = ? AND ur.revoked_at IS NULL AND r.name = ?
            """,
            byte[].class,
            uuidBytes(userId(DevUserSeeder.TARGET_B_EMAIL)),
            DevDataInitializer.TARGET_ROLE);

    assertThat(assigners)
        .singleElement()
        .isEqualTo(uuidBytes(userId(DevUserSeeder.E2E_EMAIL)));
  }

  @Test
  void should_logNoSeededEmail_when_seedingRunsAgain() {
    initializer.run(null);

    List<String> messages = appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    assertThat(messages).anyMatch(m -> m.startsWith("DEV_SEED_COMPLETED"));
    for (String email : allEmails()) {
      assertThat(messages).noneMatch(m -> m.contains(email));
    }
  }

  private List<String> allEmails() {
    return List.of(
        DevUserSeeder.E2E_EMAIL,
        DevUserSeeder.SECOND_ADMIN_EMAIL,
        DevUserSeeder.MEMBER_EMAIL,
        DevUserSeeder.ROLE_MANAGER_EMAIL,
        DevUserSeeder.USER_MANAGER_EMAIL,
        DevUserSeeder.LOCKED_EMAIL,
        DevUserSeeder.PENDING_EMAIL,
        DevUserSeeder.SECOND_TENANT_ADMIN_EMAIL,
        DevUserSeeder.ROLE_READER_USER_MANAGER_EMAIL,
        DevUserSeeder.AUDITOR_EMAIL,
        DevUserSeeder.TARGET_A_EMAIL,
        DevUserSeeder.TARGET_B_EMAIL);
  }

  /** Permission names reachable through the user's active assignments to live roles. */
  private List<String> effectivePermissionNames(String email) {
    return jdbc.queryForList(
        """
        SELECT DISTINCT p.name FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id AND r.deleted_at IS NULL
        JOIN role_permissions rp ON rp.role_id = r.id
        JOIN permissions p ON p.id = rp.permission_id
        WHERE ur.user_id = ? AND ur.revoked_at IS NULL
        """,
        String.class,
        uuidBytes(userId(email)));
  }

  private UUID userId(String email) {
    byte[] id =
        jdbc.queryForObject(
            "SELECT id FROM users WHERE tenant_id = ? AND email_hmac = ?",
            byte[].class,
            uuidBytes(defaultTenantId),
            blindIndex.blindIndex(email));
    ByteBuffer buffer = ByteBuffer.wrap(id);
    return new UUID(buffer.getLong(), buffer.getLong());
  }

  private int userCount(UUID tenantId, String email) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM users WHERE tenant_id = ? AND email_hmac = ?",
            Integer.class,
            uuidBytes(tenantId),
            blindIndex.blindIndex(email));
    return count == null ? 0 : count;
  }

  private static byte[] uuidBytes(UUID id) {
    ByteBuffer buffer = ByteBuffer.allocate(16);
    buffer.putLong(id.getMostSignificantBits());
    buffer.putLong(id.getLeastSignificantBits());
    return buffer.array();
  }
}
