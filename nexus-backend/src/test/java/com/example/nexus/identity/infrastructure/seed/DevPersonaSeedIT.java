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
          DevUserSeeder.PENDING_EMAIL);

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
        DevUserSeeder.SECOND_TENANT_ADMIN_EMAIL);
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
