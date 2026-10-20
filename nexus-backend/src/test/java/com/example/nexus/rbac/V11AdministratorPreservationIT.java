package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.infrastructure.health.RbacZeroActiveAdminsHealthIndicator;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

/**
 * US-019 T-001, the V11 semantic IT (03-design.md §3.4, US-018 RC-48.2, TM T-T21/T-E53): V11 adds
 * {@code user:directory:read} without changing who is an administrator.
 *
 * <p>Each test rewinds the shared schema to its pre-V11 catalogue inside the test transaction
 * (removes the V11 permission row and every grant of it), seeds (i) a live full-catalogue custom
 * role with a holder, (ii) a live custom role one permission short (seven of eight) with a holder,
 * and (iii) a soft-deleted full-catalogue role, then executes every statement of the V11 file
 * itself, exactly as Flyway ran it. The transaction rolls back, so nothing leaks into the shared
 * Testcontainers schema. Roles are seeded from the live table, so fixture rows other ITs leave in
 * {@code permissions} cannot make a "full" role one short.
 *
 * <p>The zero-administrator check is tenant-scoped (as in {@code
 * RbacZeroActiveAdminsHealthIndicatorIT}): the shared schema holds other ITs' tenants, so the
 * aggregate status is order-dependent; this test's tenant must never be named by the indicator.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
@Transactional
class V11AdministratorPreservationIT {

  private static final String V11_LOCATION =
      "db/migration/V11__rbac_user_directory_read_permission.sql";
  private static final String DIRECTORY_READ_ID = "019f6839-1808-7000-8000-000000000009";
  private static final String AUDIT_READ_ID = "019f6839-1806-7000-8000-000000000007";

  @Autowired private JdbcTemplate jdbc;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private UuidGenerator uuidGenerator;

  private UUID tenantId;
  private UUID fullRole;
  private UUID fullRoleHolder;
  private UUID sevenOfEightRole;
  private UUID sevenOfEightHolder;
  private UUID softDeletedFullRole;

  @BeforeEach
  void seedPreV11State() {
    rewindToPreV11Catalogue();
    tenantId = uuidGenerator.newId();

    fullRole = RbacTestCatalogue.createAdministratorRole(jdbc, tenantId, "V11-FULL");
    fullRoleHolder = seedHolder(fullRole, "full");

    sevenOfEightRole = insertRole("V11-SEVEN-OF-EIGHT");
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) "
            + "SELECT UUID_TO_BIN(?), id FROM permissions WHERE id <> UUID_TO_BIN(?)",
        sevenOfEightRole.toString(),
        AUDIT_READ_ID);
    sevenOfEightHolder = seedHolder(sevenOfEightRole, "seven");

    softDeletedFullRole =
        RbacTestCatalogue.createAdministratorRole(jdbc, tenantId, "V11-SOFT-DELETED");
    jdbc.update(
        "UPDATE roles SET deleted_at = CURRENT_TIMESTAMP(6) WHERE id = UUID_TO_BIN(?)",
        softDeletedFullRole.toString());
  }

  @Test
  void should_keepFullCatalogueRoleHolderAdministrator_when_v11Applied() throws IOException {
    RbacTestCatalogue.assertAdministrator(jdbc, fullRoleHolder, tenantId);

    applyV11();

    assertThat(holdsDirectoryRead(fullRole)).isTrue();
    RbacTestCatalogue.assertAdministrator(jdbc, fullRoleHolder, tenantId);
  }

  @Test
  void should_attachNothing_when_roleHoldsSevenOfEight() throws IOException {
    Set<String> before = permissionIds(sevenOfEightRole);

    applyV11();

    assertThat(permissionIds(sevenOfEightRole)).isEqualTo(before);
    assertThat(RbacTestCatalogue.isAdministrator(jdbc, sevenOfEightHolder, tenantId)).isFalse();
  }

  @Test
  void should_attachNothing_when_fullCatalogueRoleIsSoftDeleted() throws IOException {
    Set<String> before = permissionIds(softDeletedFullRole);

    applyV11();

    assertThat(permissionIds(softDeletedFullRole)).isEqualTo(before);
  }

  @Test
  void should_reportNoZeroAdminTenant_when_checkedBeforeAndAfterV11() throws IOException {
    assertThat(zeroAdminWarningsNamingTenant()).as("before V11").isEmpty();
    assertThat(userRoleRepository.findTenantsWithActiveAdminDefiningHolders())
        .as("before V11")
        .contains(tenantId);

    applyV11();

    assertThat(zeroAdminWarningsNamingTenant()).as("after V11").isEmpty();
    assertThat(userRoleRepository.findTenantsWithActiveAdminDefiningHolders())
        .as("after V11")
        .contains(tenantId);
  }

  /** The pre-V11 catalogue: the V11 row and every grant of it are removed (rolled back later). */
  private void rewindToPreV11Catalogue() {
    jdbc.update(
        "DELETE FROM role_permissions WHERE permission_id = UUID_TO_BIN(?)", DIRECTORY_READ_ID);
    jdbc.update("DELETE FROM permissions WHERE id = UUID_TO_BIN(?)", DIRECTORY_READ_ID);
  }

  /** Executes every statement of the V11 file, exactly as Flyway ran it. */
  private void applyV11() throws IOException {
    String migration =
        new ClassPathResource(V11_LOCATION).getContentAsString(StandardCharsets.UTF_8);
    String sql =
        migration
            .lines()
            .filter(line -> !line.strip().startsWith("--"))
            .collect(Collectors.joining("\n"));
    List<String> statements =
        Arrays.stream(sql.split(";")).map(String::strip).filter(s -> !s.isEmpty()).toList();
    assertThat(statements).as("V11: insert, footer (a), footer (b)").hasSize(3);
    statements.forEach(jdbc::execute);
  }

  private UUID insertRole(String name) {
    UUID roleId = UUID.randomUUID();
    jdbc.update(
        "INSERT INTO roles (id, tenant_id, name, description, is_system_role) "
            + "VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), ?, ?, FALSE)",
        roleId.toString(),
        tenantId.toString(),
        name,
        "US-019 V11 fixture");
    return roleId;
  }

  private UUID seedHolder(UUID roleId, String tag) {
    String email = "v11-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        userRepository.saveAndFlush(
            new User(
                uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
    jdbc.update(
        "INSERT INTO user_roles (id, user_id, role_id, tenant_id, assigned_by) "
            + "VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), UUID_TO_BIN(?), UUID_TO_BIN(?), "
            + "UUID_TO_BIN(?))",
        uuidGenerator.newId().toString(),
        user.getId().toString(),
        roleId.toString(),
        tenantId.toString(),
        user.getId().toString());
    return user.getId();
  }

  private Set<String> permissionIds(UUID roleId) {
    return Set.copyOf(
        jdbc.queryForList(
            "SELECT BIN_TO_UUID(permission_id) FROM role_permissions "
                + "WHERE role_id = UUID_TO_BIN(?)",
            String.class,
            roleId.toString()));
  }

  private boolean holdsDirectoryRead(UUID roleId) {
    return permissionIds(roleId).contains(DIRECTORY_READ_ID);
  }

  private List<String> zeroAdminWarningsNamingTenant() {
    Logger logger = (Logger) LoggerFactory.getLogger(RbacZeroActiveAdminsHealthIndicator.class);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    try {
      new RbacZeroActiveAdminsHealthIndicator(userRoleRepository).health();
    } finally {
      logger.detachAppender(appender);
      appender.stop();
    }
    return appender.list.stream()
        .filter(event -> event.getLevel() == Level.WARN)
        .map(ILoggingEvent::getFormattedMessage)
        .filter(message -> message.contains(tenantId.toString()))
        .toList();
  }
}
