package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * US-019 T-007 (03-design.md §4.8; RC-60.3, RC-66.1, RC-66.2): with the rule on (the default),
 * only an administrator can grant {@code user:directory:read}, through attach or through assign of
 * a role carrying it. End to end through the real filter chain, real RS256 JWTs and Testcontainers
 * MySQL. A non-administrator holder gets 403 {@code RBAC_001} with {@code NOT_TENANT_ADMIN}; a
 * non-holder gets A2/A3's {@code GRANT_EXCEEDS_CALLER} instead, so the denial reveals no named
 * permission. Attach writes no audit row (Decision 7); assign writes one {@code
 * ROLE_ASSIGNMENT_DENIED} row. The rule-off behaviour and the startup WARN are unit-tested
 * ({@code PiiPermissionGrantRuleTest}, the two service tests).
 *
 * <p>Fixtures use a fresh tenant per test and {@code is_system_role=false}.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class PiiPermissionGrantIT {

  private static final UUID ROLE_WRITE = RbacSeededPermissionIds.ROLE_WRITE;
  private static final UUID USER_ROLE_ASSIGN = RbacSeededPermissionIds.USER_ROLE_ASSIGN;
  private static final UUID USER_DIRECTORY_READ = RbacSeededPermissionIds.USER_DIRECTORY_READ;
  private static final String DELEGATED_COUNTER = "nexus.rbac.pii_permission_delegated";

  @Value("${local.server.port}")
  private int port;

  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JwtPort jwtPort;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private MeterRegistry meterRegistry;

  private RestTemplate restTemplate;

  @BeforeEach
  void setUp() {
    restTemplate = new RestTemplate();
    restTemplate.setErrorHandler(
        new DefaultResponseErrorHandler() {
          @Override
          public boolean hasError(ClientHttpResponse response) {
            return false;
          }
        });
  }

  // ── attach ───────────────────────────────────────────────────────────

  @Test
  void should_return403NotTenantAdminWithNoAuditRow_when_nonAdministratorHolderAttachesDirectoryRead() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithPermissions(tenantId, "attach-holder", ROLE_WRITE, USER_DIRECTORY_READ);
    Role role = seedRoleWithPermissions(tenantId, "PII-ATTACH-TARGET");
    double deniedBefore = permissionDeniedCount("role:write", "NOT_TENANT_ADMIN");
    int auditBefore = authEventCount(tenantId);

    ResponseEntity<Map> resp = postAttach(mintToken(caller), role.getId(), USER_DIRECTORY_READ);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody())
        .containsEntry("code", "RBAC_001")
        .containsEntry("requiredPermission", "role:write");
    assertThat(permissionDeniedCount("role:write", "NOT_TENANT_ADMIN") - deniedBefore)
        .isEqualTo(1.0);
    assertThat(rolePermissionCount(role.getId(), USER_DIRECTORY_READ)).isZero();
    assertThat(authEventCount(tenantId)).as("attach denials write no audit row").isEqualTo(auditBefore);
  }

  @Test
  void should_return403GrantExceedsCallerNeverNotTenantAdmin_when_nonHolderAttachesDirectoryRead() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithPermissions(tenantId, "attach-nonholder", ROLE_WRITE);
    Role role = seedRoleWithPermissions(tenantId, "PII-ATTACH-NONHOLDER");
    double exceedsBefore = permissionDeniedCount("role:write", "GRANT_EXCEEDS_CALLER");
    double adminBefore = permissionDeniedCount("role:write", "NOT_TENANT_ADMIN");

    ResponseEntity<Map> resp = postAttach(mintToken(caller), role.getId(), USER_DIRECTORY_READ);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(permissionDeniedCount("role:write", "GRANT_EXCEEDS_CALLER") - exceedsBefore)
        .isEqualTo(1.0);
    assertThat(permissionDeniedCount("role:write", "NOT_TENANT_ADMIN")).isEqualTo(adminBefore);
  }

  @Test
  void should_return201AndEmitNoDelegationSignal_when_administratorAttachesDirectoryRead() {
    UUID tenantId = uuidGenerator.newId();
    User admin = seedAdministrator(tenantId, "attach-admin");
    Role role = seedRoleWithPermissions(tenantId, "PII-ATTACH-ADMIN");
    double delegatedBefore = delegatedCount();

    ResponseEntity<Map> resp = postAttach(mintToken(admin), role.getId(), USER_DIRECTORY_READ);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(rolePermissionCount(role.getId(), USER_DIRECTORY_READ)).isEqualTo(1);
    assertThat(delegatedCount()).isEqualTo(delegatedBefore);
  }

  // ── assign ───────────────────────────────────────────────────────────

  /** The "User Manager" shape: can read the directory, cannot pass it on. */
  @Test
  void should_return403WithOneNotTenantAdminDenialRow_when_nonAdministratorHolderAssignsRoleCarryingDirectoryRead() {
    UUID tenantId = uuidGenerator.newId();
    User caller =
        seedUserWithPermissions(tenantId, "assign-holder", USER_ROLE_ASSIGN, USER_DIRECTORY_READ);
    User target = seedUser(tenantId, "assign-holder-target");
    Role role = seedRoleWithPermissions(tenantId, "PII-READER", USER_DIRECTORY_READ);

    ResponseEntity<Map> resp = postAssign(mintToken(caller), target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody())
        .containsEntry("code", "RBAC_001")
        .containsEntry("requiredPermission", "user:role:assign");
    List<Map<String, Object>> rows = denialRows(target.getId());
    assertThat(rows).as("exactly one ROLE_ASSIGNMENT_DENIED row per request").hasSize(1);
    assertThat(rows.get(0))
        .containsEntry("reason", "NOT_TENANT_ADMIN")
        .containsEntry("operation", "assign");
    assertThat(activeAssignmentCount(target.getId(), role.getId())).isZero();
  }

  @Test
  void should_return403GrantExceedsCallerNeverNotTenantAdmin_when_nonHolderAssignsRoleCarryingDirectoryRead() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithPermissions(tenantId, "assign-nonholder", USER_ROLE_ASSIGN);
    User target = seedUser(tenantId, "assign-nonholder-target");
    Role role = seedRoleWithPermissions(tenantId, "PII-READER-NONHOLDER", USER_DIRECTORY_READ);

    ResponseEntity<Map> resp = postAssign(mintToken(caller), target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    List<Map<String, Object>> rows = denialRows(target.getId());
    assertThat(rows).hasSize(1);
    assertThat(rows.get(0)).containsEntry("reason", "GRANT_EXCEEDS_CALLER");
  }

  @Test
  void should_return201AndEmitNoDelegationSignal_when_administratorAssignsRoleCarryingDirectoryRead() {
    UUID tenantId = uuidGenerator.newId();
    User admin = seedAdministrator(tenantId, "assign-admin");
    User target = seedUser(tenantId, "assign-admin-target");
    Role role = seedRoleWithPermissions(tenantId, "PII-READER-ADMIN", USER_DIRECTORY_READ);
    double delegatedBefore = delegatedCount();

    ResponseEntity<Map> resp = postAssign(mintToken(admin), target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(activeAssignmentCount(target.getId(), role.getId())).isEqualTo(1);
    assertThat(denialRows(target.getId())).isEmpty();
    assertThat(delegatedCount()).isEqualTo(delegatedBefore);
  }

  // ── Fixtures ─────────────────────────────────────────────────────────

  private User seedUser(UUID tenantId, String tag) {
    String email = "pii-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRepository.save(
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  private Role seedRoleWithPermissions(UUID tenantId, String name, UUID... permissionIds) {
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, name + "-" + UUID.randomUUID(), null, false));
    for (UUID permissionId : permissionIds) {
      rolePermissionRepository.save(new RolePermission(role.getId(), permissionId));
    }
    return role;
  }

  /** A user holding the given permissions through one freshly created, non-admin-defining role. */
  private User seedUserWithPermissions(UUID tenantId, String tag, UUID... permissionIds) {
    User user = seedUser(tenantId, tag);
    Role role = seedRoleWithPermissions(tenantId, "PII-CALLER", permissionIds);
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), user.getId(), role.getId(), tenantId, user.getId()));
    return user;
  }

  /** A user holding one role carrying the whole live catalogue (ADR-0021 D3). */
  private User seedAdministrator(UUID tenantId, String tag) {
    User user = seedUser(tenantId, tag);
    UUID roleId =
        RbacTestCatalogue.createAdministratorRole(jdbc, tenantId, "PII-ADMIN-" + UUID.randomUUID());
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), user.getId(), roleId, tenantId, user.getId()));
    RbacTestCatalogue.assertAdministrator(jdbc, user.getId(), tenantId);
    return user;
  }

  private String mintToken(User user) {
    return jwtPort.issue(user).token();
  }

  private ResponseEntity<Map> postAssign(String token, UUID pathUserId, UUID roleId) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    headers.setContentType(MediaType.APPLICATION_JSON);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/users/" + pathUserId + "/roles",
        HttpMethod.POST,
        new HttpEntity<>(Map.of("roleId", roleId.toString()), headers),
        Map.class);
  }

  private ResponseEntity<Map> postAttach(String token, UUID roleId, UUID permissionId) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    headers.setContentType(MediaType.APPLICATION_JSON);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/roles/" + roleId + "/permissions",
        HttpMethod.POST,
        new HttpEntity<>(Map.of("permissionId", permissionId.toString()), headers),
        Map.class);
  }

  private double permissionDeniedCount(String permission, String reason) {
    Counter counter =
        meterRegistry
            .find("nexus.rbac.permission_denied")
            .tag("permission", permission)
            .tag("reason", reason)
            .counter();
    return counter == null ? 0.0 : counter.count();
  }

  private double delegatedCount() {
    Counter counter = meterRegistry.find(DELEGATED_COUNTER).counter();
    return counter == null ? 0.0 : counter.count();
  }

  private int rolePermissionCount(UUID roleId, UUID permissionId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM role_permissions "
                + "WHERE role_id = UUID_TO_BIN(?) AND permission_id = UUID_TO_BIN(?)",
            Integer.class,
            roleId.toString(),
            permissionId.toString());
    return count == null ? 0 : count;
  }

  private int authEventCount(UUID tenantId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM auth_events WHERE tenant_id = UUID_TO_BIN(?)",
            Integer.class,
            tenantId.toString());
    return count == null ? 0 : count;
  }

  private List<Map<String, Object>> denialRows(UUID targetUserId) {
    return jdbc.queryForList(
        "SELECT JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.reason')) AS reason, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.operation')) AS operation "
            + "FROM auth_events WHERE user_id = UUID_TO_BIN(?) "
            + "AND event_type = 'ROLE_ASSIGNMENT_DENIED'",
        targetUserId.toString());
  }

  private int activeAssignmentCount(UUID userId, UUID roleId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = UUID_TO_BIN(?) "
                + "AND role_id = UUID_TO_BIN(?) AND revoked_at IS NULL",
            Integer.class,
            userId.toString(),
            roleId.toString());
    return count == null ? 0 : count;
  }
}
