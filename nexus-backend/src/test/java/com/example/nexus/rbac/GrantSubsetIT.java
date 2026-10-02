package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
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
 * US-018 T-001 (ADR-0021 D1, D2; 03-design.md §4.3, §4.11): grant-subset on {@code POST
 * /api/v1/users/{userId}/roles}, end to end through the real filter chain, real RS256 JWTs and
 * Testcontainers MySQL. A caller holding {@code user:role:assign} may assign a role only when they
 * hold every permission it carries (A2).
 *
 * <p><b>M2 precedence note.</b> Until M3 retires it, the legacy US-016/017 gate runs before A2, so
 * a non-administrator assigning a role that carries a legacy "dangerous" permission ({@code
 * role:write}, {@code user:write}, {@code tenant:write}) is denied there, with {@code
 * NOT_TENANT_ADMIN}. The A2-specific cases below therefore use {@code audit:read}, which the
 * legacy gate does not classify, so the denial they observe is A2's own.
 *
 * <p>Fixtures use a fresh tenant per test and {@code is_system_role=false} (see {@code
 * RoleAssignmentIT}'s shared-schema caveat).
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class GrantSubsetIT {

  // Seeded literals -- V5__rbac_schema.sql and V6__rbac_user_role_assign_permission.sql headers.
  private static final UUID ROLE_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1805-7000-8000-000000000006");
  private static final UUID AUDIT_READ_PERMISSION_ID =
      UUID.fromString("019f6839-1806-7000-8000-000000000007");
  private static final UUID USER_ROLE_ASSIGN_PERMISSION_ID =
      UUID.fromString("019f6839-1807-7000-8000-000000000008");

  @Value("${local.server.port}")
  private int port;

  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JwtPort jwtPort;
  @Autowired private JdbcTemplate jdbc;

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

  /** TS-1: the caller holds user:role:assign but not role:write, and the target carries it. */
  @Test
  void should_return403AndOneDenialRow_when_callerLacksRoleWriteCarriedByTarget() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithPermissions(tenantId, "ts1-caller", USER_ROLE_ASSIGN_PERMISSION_ID);
    User target = seedUser(tenantId, "ts1-target");
    Role role = seedRoleWithPermissions(tenantId, "TS1-ROLE-WRITER", ROLE_WRITE_PERMISSION_ID);

    ResponseEntity<Map> resp = postAssign(mintToken(caller), target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody())
        .containsEntry("code", "RBAC_001")
        .containsEntry("requiredPermission", "user:role:assign");
    List<Map<String, Object>> rows = denialRows(target.getId());
    assertThat(rows).as("exactly one ROLE_ASSIGNMENT_DENIED row per request").hasSize(1);
    // M2: the legacy gate classifies role:write and fires first; M3 retires it, and A2 then
    // reports GRANT_EXCEEDS_CALLER for this same request.
    assertThat(rows.get(0)).containsEntry("reason", "NOT_TENANT_ADMIN");
    assertThat(activeAssignmentCount(target.getId(), role.getId())).isZero();
  }

  @Test
  void should_return403GrantExceedsCallerWithMissingCountOnly_when_callerLacksNonDangerousPermission() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithPermissions(tenantId, "a2-caller", USER_ROLE_ASSIGN_PERMISSION_ID);
    User target = seedUser(tenantId, "a2-target");
    Role role = seedRoleWithPermissions(tenantId, "A2-AUDITOR", AUDIT_READ_PERMISSION_ID);

    ResponseEntity<Map> resp = postAssign(mintToken(caller), target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("requiredPermission", "user:role:assign");
    List<Map<String, Object>> rows = denialRows(target.getId());
    assertThat(rows).hasSize(1);
    assertThat(rows.get(0))
        .containsEntry("reason", "GRANT_EXCEEDS_CALLER")
        .containsEntry("operation", "assign")
        .containsEntry("missing_count", "1");
    assertThat((String) rows.get(0).get("metadata"))
        .as("the denial row carries the count only, never the missing permission's id or name")
        .doesNotContain(AUDIT_READ_PERMISSION_ID.toString())
        .doesNotContain("audit:read");
    assertThat(activeAssignmentCount(target.getId(), role.getId())).isZero();
  }

  @Test
  void should_return201_when_callerHoldsEveryPermissionOfTargetRole() {
    UUID tenantId = uuidGenerator.newId();
    User caller =
        seedUserWithPermissions(
            tenantId, "a2-pos-caller", USER_ROLE_ASSIGN_PERMISSION_ID, AUDIT_READ_PERMISSION_ID);
    User target = seedUser(tenantId, "a2-pos-target");
    Role role = seedRoleWithPermissions(tenantId, "A2-POS-AUDITOR", AUDIT_READ_PERMISSION_ID);

    ResponseEntity<Map> resp = postAssign(mintToken(caller), target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(activeAssignmentCount(target.getId(), role.getId())).isEqualTo(1);
  }

  /** EC7: an empty role grants nothing, so a caller holding only the endpoint permission passes. */
  @Test
  void should_return201_when_targetRoleEmpty() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithPermissions(tenantId, "ec7-caller", USER_ROLE_ASSIGN_PERMISSION_ID);
    User target = seedUser(tenantId, "ec7-target");
    Role role = seedRoleWithPermissions(tenantId, "EC7-EMPTY");

    ResponseEntity<Map> resp = postAssign(mintToken(caller), target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(denialRows(target.getId())).isEmpty();
  }

  /**
   * T-S1 on M13: a {@code user_roles} row whose {@code tenant_id} is the caller's tenant but whose
   * role belongs to another tenant (possible until the V8 composite FK) must not widen the caller's
   * holdings, even though the foreign role carries exactly the permission the target needs.
   */
  @Test
  void should_ignoreForeignTenantRole_when_userRoleRowPointsCrossTenant() {
    UUID tenantId = uuidGenerator.newId();
    UUID foreignTenantId = uuidGenerator.newId();
    User caller = seedUserWithPermissions(tenantId, "ts1-xt-caller", USER_ROLE_ASSIGN_PERMISSION_ID);
    Role foreignRole =
        seedRoleWithPermissions(foreignTenantId, "XT-FOREIGN-AUDITOR", AUDIT_READ_PERMISSION_ID);
    userRoleRepository.save(
        new UserRole(
            uuidGenerator.newId(), caller.getId(), foreignRole.getId(), tenantId, caller.getId()));
    User target = seedUser(tenantId, "ts1-xt-target");
    Role role = seedRoleWithPermissions(tenantId, "XT-LOCAL-AUDITOR", AUDIT_READ_PERMISSION_ID);

    ResponseEntity<Map> resp = postAssign(mintToken(caller), target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(denialRows(target.getId()))
        .singleElement()
        .satisfies(row -> assertThat(row).containsEntry("reason", "GRANT_EXCEEDS_CALLER"));
    assertThat(activeAssignmentCount(target.getId(), role.getId())).isZero();
  }

  // ── Fixtures ─────────────────────────────────────────────────────────

  private User seedUser(UUID tenantId, String tag) {
    String email = "gs-" + tag + "-" + UUID.randomUUID() + "@example.com";
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

  /** Seeds a user holding the given permissions through one freshly created role. */
  private User seedUserWithPermissions(UUID tenantId, String tag, UUID... permissionIds) {
    User user = seedUser(tenantId, tag);
    Role role = seedRoleWithPermissions(tenantId, "GS-CALLER", permissionIds);
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), user.getId(), role.getId(), tenantId, user.getId()));
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

  private List<Map<String, Object>> denialRows(UUID targetUserId) {
    return jdbc.queryForList(
        "SELECT JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.reason')) AS reason, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.operation')) AS operation, "
            + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.missingCount')) AS missing_count, "
            + "metadata "
            + "FROM auth_events WHERE user_id = ? AND event_type = 'ROLE_ASSIGNMENT_DENIED'",
        toBytes(targetUserId));
  }

  private int activeAssignmentCount(UUID userId, UUID roleId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ? "
                + "AND revoked_at IS NULL",
            Integer.class,
            toBytes(userId),
            toBytes(roleId));
    return count == null ? 0 : count;
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
