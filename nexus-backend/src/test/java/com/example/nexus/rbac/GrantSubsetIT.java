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
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.ByteBuffer;
import java.util.Arrays;
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
 * hold every permission it carries (A2). US-018 T-002 adds A4: a caller may assign a role to
 * themselves only if they are an administrator (one role carrying the whole catalogue). US-018
 * T-003 adds A3 on {@code POST /api/v1/roles/{roleId}/permissions}: a caller may attach a
 * permission only if they hold it. A3 denials write no {@code auth_events} row; they are observable
 * as a WARN and as {@code nexus.rbac.permission_denied{permission=role:write,
 * reason=GRANT_EXCEEDS_CALLER}}. 07-security-review.md M-1 adds revoke-subset on {@code DELETE
 * /api/v1/users/{userId}/roles/{roleId}}: a caller may revoke a role only when they hold every
 * permission it carries.
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

  // ── US-018 T-002: A4 self-assignment (03-design.md §2.1, §4.4) ──────────────────────

  /**
   * TS-3: a non-administrator self-assigns a role they could otherwise grant. The target carries
   * only {@code audit:read}, which the caller holds and which the legacy gate does not classify,
   * so neither the legacy gate nor A2 can be the one denying: the reason is A4's own.
   */
  @Test
  void should_return403SelfAssignmentAndOneDenialRow_when_nonAdministratorSelfAssigns() {
    UUID tenantId = uuidGenerator.newId();
    User caller =
        seedUserWithPermissions(
            tenantId, "ts3-caller", USER_ROLE_ASSIGN_PERMISSION_ID, AUDIT_READ_PERMISSION_ID);
    Role role = seedRoleWithPermissions(tenantId, "TS3-AUDITOR", AUDIT_READ_PERMISSION_ID);

    ResponseEntity<Map> resp = postAssign(mintToken(caller), caller.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody())
        .containsEntry("code", "RBAC_001")
        .containsEntry("requiredPermission", "user:role:assign");
    List<Map<String, Object>> rows = denialRows(caller.getId());
    assertThat(rows).as("exactly one ROLE_ASSIGNMENT_DENIED row per request").hasSize(1);
    assertThat(rows.get(0))
        .containsEntry("reason", "SELF_ASSIGNMENT")
        .containsEntry("operation", "assign")
        .containsEntry("missing_count", null);
    assertThat(activeAssignmentCount(caller.getId(), role.getId())).isZero();
  }

  /**
   * TS-4: the RES-1(b) pre-positioning sequence is blocked at its self-assign step. A
   * non-administrator tries to self-assign a benign role (denied), then an administrator makes
   * that role dangerous. The caller never became a holder, so the later attach widens nothing for
   * them. The second-account variant of this sequence is RES-26 and is not covered by A4.
   */
  @Test
  void should_blockRes1bAtSelfAssignStep_so_laterAttachEscalatesNothing() {
    UUID tenantId = uuidGenerator.newId();
    User caller =
        seedUserWithPermissions(
            tenantId, "ts4-caller", USER_ROLE_ASSIGN_PERMISSION_ID, AUDIT_READ_PERMISSION_ID);
    Role benignRole = seedRoleWithPermissions(tenantId, "TS4-BENIGN", AUDIT_READ_PERMISSION_ID);

    ResponseEntity<Map> resp = postAssign(mintToken(caller), caller.getId(), benignRole.getId());
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(denialRows(caller.getId()))
        .singleElement()
        .satisfies(row -> assertThat(row).containsEntry("reason", "SELF_ASSIGNMENT"));

    // The later administrator attach (its own gates are T-003's subject, so seeded directly).
    rolePermissionRepository.save(new RolePermission(benignRole.getId(), ROLE_WRITE_PERMISSION_ID));

    assertThat(activeAssignmentCount(caller.getId(), benignRole.getId())).isZero();
  }

  /**
   * US-017 RES-13 regression: a caller holding the three dangerous permissions (but not the whole
   * catalogue) passes the legacy gate for {@code TENANT_ADMIN}; A4 is the only control denying the
   * self-assignment.
   */
  @Test
  void should_return403SelfAssignment_when_callerWithDangerousPermissionsSelfAssignsTenantAdmin() {
    UUID tenantId = uuidGenerator.newId();
    User caller =
        seedUserWithPermissions(
            tenantId,
            "a4-priv",
            permissionIdByName("user:write"),
            permissionIdByName("role:write"),
            permissionIdByName("tenant:write"),
            USER_ROLE_ASSIGN_PERMISSION_ID);
    Role tenantAdmin =
        roleRepository.save(new Role(uuidGenerator.newId(), tenantId, "TENANT_ADMIN", null, false));

    ResponseEntity<Map> resp = postAssign(mintToken(caller), caller.getId(), tenantAdmin.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody())
        .containsEntry("code", "RBAC_001")
        .containsEntry("requiredPermission", "user:role:assign");
    assertThat(denialRows(caller.getId()))
        .singleElement()
        .satisfies(row -> assertThat(row).containsEntry("reason", "SELF_ASSIGNMENT"));
    assertThat(activeAssignmentCount(caller.getId(), tenantAdmin.getId())).isZero();
  }

  /**
   * An administrator (one role carrying the whole catalogue) may self-assign. The target carries
   * {@code role:write}, so this also exercises a legacy-gate pass via all three dangerous
   * permissions.
   */
  @Test
  void should_return201_when_administratorSelfAssigns() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithPermissions(tenantId, "a4-admin", catalogueIds());
    Role role = seedRoleWithPermissions(tenantId, "A4-ROLE-WRITER", ROLE_WRITE_PERMISSION_ID);

    ResponseEntity<Map> resp = postAssign(mintToken(caller), caller.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(denialRows(caller.getId())).isEmpty();
    assertThat(activeAssignmentCount(caller.getId(), role.getId())).isEqualTo(1);
  }

  /** §2.1: the whole catalogue held only across two partial roles is not an administrator. */
  @Test
  void should_return403SelfAssignment_when_callerHoldsCatalogueOnlyAcrossTwoRoles() {
    UUID tenantId = uuidGenerator.newId();
    UUID[] catalogue = catalogueIds();
    User caller = seedUser(tenantId, "a4-union");
    int half = catalogue.length / 2;
    grantViaNewRole(tenantId, caller, Arrays.copyOfRange(catalogue, 0, half));
    grantViaNewRole(
        tenantId, caller, Arrays.copyOfRange(catalogue, half, catalogue.length));
    Role role = seedRoleWithPermissions(tenantId, "A4-UNION-AUDITOR", AUDIT_READ_PERMISSION_ID);

    ResponseEntity<Map> resp = postAssign(mintToken(caller), caller.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(denialRows(caller.getId()))
        .singleElement()
        .satisfies(row -> assertThat(row).containsEntry("reason", "SELF_ASSIGNMENT"));
    assertThat(activeAssignmentCount(caller.getId(), role.getId())).isZero();
  }

  // ── US-018 T-003: A3 attach requires the caller to hold the permission ───────────────

  /**
   * TS-2: a {@code role:write} holder attaches {@code audit:read}, which they do not hold, to a
   * custom role. {@code audit:read} is not a legacy "dangerous" permission, so AC11 does not fire
   * and the denial observed is A3's own.
   */
  @Test
  void should_return403AndNoAuditRow_when_callerAttachesPermissionTheyDoNotHold() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithPermissions(tenantId, "ts2-caller", ROLE_WRITE_PERMISSION_ID);
    Role role = seedRoleWithPermissions(tenantId, "TS2-TARGET");
    double before = permissionDeniedCount("role:write", "GRANT_EXCEEDS_CALLER");

    ResponseEntity<Map> resp =
        postAttach(mintToken(caller), role.getId(), AUDIT_READ_PERMISSION_ID);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody())
        .containsEntry("code", "RBAC_001")
        .containsEntry("requiredPermission", "role:write");
    assertThat(permissionDeniedCount("role:write", "GRANT_EXCEEDS_CALLER") - before)
        .as("nexus.rbac.permission_denied{role:write,GRANT_EXCEEDS_CALLER} must increment by 1")
        .isEqualTo(1.0);
    assertThat(rolePermissionCount(role.getId(), AUDIT_READ_PERMISSION_ID)).isZero();
    assertThat(authEventCount(tenantId))
        .as("an A3 denial writes no auth_events row, matching the shipped attach gate")
        .isZero();
  }

  @Test
  void should_return201_when_callerHoldsPermissionBeingAttached() {
    UUID tenantId = uuidGenerator.newId();
    User caller =
        seedUserWithPermissions(
            tenantId, "a3-pos-caller", ROLE_WRITE_PERMISSION_ID, AUDIT_READ_PERMISSION_ID);
    Role role = seedRoleWithPermissions(tenantId, "A3-POS-TARGET");

    ResponseEntity<Map> resp =
        postAttach(mintToken(caller), role.getId(), AUDIT_READ_PERMISSION_ID);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(rolePermissionCount(role.getId(), AUDIT_READ_PERMISSION_ID)).isEqualTo(1);
  }

  /** A3 runs before the duplicate check, so the 409 is no attachment-state oracle. */
  @Test
  void should_return403Not409_when_permissionAlreadyAttachedAndCallerDoesNotHoldIt() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithPermissions(tenantId, "a3-dup-caller", ROLE_WRITE_PERMISSION_ID);
    Role role = seedRoleWithPermissions(tenantId, "A3-DUP-TARGET", AUDIT_READ_PERMISSION_ID);

    ResponseEntity<Map> resp =
        postAttach(mintToken(caller), role.getId(), AUDIT_READ_PERMISSION_ID);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody())
        .containsEntry("code", "RBAC_001")
        .containsEntry("requiredPermission", "role:write");
  }

  // ── US-018 07-security-review.md M-1: revoke-subset on DELETE /users/{userId}/roles/{roleId} ──

  /**
   * A delegated {@code user:role:assign} holder may not revoke a role carrying a permission they do
   * not hold. {@code audit:read} is not legacy-"dangerous", so the legacy gate passes and the denial
   * observed is revoke-subset's own: 403 {@code RBAC_001}, one {@code ROLE_ASSIGNMENT_DENIED} row
   * with {@code GRANT_EXCEEDS_CALLER} and {@code operation=revoke}, and the assignment untouched.
   */
  @Test
  void should_return403GrantExceedsCallerAndKeepAssignment_when_revokeTargetExceedsCallerHoldings() {
    UUID tenantId = uuidGenerator.newId();
    User caller =
        seedUserWithPermissions(tenantId, "rs-neg-caller", USER_ROLE_ASSIGN_PERMISSION_ID);
    User target = seedUser(tenantId, "rs-neg-target");
    Role role = seedRoleWithPermissions(tenantId, "RS-NEG-AUDITOR", AUDIT_READ_PERMISSION_ID);
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), target.getId(), role.getId(), tenantId, caller.getId()));
    double before = permissionDeniedCount("user:role:assign", "GRANT_EXCEEDS_CALLER");

    ResponseEntity<Map> resp = deleteAssignment(mintToken(caller), target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody())
        .containsEntry("code", "RBAC_001")
        .containsEntry("requiredPermission", "user:role:assign");
    List<Map<String, Object>> rows = denialRows(target.getId());
    assertThat(rows).as("exactly one ROLE_ASSIGNMENT_DENIED row per request").hasSize(1);
    assertThat(rows.get(0))
        .containsEntry("reason", "GRANT_EXCEEDS_CALLER")
        .containsEntry("operation", "revoke")
        .containsEntry("missing_count", "1");
    assertThat(permissionDeniedCount("user:role:assign", "GRANT_EXCEEDS_CALLER") - before)
        .as("the central handler increments nexus.rbac.permission_denied exactly once")
        .isEqualTo(1.0);
    assertThat(activeAssignmentCount(target.getId(), role.getId()))
        .as("a denied revoke must leave the assignment active")
        .isEqualTo(1);
  }

  @Test
  void should_return204AndRevoke_when_revokeTargetWithinCallerHoldings() {
    UUID tenantId = uuidGenerator.newId();
    User caller =
        seedUserWithPermissions(
            tenantId, "rs-pos-caller", USER_ROLE_ASSIGN_PERMISSION_ID, AUDIT_READ_PERMISSION_ID);
    User target = seedUser(tenantId, "rs-pos-target");
    Role role = seedRoleWithPermissions(tenantId, "RS-POS-AUDITOR", AUDIT_READ_PERMISSION_ID);
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), target.getId(), role.getId(), tenantId, caller.getId()));

    ResponseEntity<Map> resp = deleteAssignment(mintToken(caller), target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    assertThat(denialRows(target.getId())).isEmpty();
    assertThat(activeAssignmentCount(target.getId(), role.getId())).isZero();
  }

  // ── Fixtures ─────────────────────────────────────────────────────────

  /** Every permission id in the catalogue, read live so the fixture follows future migrations. */
  private UUID[] catalogueIds() {
    return jdbc.query("SELECT id FROM permissions", (rs, i) -> fromBytes(rs.getBytes(1)))
        .toArray(UUID[]::new);
  }

  private void grantViaNewRole(UUID tenantId, User user, UUID... permissionIds) {
    Role role = seedRoleWithPermissions(tenantId, "GS-PARTIAL", permissionIds);
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), user.getId(), role.getId(), tenantId, user.getId()));
  }

  private UUID permissionIdByName(String name) {
    return jdbc.queryForObject(
        "SELECT id FROM permissions WHERE name = ?", (rs, i) -> fromBytes(rs.getBytes(1)), name);
  }

  private static UUID fromBytes(byte[] bytes) {
    ByteBuffer buf = ByteBuffer.wrap(bytes);
    return new UUID(buf.getLong(), buf.getLong());
  }

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

  private ResponseEntity<Map> deleteAssignment(String token, UUID pathUserId, UUID roleId) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/users/" + pathUserId + "/roles/" + roleId,
        HttpMethod.DELETE,
        new HttpEntity<>(headers),
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

  /** Modelled on {@code RolePermissionSecurityIT}'s helper: callers assert before/after deltas. */
  private double permissionDeniedCount(String permission, String reason) {
    Counter counter =
        meterRegistry
            .find("nexus.rbac.permission_denied")
            .tag("permission", permission)
            .tag("reason", reason)
            .counter();
    return counter == null ? 0.0 : counter.count();
  }

  private int rolePermissionCount(UUID roleId, UUID permissionId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM role_permissions WHERE role_id = ? AND permission_id = ?",
            Integer.class,
            toBytes(roleId),
            toBytes(permissionId));
    return count == null ? 0 : count;
  }

  private int authEventCount(UUID tenantId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM auth_events WHERE tenant_id = ?",
            Integer.class,
            toBytes(tenantId));
    return count == null ? 0 : count;
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
