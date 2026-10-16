package com.example.nexus.rbac.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.RolePermissionId;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * US-015 T-010 (Test Scenarios 5, 6, 9, 10; 03b-threat-model.md RC-5b; 03-design.md §8.6): the
 * end-to-end HTTP proof of AC7's system-role immutability, AC8-mirrored cross-tenant isolation,
 * and (until US-018 M3) AC11's dangerous-permission admin gate, now A3 and role-subset — real
 * embedded server, real production filter chain,
 * real minted RS256 JWTs, structurally modelled on {@code RoleAssignmentSecurityIT} (denial-reason
 * assertions via {@link MeterRegistry} before/after deltas, since {@code reason} is never on the
 * response body) with the second-tenant fixture shape from {@code CrossTenantPermissionIT}.
 *
 * <p>{@code RoleManagementAdminGateIT} covers the attach and detach rules at the service layer;
 * this file stays at the HTTP boundary, proving the 403/409 status codes and check ordering an
 * actual client observes.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class RolePermissionSecurityIT {

  // Seeded literals — V5__rbac_schema.sql header comment.
  private static final UUID BOOTSTRAP_TENANT_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final UUID SEEDED_TENANT_ADMIN_ROLE_ID =
      UUID.fromString("019f6839-1810-7000-8000-00000000000a");
  private static final UUID SEEDED_MEMBER_ROLE_ID =
      UUID.fromString("019f6839-1811-7000-8000-00000000000b");
  private static final UUID USER_READ_PERMISSION_ID =
      UUID.fromString("019f6839-1802-7000-8000-000000000003");
  private static final UUID ROLE_READ_PERMISSION_ID =
      UUID.fromString("019f6839-1804-7000-8000-000000000005");
  private static final UUID ROLE_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1805-7000-8000-000000000006");
  private static final UUID USER_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1803-7000-8000-000000000004");
  private static final UUID TENANT_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1801-7000-8000-000000000002");

  private static byte[] toBytes(UUID uuid) {
    java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }

  @Value("${local.server.port}")
  private int port;

  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JwtPort jwtPort;
  @Autowired private MeterRegistry meterRegistry;
  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private org.springframework.jdbc.core.JdbcTemplate jdbc;

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

  // ═══════════════════════════════════════════════════════════════════
  // Scenario 5: modify TENANT_ADMIN's permissions -> 409 RBAC_003
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_return409WithRbac003_when_attachingPermissionToSeededTenantAdmin() {
    User caller = seedUserWithRoleWritePermission(BOOTSTRAP_TENANT_ID, "s5-attach-caller");
    String token = mintToken(caller);

    ResponseEntity<Map> resp =
        postAttach(token, SEEDED_TENANT_ADMIN_ROLE_ID, USER_READ_PERMISSION_ID.toString());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_003");
  }

  @Test
  void should_return409WithRbac003_when_detachingPermissionFromSeededTenantAdmin() {
    User caller = seedUserWithRoleWritePermission(BOOTSTRAP_TENANT_ID, "s5-detach-caller");
    String token = mintToken(caller);

    ResponseEntity<Map> resp =
        deleteDetach(token, SEEDED_TENANT_ADMIN_ROLE_ID, USER_READ_PERMISSION_ID);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_003");
  }

  // ═══════════════════════════════════════════════════════════════════
  // RC-5b: MEMBER named explicitly -- the sole gate against tenant-wide amplification
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_return409WithRbac003_when_attachingRoleWriteToSeededMember() {
    User caller = seedUserWithRoleWritePermission(BOOTSTRAP_TENANT_ID, "rc5b-attach-caller");
    String token = mintToken(caller);

    ResponseEntity<Map> resp =
        postAttach(token, SEEDED_MEMBER_ROLE_ID, ROLE_WRITE_PERMISSION_ID.toString());

    assertThat(resp.getStatusCode())
        .as("attaching role:write to MEMBER must 409 -- AC7 is the SOLE gate here, since AC7"
            + " runs before AC11 and MEMBER is a system role (RC-5b)")
        .isEqualTo(HttpStatus.CONFLICT);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_003");
  }

  @Test
  void should_return409WithRbac003_when_detachingUserReadFromSeededMember() {
    User caller = seedUserWithRoleWritePermission(BOOTSTRAP_TENANT_ID, "rc5b-detach-caller");
    String token = mintToken(caller);

    ResponseEntity<Map> resp = deleteDetach(token, SEEDED_MEMBER_ROLE_ID, USER_READ_PERMISSION_ID);

    assertThat(resp.getStatusCode())
        .as("detaching user:read from MEMBER must 409, never a 404 or a silent 204 -- it would"
            + " strip read access from every self-registered member of the tenant")
        .isEqualTo(HttpStatus.CONFLICT);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_003");
  }

  // ═══════════════════════════════════════════════════════════════════
  // Scenario 6: cross-tenant role read/write -> 404 (US-018 B1)
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_return404WithRoleNotFound_when_listingPermissionsForRoleInDifferentTenant() {
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    User caller = seedUserWithRoleReadPermission(tenantA, "s6-get-caller");
    Role roleInTenantB = seedRole(tenantB, "s6-get-target");
    String token = mintToken(caller);

    ResponseEntity<Map> resp = getPermissions(token, roleInTenantB.getId());

    assertThat(resp.getStatusCode())
        .as("a cross-tenant GET must be the genuine-not-found 404, never 200 with any data array")
        .isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(resp.getBody()).containsEntry("code", "ROLE_NOT_FOUND");
  }

  @Test
  void should_return404WithRoleNotFound_when_attachingPermissionToRoleInDifferentTenant() {
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    User caller = seedUserWithRoleWritePermission(tenantA, "s6-post-caller");
    Role roleInTenantB = seedRole(tenantB, "s6-post-target");
    String token = mintToken(caller);

    ResponseEntity<Map> resp =
        postAttach(token, roleInTenantB.getId(), USER_READ_PERMISSION_ID.toString());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(resp.getBody()).containsEntry("code", "ROLE_NOT_FOUND");
  }

  @Test
  void should_return404WithRoleNotFound_when_detachingPermissionFromRoleInDifferentTenant() {
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    User caller = seedUserWithRoleWritePermission(tenantA, "s6-delete-caller");
    Role roleInTenantB = seedRole(tenantB, "s6-delete-target");
    String token = mintToken(caller);

    ResponseEntity<Map> resp = deleteDetach(token, roleInTenantB.getId(), USER_READ_PERMISSION_ID);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(resp.getBody()).containsEntry("code", "ROLE_NOT_FOUND");
  }

  @Test
  void should_return404_when_listingPermissionsForUnknownRole() {
    User caller = seedUserWithRoleReadPermission(uuidGenerator.newId(), "s6-404-caller");
    String token = mintToken(caller);

    ResponseEntity<Map> resp = getPermissions(token, uuidGenerator.newId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(resp.getBody()).containsEntry("code", "ROLE_NOT_FOUND");
  }

  // ═══════════════════════════════════════════════════════════════════
  // Scenario 9 (US-018 M3, T-017, rows 11 and A3): attach is bounded by what the caller HOLDS, for
  // every permission alike. Formerly "role:write holder, no active TENANT_ADMIN -> 403
  // NOT_TENANT_ADMIN" (AC11, a name-based gate on role:write / user:write / tenant:write): that
  // gate is retired. The 403 outcome for a permission the caller does not hold is unchanged and the
  // reason is GRANT_EXCEEDS_CALLER; attaching role:write itself is now allowed to a caller who
  // holds it, which is the intended loosening of ADR-0021 (recorded there).
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_return403WithGrantExceedsCaller_when_roleWriteHolderAttachesUserWriteToCustomRole() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithRoleWritePermission(tenantId, "s9-user-write-caller");
    Role targetRole = seedRole(tenantId, "s9-user-write-target");
    String token = mintToken(caller);
    double before = permissionDeniedCount("role:write", "GRANT_EXCEEDS_CALLER");

    ResponseEntity<Map> resp =
        postAttach(token, targetRole.getId(), USER_WRITE_PERMISSION_ID.toString());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("role:write", "GRANT_EXCEEDS_CALLER", before);
  }

  @Test
  void should_return403WithGrantExceedsCaller_when_roleWriteHolderAttachesTenantWriteToCustomRole() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithRoleWritePermission(tenantId, "s9-tenant-write-caller");
    Role targetRole = seedRole(tenantId, "s9-tenant-write-target");
    String token = mintToken(caller);
    double before = permissionDeniedCount("role:write", "GRANT_EXCEEDS_CALLER");

    ResponseEntity<Map> resp =
        postAttach(token, targetRole.getId(), TENANT_WRITE_PERMISSION_ID.toString());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("role:write", "GRANT_EXCEEDS_CALLER", before);
  }

  /**
   * Row 11's intended loosening, over HTTP: attaching {@code role:write} itself, by a caller who
   * holds it and is not an administrator. (Formerly the same request was 403 NOT_TENANT_ADMIN.)
   * Every freshly generated tenant here has no {@code TENANT_ADMIN} role at all, which the former
   * "no seeded TENANT_ADMIN role" fail-closed case made its own test; it is no longer a branch.
   */
  @Test
  void should_return201_when_roleWriteHolderAttachesRoleWriteToCustomRole() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithRoleWritePermission(tenantId, "s9-role-write-caller");
    Role targetRole = seedRole(tenantId, "s9-role-write-target");
    String token = mintToken(caller);

    ResponseEntity<Map> resp =
        postAttach(token, targetRole.getId(), ROLE_WRITE_PERMISSION_ID.toString());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(
            rolePermissionRepository.existsById(
                new RolePermissionId(targetRole.getId(), ROLE_WRITE_PERMISSION_ID)))
        .isTrue();
  }

  // ═══════════════════════════════════════════════════════════════════
  // Scenario 10: an administrator attaches role:write to a custom role and grants it to a
  // non-administrator (via US-012's RoleAssignmentService); the non-administrator's own attach of a
  // permission they do not hold still 403s
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_return403OnTheAttachAttempt_when_nonAdminHolderOfRoleWriteViaGrantedRoleAttemptsToAttachWhatTheyDoNotHold() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedNamedRole(tenantId, "TENANT_ADMIN", "s10-admin-role");
    // The administrator holds the whole catalogue: role:write to reach the endpoint, user:role:assign
    // for the service-level assign() below (L-1) and every permission it attaches or grants (A2, A3).
    grantWholeCatalogue(adminRole.getId());
    User admin = seedUser(tenantId, "s10-admin");
    seedActiveAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());
    String adminToken = mintToken(admin);

    Role powerfulCustomRole = seedRole(tenantId, "s10-powerful-custom");
    ResponseEntity<Map> attachResp =
        postAttach(adminToken, powerfulCustomRole.getId(), ROLE_WRITE_PERMISSION_ID.toString());
    assertThat(attachResp.getStatusCode())
        .as("setup: the administrator's own attach must succeed")
        .isEqualTo(HttpStatus.CREATED);

    // Grant the now-powerful custom role to a non-administrator user, VIA US-012's real
    // RoleAssignmentService (not a raw fixture row) -- genuinely exercising the cross-story
    // integration the scenario names.
    User nonAdmin = seedUser(tenantId, "s10-non-admin");
    roleAssignmentService.assign(
        new RoleChangeActor(admin.getId(), tenantId), nonAdmin.getId(), powerfulCustomRole.getId(),
        RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "RolePermissionSecurityIT"));

    // The non-administrator now holds role:write (via the custom role) but not user:write. Their
    // own attempt to attach user:write must 403: they could not have granted it.
    Role anotherTargetRole = seedRole(tenantId, "s10-another-target");
    String nonAdminToken = mintToken(nonAdmin);
    double before = permissionDeniedCount("role:write", "GRANT_EXCEEDS_CALLER");

    ResponseEntity<Map> resp =
        postAttach(nonAdminToken, anotherTargetRole.getId(), USER_WRITE_PERMISSION_ID.toString());

    assertThat(resp.getStatusCode())
        .as("a role:write holder must still fail A3 for a permission they do not hold")
        .isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("role:write", "GRANT_EXCEEDS_CALLER", before);
  }

  // ═══════════════════════════════════════════════════════════════════
  // 07-security-review.md L-3, re-cast by US-018 T-017 (row 12): D13's name-based detach gate is
  // replaced by role-subset. These cases prove the rule at the HTTP boundary: the caller must hold
  // every permission of the role. (Formerly "role:write-only caller, no active TENANT_ADMIN ->
  // 403 NOT_TENANT_ADMIN" on a dangerous permission.)
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_return403AndLeaveRowIntact_when_callerLacksAPermissionOfTheRoleBeingDetachedFrom() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithRoleWritePermission(tenantId, "l3-dang-caller");
    Role targetRole = seedRole(tenantId, "l3-dang-target");
    grantPermission(targetRole.getId(), ROLE_WRITE_PERMISSION_ID);
    grantPermission(targetRole.getId(), USER_WRITE_PERMISSION_ID);
    String token = mintToken(caller);
    double before = permissionDeniedCount("role:write", "GRANT_EXCEEDS_CALLER");

    ResponseEntity<Map> resp = deleteDetach(token, targetRole.getId(), ROLE_WRITE_PERMISSION_ID);

    assertThat(resp.getStatusCode())
        .as("a caller who does not hold user:write must be denied on a role that carries it")
        .isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("role:write", "GRANT_EXCEEDS_CALLER", before);
    assertThat(
            rolePermissionRepository.existsById(
                new RolePermissionId(targetRole.getId(), ROLE_WRITE_PERMISSION_ID)))
        .as("the denied detach must not have removed the role_permissions row")
        .isTrue();
  }

  /**
   * T-I14: a caller outside the role-subset who targets a permission that was never attached must
   * still 403 (role-subset runs before the delete's affected-rows check), never a 404 that would
   * let them distinguish "attached" from "never attached".
   */
  @Test
  void should_return403NotFound_when_callerOutsideTheRoleSubsetDetachesAPermissionNeverAttached() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithRoleWritePermission(tenantId, "l3-never-caller");
    Role targetRole = seedRole(tenantId, "l3-never-target");
    grantPermission(targetRole.getId(), USER_WRITE_PERMISSION_ID);
    String token = mintToken(caller);
    double before = permissionDeniedCount("role:write", "GRANT_EXCEEDS_CALLER");

    ResponseEntity<Map> resp = deleteDetach(token, targetRole.getId(), ROLE_WRITE_PERMISSION_ID);

    assertThat(resp.getStatusCode())
        .as("must 403, not 404 -- the caller must not be able to use the response code to"
            + " discover whether a permission is attached")
        .isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("role:write", "GRANT_EXCEEDS_CALLER", before);
  }

  @Test
  void should_return204_when_callerHoldingEveryPermissionOfTheRoleDetachesOne() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithRoleWritePermission(tenantId, "l3-ord-caller");
    // The caller also holds role:read, the one permission the target role carries.
    Role callerExtraRole = seedRole(tenantId, "l3-ord-caller-extra");
    grantPermission(callerExtraRole.getId(), ROLE_READ_PERMISSION_ID);
    seedActiveAssignment(tenantId, callerExtraRole.getId(), caller.getId(), caller.getId());
    Role targetRole = seedRole(tenantId, "l3-ord-target");
    grantPermission(targetRole.getId(), ROLE_READ_PERMISSION_ID);
    String token = mintToken(caller);

    ResponseEntity<Map> resp = deleteDetach(token, targetRole.getId(), ROLE_READ_PERMISSION_ID);

    assertThat(resp.getStatusCode())
        .as("role-subset: a caller who holds every permission of the role may detach from it"
            + " without being an administrator")
        .isEqualTo(HttpStatus.NO_CONTENT);
    assertThat(
            rolePermissionRepository.existsById(
                new RolePermissionId(targetRole.getId(), ROLE_READ_PERMISSION_ID)))
        .as("the row must actually be gone, not merely reported as gone")
        .isFalse();
  }

  // ── Shared seeding helpers ───────────────────────────────────────────

  private User seedUser(UUID tenantId, String tag) {
    String email = "rps-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }

  private Role seedRole(UUID tenantId, String tag) {
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "RPS-" + tag + "-" + UUID.randomUUID(), null,
            false));
  }

  /** Overload for a literal role name (e.g. {@code "TENANT_ADMIN"}) AC11/AC8 match on. */
  private Role seedNamedRole(UUID tenantId, String literalName, String tag) {
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, literalName, tag, false));
  }

  private void grantPermission(UUID roleId, UUID permissionId) {
    rolePermissionRepository.save(new RolePermission(roleId, permissionId));
  }

  /** Makes {@code roleId} admin-defining (ADR-0021 D3): attaches every catalogue permission. */
  private void grantWholeCatalogue(UUID roleId) {
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions",
        toBytes(roleId));
  }

  private UserRole seedActiveAssignment(UUID tenantId, UUID roleId, UUID assigneeId, UUID assignedById) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), assigneeId, roleId, tenantId, assignedById));
  }

  private User seedUserWithRoleWritePermission(UUID tenantId, String tag) {
    User user = seedUser(tenantId, tag);
    Role role = seedRole(tenantId, tag);
    grantPermission(role.getId(), ROLE_WRITE_PERMISSION_ID);
    seedActiveAssignment(tenantId, role.getId(), user.getId(), user.getId());
    return user;
  }

  private User seedUserWithRoleReadPermission(UUID tenantId, String tag) {
    User user = seedUser(tenantId, tag);
    Role role = seedRole(tenantId, tag);
    grantPermission(role.getId(), ROLE_READ_PERMISSION_ID);
    seedActiveAssignment(tenantId, role.getId(), user.getId(), user.getId());
    return user;
  }

  private String mintToken(User user) {
    return jwtPort.issue(user).token();
  }

  // ── HTTP helpers ─────────────────────────────────────────────────────

  private String baseUrl(String path) {
    return "http://localhost:" + port + path;
  }

  private ResponseEntity<Map> postAttach(String token, UUID roleId, String permissionId) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    headers.setContentType(MediaType.APPLICATION_JSON);
    return restTemplate.exchange(
        baseUrl("/api/v1/roles/" + roleId + "/permissions"),
        HttpMethod.POST,
        new HttpEntity<>(Map.of("permissionId", permissionId), headers),
        Map.class);
  }

  private ResponseEntity<Map> deleteDetach(String token, UUID roleId, UUID permissionId) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    return restTemplate.exchange(
        baseUrl("/api/v1/roles/" + roleId + "/permissions/" + permissionId),
        HttpMethod.DELETE,
        new HttpEntity<>(headers),
        Map.class);
  }

  private ResponseEntity<Map> getPermissions(String token, UUID roleId) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    return restTemplate.exchange(
        baseUrl("/api/v1/roles/" + roleId + "/permissions"),
        HttpMethod.GET,
        new HttpEntity<>(headers),
        Map.class);
  }

  // ── Metric assertion helpers (mirrors RoleAssignmentSecurityIT) ────────

  private double permissionDeniedCount(String permission, String reason) {
    Counter counter =
        meterRegistry
            .find("nexus.rbac.permission_denied")
            .tag("permission", permission)
            .tag("reason", reason)
            .counter();
    return counter == null ? 0.0 : counter.count();
  }

  private void assertDenialReasonIncrementedByOne(String permission, String reason, double before) {
    double after = permissionDeniedCount(permission, reason);
    assertThat(after - before)
        .as(
            "nexus.rbac.permission_denied{permission=%s,reason=%s} must increment by exactly 1",
            permission, reason)
        .isEqualTo(1.0);
  }
}
