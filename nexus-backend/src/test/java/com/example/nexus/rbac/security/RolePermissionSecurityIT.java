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
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermission;
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
 * and AC11's dangerous-permission admin gate — real embedded server, real production filter chain,
 * real minted RS256 JWTs, structurally modelled on {@code RoleAssignmentSecurityIT} (denial-reason
 * assertions via {@link MeterRegistry} before/after deltas, since {@code reason} is never on the
 * response body) with the second-tenant fixture shape from {@code CrossTenantPermissionIT}.
 *
 * <p>{@code RoleManagementAdminGateIT} covers AC11's DB-locking guarantee itself (service layer);
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
  // Scenario 6: cross-tenant role read/write -> 403/404
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_return403WithCrossTenantTarget_when_listingPermissionsForRoleInDifferentTenant() {
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    User caller = seedUserWithRoleReadPermission(tenantA, "s6-get-caller");
    Role roleInTenantB = seedRole(tenantB, "s6-get-target");
    String token = mintToken(caller);

    ResponseEntity<Map> resp = getPermissions(token, roleInTenantB.getId());

    assertThat(resp.getStatusCode())
        .as("a cross-tenant GET must be 403, never 200 with any data array")
        .isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
  }

  @Test
  void should_return403WithCrossTenantTarget_when_attachingPermissionToRoleInDifferentTenant() {
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    User caller = seedUserWithRoleWritePermission(tenantA, "s6-post-caller");
    Role roleInTenantB = seedRole(tenantB, "s6-post-target");
    String token = mintToken(caller);

    ResponseEntity<Map> resp =
        postAttach(token, roleInTenantB.getId(), USER_READ_PERMISSION_ID.toString());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
  }

  @Test
  void should_return403WithCrossTenantTarget_when_detachingPermissionFromRoleInDifferentTenant() {
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    User caller = seedUserWithRoleWritePermission(tenantA, "s6-delete-caller");
    Role roleInTenantB = seedRole(tenantB, "s6-delete-target");
    String token = mintToken(caller);

    ResponseEntity<Map> resp = deleteDetach(token, roleInTenantB.getId(), USER_READ_PERMISSION_ID);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
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
  // Scenario 9: role:write holder, no active TENANT_ADMIN -> 403 NOT_TENANT_ADMIN
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_return403WithNotTenantAdmin_when_nonAdminAttachesRoleWriteToCustomRole() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithRoleWritePermission(tenantId, "s9-role-write-caller");
    Role targetRole = seedRole(tenantId, "s9-role-write-target");
    String token = mintToken(caller);
    double before = permissionDeniedCount("role:write", "NOT_TENANT_ADMIN");

    ResponseEntity<Map> resp =
        postAttach(token, targetRole.getId(), ROLE_WRITE_PERMISSION_ID.toString());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("role:write", "NOT_TENANT_ADMIN", before);
  }

  @Test
  void should_return403WithNotTenantAdmin_when_nonAdminAttachesUserWriteToCustomRole() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithRoleWritePermission(tenantId, "s9-user-write-caller");
    Role targetRole = seedRole(tenantId, "s9-user-write-target");
    String token = mintToken(caller);
    double before = permissionDeniedCount("role:write", "NOT_TENANT_ADMIN");

    ResponseEntity<Map> resp =
        postAttach(token, targetRole.getId(), USER_WRITE_PERMISSION_ID.toString());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("role:write", "NOT_TENANT_ADMIN", before);
  }

  @Test
  void should_return403WithNotTenantAdmin_when_nonAdminAttachesTenantWriteToCustomRole() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithRoleWritePermission(tenantId, "s9-tenant-write-caller");
    Role targetRole = seedRole(tenantId, "s9-tenant-write-target");
    String token = mintToken(caller);
    double before = permissionDeniedCount("role:write", "NOT_TENANT_ADMIN");

    ResponseEntity<Map> resp =
        postAttach(token, targetRole.getId(), TENANT_WRITE_PERMISSION_ID.toString());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("role:write", "NOT_TENANT_ADMIN", before);
  }

  /**
   * Fail-closed branch (03-design.md §8.5 row 7, R-10): the caller's tenant has no seeded
   * TENANT_ADMIN role at ALL -- true of every freshly generated tenant used throughout this class
   * (and the normal state for every Epic-3-created tenant today), made explicit here as its own
   * named case rather than left incidental to the Scenario 9 tests above. Q3 (findRoleIdByName)
   * returns empty, short-circuiting before Q11 ever runs.
   */
  @Test
  void should_return403WithNotTenantAdmin_when_tenantHasNoSeededTenantAdminRoleAtAll() {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUserWithRoleWritePermission(tenantId, "s9-no-admin-role-caller");
    Role targetRole = seedRole(tenantId, "s9-no-admin-role-target");
    String token = mintToken(caller);
    double before = permissionDeniedCount("role:write", "NOT_TENANT_ADMIN");

    ResponseEntity<Map> resp =
        postAttach(token, targetRole.getId(), ROLE_WRITE_PERMISSION_ID.toString());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertDenialReasonIncrementedByOne("role:write", "NOT_TENANT_ADMIN", before);
  }

  // ═══════════════════════════════════════════════════════════════════
  // Scenario 10: admin attaches role:write to custom role, grants it to a non-admin (via
  // US-012's RoleAssignmentService), the non-admin's own attach attempt still 403s
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_return403OnTheAttachAttempt_when_nonAdminHolderOfRoleWriteViaGrantedRoleAttemptsToAttach() {
    UUID tenantId = uuidGenerator.newId();
    Role adminRole = seedNamedRole(tenantId, "TENANT_ADMIN", "s10-admin-role");
    // The admin needs role:write GRANTED (not just an active TENANT_ADMIN assignment) to pass
    // @RequiresPermission("role:write") and reach the endpoint at all -- AC11's admin gate is a
    // SEPARATE, additional check inside the service, not a substitute for holding the permission.
    grantPermission(adminRole.getId(), ROLE_WRITE_PERMISSION_ID);
    User admin = seedUser(tenantId, "s10-admin");
    seedActiveAssignment(tenantId, adminRole.getId(), admin.getId(), admin.getId());
    String adminToken = mintToken(admin);

    Role dangerousCustomRole = seedRole(tenantId, "s10-dangerous-custom");
    ResponseEntity<Map> attachResp =
        postAttach(adminToken, dangerousCustomRole.getId(), ROLE_WRITE_PERMISSION_ID.toString());
    assertThat(attachResp.getStatusCode())
        .as("setup: the admin's own attach must succeed")
        .isEqualTo(HttpStatus.CREATED);

    // Grant the now-dangerous custom role to a non-admin user, VIA US-012's real
    // RoleAssignmentService (not a raw fixture row) -- genuinely exercising the cross-story
    // integration the scenario names.
    User nonAdmin = seedUser(tenantId, "s10-non-admin");
    roleAssignmentService.assign(
        new RoleChangeActor(admin.getId(), tenantId), nonAdmin.getId(), dangerousCustomRole.getId(),
        RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "RolePermissionSecurityIT"));

    // The non-admin now holds role:write (via the dangerous custom role) but is NOT an active
    // TENANT_ADMIN. Their own attempt to attach a dangerous permission must still 403.
    Role anotherTargetRole = seedRole(tenantId, "s10-another-target");
    String nonAdminToken = mintToken(nonAdmin);
    double before = permissionDeniedCount("role:write", "NOT_TENANT_ADMIN");

    ResponseEntity<Map> resp =
        postAttach(nonAdminToken, anotherTargetRole.getId(), USER_WRITE_PERMISSION_ID.toString());

    assertThat(resp.getStatusCode())
        .as("the non-admin holder of role:write must still fail AC11's active-TENANT_ADMIN check")
        .isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("role:write", "NOT_TENANT_ADMIN", before);
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
