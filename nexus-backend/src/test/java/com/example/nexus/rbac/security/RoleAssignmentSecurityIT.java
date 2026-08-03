package com.example.nexus.rbac.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.identity.infrastructure.security.RsaKeyConfig;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import io.jsonwebtoken.Jwts;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Date;
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
 * US-012 T-019 (04-tasks.md; 03b-threat-model.md T-E7, T-E8, T-E9, T-E10, T-E11, T-S4): the
 * story's highest-consequence test class, and the <b>only</b> automated control that exercises
 * {@link com.example.nexus.rbac.interfaces.rest.UserRoleController} end-to-end — real embedded
 * server, real production filter chain, real minted RS256 JWTs — rather than at the service layer
 * ({@code RoleAssignmentIT}, {@code LastAdminLockoutIT}) or via a standalone MockMvc slice
 * ({@code UserRoleControllerTest}).
 *
 * <p><b>Structural template:</b> {@link CrossTenantPermissionIT} — {@code
 * @SpringBootTest(webEnvironment = RANDOM_PORT)}, {@code @ActiveProfiles("test")}, real JWTs
 * minted via {@link JwtPort#issue}, and a {@link RestTemplate} configured to never throw on
 * 4xx/5xx so every assertion below checks the <b>literal</b> status code, never "not 2xx" — the
 * feature flag behind this controller is enabled only under the {@code test} profile (03-design.md
 * §10.1 / T-013's trap #1); a missing {@code @ActiveProfiles("test")} would 404 every request here,
 * which could otherwise be misread as a passing negative-permission test.
 *
 * <p><b>Why {@code reason} is asserted via the {@link MeterRegistry} counter, not the response
 * body:</b> {@code GlobalExceptionHandler#handleInsufficientPermission} puts {@code code} (always
 * {@code RBAC_001}) and {@code requiredPermission} on the RFC 7807 response body, but {@code
 * reason} (e.g. {@code CROSS_TENANT_TARGET}, {@code NOT_TENANT_ADMIN}) is only logged (WARN) and
 * tagged onto the {@code nexus.rbac.permission_denied{permission,reason}} counter — confirmed by
 * reading that handler. Every denial-reason assertion below therefore reads the real, Spring-
 * managed {@link MeterRegistry} bean (the same one the running {@code GlobalExceptionHandler}
 * increments) and compares a <b>before/after delta</b> rather than an absolute count, since this
 * class's {@code @SpringBootTest} context — and therefore this registry — is shared and
 * accumulates across every test method in this class.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class RoleAssignmentSecurityIT {

  // Seeded literals — V5__rbac_schema.sql header comment.
  private static final UUID USER_READ_PERMISSION_ID =
      UUID.fromString("019f6839-1802-7000-8000-000000000003");
  private static final UUID USER_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1803-7000-8000-000000000004");

  @Value("${local.server.port}")
  private int port;

  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JwtPort jwtPort;
  @Autowired private RsaKeyConfig rsaKeyConfig;
  @Autowired private MeterRegistry meterRegistry;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private org.springframework.transaction.PlatformTransactionManager transactionManager;

  private RestTemplate restTemplate;

  @BeforeEach
  void setUp() {
    restTemplate = new RestTemplate();
    // Suppress RestTemplate's default behaviour of throwing on 4xx/5xx so every test below can
    // assert the literal status code directly (mirrors CrossTenantPermissionIT).
    restTemplate.setErrorHandler(
        new DefaultResponseErrorHandler() {
          @Override
          public boolean hasError(ClientHttpResponse response) {
            return false;
          }
        });
  }

  // ═══════════════════════════════════════════════════════════════════
  // T-E8: cross-tenant isolation on ALL THREE verbs
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_return403WithCrossTenantTarget_when_postingRoleAssignmentForUserInDifferentTenant() {
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantA, "post-xt-caller", "WRITER", USER_WRITE_PERMISSION_ID);
    User targetInTenantB = seedUser(tenantB, "post-xt-target");
    UUID someRoleId = uuidGenerator.newId(); // never reached: the tenant check on the user fires first
    String token = mintToken(caller);
    double before = permissionDeniedCount("user:write", "CROSS_TENANT_TARGET");

    ResponseEntity<Map> resp = postAssign(token, targetInTenantB.getId(), someRoleId);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("user:write", "CROSS_TENANT_TARGET", before);
  }

  /**
   * <b>The single most important assertion in this entire test class.</b> A design defect found
   * in threat-model review (T-E8) would have let this endpoint silently return {@code 200
   * {"data": []}} for a cross-tenant probe instead of {@code 403} — destroying the only signal
   * (the WARN log + {@code nexus.rbac.permission_denied{reason="CROSS_TENANT_TARGET"}} counter)
   * that makes cross-tenant probing on {@code GET} detectable. This must be {@code 403}, never
   * {@code 200} with an empty (or any) {@code data} array.
   */
  @Test
  void should_return403WithCrossTenantTarget_notEmptyList_when_gettingRolesForUserInDifferentTenant() {
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantA, "get-xt-caller", "READER", USER_READ_PERMISSION_ID);
    User targetInTenantB = seedUser(tenantB, "get-xt-target");
    String token = mintToken(caller);
    double before = permissionDeniedCount("user:read", "CROSS_TENANT_TARGET");

    ResponseEntity<Map> resp = getRoles(token, targetInTenantB.getId());

    assertThat(resp.getStatusCode())
        .as("cross-tenant GET must be 403 CROSS_TENANT_TARGET -- explicitly NOT 200 with an"
            + " empty (or any) data array (T-E8)")
        .isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getStatusCode()).isNotEqualTo(HttpStatus.OK);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("user:read", "CROSS_TENANT_TARGET", before);
  }

  @Test
  void should_return403WithCrossTenantTarget_when_deletingRoleAssignmentForUserInDifferentTenant() {
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantA, "delete-xt-caller", "WRITER", USER_WRITE_PERMISSION_ID);
    User targetInTenantB = seedUser(tenantB, "delete-xt-target");
    UUID someRoleId = uuidGenerator.newId(); // never reached: the tenant check on the user fires first
    String token = mintToken(caller);
    double before = permissionDeniedCount("user:write", "CROSS_TENANT_TARGET");

    ResponseEntity<Map> resp = deleteRole(token, targetInTenantB.getId(), someRoleId);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("user:write", "CROSS_TENANT_TARGET", before);
  }

  // ── Nonexistent user (distinct from cross-tenant): 404 on all three verbs ──────────────

  @Test
  void should_return404_when_postingRoleAssignmentForNonexistentUser() {
    UUID tenantA = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantA, "post-404-caller", "WRITER", USER_WRITE_PERMISSION_ID);
    UUID nonexistentUserId = uuidGenerator.newId();
    UUID someRoleId = uuidGenerator.newId();
    String token = mintToken(caller);

    ResponseEntity<Map> resp = postAssign(token, nonexistentUserId, someRoleId);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(resp.getBody()).containsEntry("code", "USER_NOT_FOUND");
  }

  @Test
  void should_return404_when_gettingRolesForNonexistentUser() {
    UUID tenantA = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantA, "get-404-caller", "READER", USER_READ_PERMISSION_ID);
    UUID nonexistentUserId = uuidGenerator.newId();
    String token = mintToken(caller);

    ResponseEntity<Map> resp = getRoles(token, nonexistentUserId);

    assertThat(resp.getStatusCode())
        .as("an unknown userId must be 404, distinct from the 403 cross-tenant case above --"
            + " never a 200 with an empty data array")
        .isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(resp.getBody()).containsEntry("code", "USER_NOT_FOUND");
  }

  @Test
  void should_return404_when_deletingRoleAssignmentForNonexistentUser() {
    UUID tenantA = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantA, "delete-404-caller", "WRITER", USER_WRITE_PERMISSION_ID);
    UUID nonexistentUserId = uuidGenerator.newId();
    UUID someRoleId = uuidGenerator.newId();
    String token = mintToken(caller);

    ResponseEntity<Map> resp = deleteRole(token, nonexistentUserId, someRoleId);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(resp.getBody()).containsEntry("code", "USER_NOT_FOUND");
  }

  // ═══════════════════════════════════════════════════════════════════
  // T-E7: AC8 self-escalation (the design's Critical-risk control)
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_return403WithNotTenantAdmin_when_nonAdminHoldingUserWriteAttemptsToGrantTenantAdmin() {
    UUID tenantC = uuidGenerator.newId();
    // Holds user:write via a role NOT named TENANT_ADMIN -- today this is unreachable in
    // production (only TENANT_ADMIN carries user:write pre-US-015), but this test must not
    // depend on that: it seeds the scenario directly, per 04-tasks.md T-019's own instruction.
    User nonAdminWriter =
        seedUserWithRole(tenantC, "self-esc-caller", "USER_WRITER", USER_WRITE_PERMISSION_ID);
    Role tenantAdminRole = seedRole(tenantC, "TENANT_ADMIN", "self-esc");
    User target = seedUser(tenantC, "self-esc-target");
    String token = mintToken(nonAdminWriter);
    double before = permissionDeniedCount("user:write", "NOT_TENANT_ADMIN");

    ResponseEntity<Map> resp = postAssign(token, target.getId(), tenantAdminRole.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("user:write", "NOT_TENANT_ADMIN", before);
  }

  /**
   * <b>The stale-JWT test -- the only test in this story that catches a claim-based (as opposed
   * to live-DB-read) implementation of AC8.</b> Mints a valid JWT for a user who, at mint time,
   * holds an active {@code TENANT_ADMIN} assignment (so the JWT's own {@code permissions[]} claim
   * legitimately includes {@code user:write}, and would -- under a claims-based implementation --
   * still "look" like an admin). The assignment is then revoked directly via the repository,
   * bypassing the API/service entirely, simulating an out-of-band revocation (e.g. an incident
   * responder de-privileging a rogue admin). The SAME still-valid, unexpired JWT is then used to
   * attempt granting {@code TENANT_ADMIN} to a third user. {@link
   * com.example.nexus.rbac.application.RoleAssignmentService#assign} MUST reject this via its
   * live (M5, locking) DB read -- if it instead trusted {@code authentication.getAuthorities()} or
   * any JWT claim, this specific request would incorrectly succeed.
   */
  @Test
  void should_return403WithNotTenantAdmin_when_staleJwtStillClaimsAdminAfterOutOfBandRevocation() {
    UUID tenantD = uuidGenerator.newId();
    Role adminRole = seedRole(tenantD, "TENANT_ADMIN", "stale-jwt");
    grantPermission(adminRole.getId(), USER_WRITE_PERMISSION_ID);
    User admin = seedUser(tenantD, "stale-jwt-admin");
    UserRole assignment = seedActiveAssignment(tenantD, adminRole.getId(), admin.getId(), admin.getId());

    // Minted WHILE admin genuinely holds an active TENANT_ADMIN assignment -- permissions[]
    // legitimately contains user:write at this instant.
    String staleToken = mintToken(admin);

    // Out-of-band revocation: directly via the repository (M6), bypassing the controller/service
    // entirely -- simulates an incident responder or a raw admin action outside this API.
    // revokeById is a bulk @Modifying UPDATE, which Spring Data JPA refuses to run without an
    // active JPA transaction -- this test method itself isn't @Transactional (deliberately: the
    // whole point is an out-of-band revocation outside any request-scoped transaction), so one
    // must be opened manually purely to satisfy that requirement.
    int[] affectedHolder = new int[1];
    new org.springframework.transaction.support.TransactionTemplate(transactionManager)
        .executeWithoutResult(
            status ->
                affectedHolder[0] =
                    userRoleRepository.revokeById(assignment.getId(), java.time.Instant.now()));
    int affected = affectedHolder[0];
    assertThat(affected).as("the out-of-band revoke itself must succeed").isEqualTo(1);

    User target = seedUser(tenantD, "stale-jwt-target");
    double before = permissionDeniedCount("user:write", "NOT_TENANT_ADMIN");

    // Same token, still cryptographically valid and unexpired.
    ResponseEntity<Map> resp = postAssign(staleToken, target.getId(), adminRole.getId());

    assertThat(resp.getStatusCode())
        .as("a JWT minted while the caller was an active TENANT_ADMIN must NOT still be honored"
            + " as admin once that assignment is revoked out-of-band -- AC8's guard must be a"
            + " live DB read, never trust the JWT's own claims (T-E7)")
        .isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("user:write", "NOT_TENANT_ADMIN", before);
  }

  // ═══════════════════════════════════════════════════════════════════
  // T-E11: paired positive/negative permission controls, per endpoint
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_return403_when_callerLacksUserWriteForAssign() {
    UUID tenantE = uuidGenerator.newId();
    User callerWithNoPermissions = seedUser(tenantE, "pair-post-neg-caller");
    User target = seedUser(tenantE, "pair-post-neg-target");
    Role role = seedRole(tenantE, "REGULAR", "pair-post-neg");
    String token = mintToken(callerWithNoPermissions);
    double before = permissionDeniedCount("user:write", "PERMISSION_ABSENT");

    ResponseEntity<Map> resp = postAssign(token, target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertDenialReasonIncrementedByOne("user:write", "PERMISSION_ABSENT", before);
  }

  @Test
  void should_return201_when_callerHasUserWriteForAssign() {
    UUID tenantE = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantE, "pair-post-pos-caller", "WRITER", USER_WRITE_PERMISSION_ID);
    User target = seedUser(tenantE, "pair-post-pos-target");
    Role role = seedRole(tenantE, "REGULAR", "pair-post-pos");
    String token = mintToken(caller);

    ResponseEntity<Map> resp = postAssign(token, target.getId(), role.getId());

    assertThat(resp.getStatusCode())
        .as("the positive half of the pair: the SAME endpoint must actually work when the"
            + " permission is present -- a negative-only test can pass for the wrong reason"
            + " (e.g. a missing bean denying everyone)")
        .isEqualTo(HttpStatus.CREATED);
  }

  @Test
  void should_return403_when_callerLacksUserReadForList() {
    UUID tenantE = uuidGenerator.newId();
    User callerWithNoPermissions = seedUser(tenantE, "pair-get-neg-caller");
    User target = seedUser(tenantE, "pair-get-neg-target");
    String token = mintToken(callerWithNoPermissions);
    double before = permissionDeniedCount("user:read", "PERMISSION_ABSENT");

    ResponseEntity<Map> resp = getRoles(token, target.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertDenialReasonIncrementedByOne("user:read", "PERMISSION_ABSENT", before);
  }

  @Test
  void should_return200_when_callerHasUserReadForList() {
    UUID tenantE = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantE, "pair-get-pos-caller", "READER", USER_READ_PERMISSION_ID);
    User target = seedUser(tenantE, "pair-get-pos-target");
    String token = mintToken(caller);

    ResponseEntity<Map> resp = getRoles(token, target.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(resp.getBody()).containsKey("data");
  }

  @Test
  void should_return403_when_callerLacksUserWriteForRevoke() {
    UUID tenantE = uuidGenerator.newId();
    User callerWithNoPermissions = seedUser(tenantE, "pair-delete-neg-caller");
    User target = seedUser(tenantE, "pair-delete-neg-target");
    Role role = seedRole(tenantE, "REGULAR", "pair-delete-neg");
    String token = mintToken(callerWithNoPermissions);
    double before = permissionDeniedCount("user:write", "PERMISSION_ABSENT");

    ResponseEntity<Map> resp = deleteRole(token, target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertDenialReasonIncrementedByOne("user:write", "PERMISSION_ABSENT", before);
  }

  @Test
  void should_return204_when_callerHasUserWriteForRevoke() {
    UUID tenantE = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantE, "pair-delete-pos-caller", "WRITER", USER_WRITE_PERMISSION_ID);
    User target = seedUser(tenantE, "pair-delete-pos-target");
    Role role = seedRole(tenantE, "REGULAR", "pair-delete-pos");
    seedActiveAssignment(tenantE, role.getId(), target.getId(), caller.getId());
    String token = mintToken(caller);

    ResponseEntity<Map> resp = deleteRole(token, target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
  }

  // ═══════════════════════════════════════════════════════════════════
  // T-E10: provenance -- path userId must never become the actor
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_recordJwtSubjectAsAssignedBy_never_thePathUserId_when_pathUserIdDiffersFromCaller() {
    UUID tenantF = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantF, "provenance-caller", "WRITER", USER_WRITE_PERMISSION_ID);
    User target = seedUser(tenantF, "provenance-target"); // deliberately NOT the caller
    Role role = seedRole(tenantF, "ORDINARY", "provenance");
    String token = mintToken(caller);

    ResponseEntity<Map> resp = postAssign(token, target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    Map<String, Object> row =
        jdbc.queryForMap(
            "SELECT user_id, assigned_by FROM user_roles WHERE user_id = ? AND role_id = ?",
            toBytes(target.getId()),
            toBytes(role.getId()));
    assertThat(toUuid((byte[]) row.get("user_id")))
        .as("user_id must be the path-carried TARGET, never confused with the actor")
        .isEqualTo(target.getId());
    assertThat(toUuid((byte[]) row.get("assigned_by")))
        .as("assigned_by must always be the JWT sub (the caller), regardless of what the path"
            + " says -- never influenced by the path value (T-E10)")
        .isEqualTo(caller.getId());
  }

  // ═══════════════════════════════════════════════════════════════════
  // T-S4: fail-closed principal handling
  // ═══════════════════════════════════════════════════════════════════

  /**
   * A real JWT minted via {@link JwtPort#issue} always carries a valid UUID {@code sub} ({@code
   * user.getId().toString()}), so this scenario cannot be reached through the normal minting
   * path. {@link com.example.nexus.identity.infrastructure.web.JwtAuthenticationFilter} performs
   * no UUID validation on {@code sub} at all -- confirmed by reading it -- it simply forwards
   * whatever string {@link com.example.nexus.identity.infrastructure.security.JwtRs256Service
   * #verify} extracts as the JWT {@code sub} claim into {@code Authentication}'s principal. This
   * test therefore builds a real, validly-signed RS256 JWT directly with the same {@link
   * RsaKeyConfig} key pair the running application uses (autowired from the real Spring context),
   * with every other required claim present and valid, but a non-UUID {@code sub}. Sent through
   * the real filter chain, this reaches {@code UserRoleController#resolveActor}'s principal
   * parsing with a malformed principal -- the fail-closed path this test exists to prove.
   */
  @Test
  void should_return403WithMalformedAuthentication_notInternalServerError_when_principalIsNotAUuid() {
    UUID tenantG = uuidGenerator.newId();
    String malformedToken =
        forgeJwtWithSubject("not-a-uuid-subject", tenantG, List.of("user:read", "user:write"));
    double before = permissionDeniedCount("user:read", "MALFORMED_AUTHENTICATION");

    ResponseEntity<Map> resp = getRoles(malformedToken, uuidGenerator.newId());

    assertThat(resp.getStatusCode())
        .as("an unparseable (non-UUID) principal must fail closed to 403, never surface as an"
            + " unhandled 500 (T-S4)")
        .isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("user:read", "MALFORMED_AUTHENTICATION", before);
  }

  // ═══════════════════════════════════════════════════════════════════
  // D15/R-12: malformed path/body UUIDs -> 400, not 500 (quick end-to-end regression;
  // exhaustive coverage already lives in UserRoleControllerTest, T-011)
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_return400_when_pathUserIdIsMalformedUuid() {
    UUID tenantH = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantH, "malformed-path-user-caller", "READER", USER_READ_PERMISSION_ID);
    String token = mintToken(caller);

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    ResponseEntity<Map> resp =
        restTemplate.exchange(
            baseUrl("/api/v1/users/not-a-uuid/roles"),
            HttpMethod.GET,
            new HttpEntity<>(headers),
            Map.class);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(fieldOfFirstDetail(resp)).isEqualTo("userId");
  }

  @Test
  void should_return400_when_pathRoleIdIsMalformedUuidOnDelete() {
    UUID tenantH = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantH, "malformed-path-role-caller", "WRITER", USER_WRITE_PERMISSION_ID);
    User target = seedUser(tenantH, "malformed-path-role-target");
    String token = mintToken(caller);

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    ResponseEntity<Map> resp =
        restTemplate.exchange(
            baseUrl("/api/v1/users/" + target.getId() + "/roles/not-a-uuid"),
            HttpMethod.DELETE,
            new HttpEntity<>(headers),
            Map.class);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(fieldOfFirstDetail(resp)).isEqualTo("roleId");
  }

  @Test
  void should_return400_when_bodyRoleIdIsMalformedUuidOnPost() {
    UUID tenantH = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantH, "malformed-body-role-caller", "WRITER", USER_WRITE_PERMISSION_ID);
    User target = seedUser(tenantH, "malformed-body-role-target");
    String token = mintToken(caller);

    ResponseEntity<Map> resp = postAssignRaw(token, target.getId(), "not-a-uuid");

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(fieldOfFirstDetail(resp)).isEqualTo("roleId");
  }

  // ═══════════════════════════════════════════════════════════════════
  // T-I5/O-10: assignedBy visibility on GET is gated on the CALLER's own live
  // TENANT_ADMIN status -- gap identified in Phase 8 test-validate: this decision (03-design.md
  // §4.2/O-10, 04-tasks.md's own "one decision made during breakdown, not left implicit") was
  // previously proven only at the unit level (RoleAssignmentServiceTest, mocked ports) and via a
  // MockMvc slice with a MOCKED service (UserRoleControllerTest) -- neither exercises the real
  // `callerHoldsActiveTenantAdmin` DB read end-to-end over HTTP. This class is the only one with a
  // real embedded server + real JWTs, so it is the right place to close that gap.
  // ═══════════════════════════════════════════════════════════════════

  @Test
  @SuppressWarnings("unchecked")
  void should_includeAssignedBy_when_callerIsActiveTenantAdmin() {
    UUID tenantI = uuidGenerator.newId();
    User admin = seedUserWithRole(tenantI, "assignedby-admin-caller", "TENANT_ADMIN", USER_READ_PERMISSION_ID);
    User target = seedUser(tenantI, "assignedby-admin-target");
    Role role = seedRole(tenantI, "ORDINARY", "assignedby-admin");
    User grantor = seedUser(tenantI, "assignedby-admin-grantor");
    seedActiveAssignment(tenantI, role.getId(), target.getId(), grantor.getId());
    String token = mintToken(admin);

    ResponseEntity<Map> resp = getRoles(token, target.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
    List<Map<String, Object>> data = (List<Map<String, Object>>) resp.getBody().get("data");
    assertThat(data)
        .as("caller holding an active TENANT_ADMIN assignment must see assignedBy (O-10)")
        .anySatisfy(row -> assertThat(row).containsEntry("assignedBy", grantor.getId().toString()));
  }

  @Test
  @SuppressWarnings("unchecked")
  void should_omitAssignedBy_when_callerIsNotActiveTenantAdmin() {
    UUID tenantJ = uuidGenerator.newId();
    User nonAdmin =
        seedUserWithRole(tenantJ, "assignedby-nonadmin-caller", "ORDINARY_READER", USER_READ_PERMISSION_ID);
    User target = seedUser(tenantJ, "assignedby-nonadmin-target");
    Role role = seedRole(tenantJ, "ORDINARY", "assignedby-nonadmin");
    User grantor = seedUser(tenantJ, "assignedby-nonadmin-grantor");
    seedActiveAssignment(tenantJ, role.getId(), target.getId(), grantor.getId());
    String token = mintToken(nonAdmin);

    ResponseEntity<Map> resp = getRoles(token, target.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
    List<Map<String, Object>> data = (List<Map<String, Object>>) resp.getBody().get("data");
    // RoleAssignmentResponse.assignedBy is documented as "omitted/null" (no @JsonInclude(NON_NULL)
    // on the DTO) -- Jackson serializes it as a present "assignedBy":null key, not an absent one.
    // row.get(...) returns null either way, matching UserRoleControllerTest's own
    // jsonPath(...).doesNotExist() assertion, which likewise accepts null-or-absent.
    assertThat(data)
        .as("a caller with no active TENANT_ADMIN assignment must never see a real assignedBy"
            + " value (T-I5: admin-roster enumeration)")
        .allSatisfy(row -> assertThat(row.get("assignedBy")).isNull());
  }

  // ── Shared seeding helpers ───────────────────────────────────────────

  private User seedUser(UUID tenantId, String tag) {
    String email = "sec-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    return userRepository.save(user);
  }

  private Role seedRole(UUID tenantId, String name, String tag) {
    // is_system_role=false: keeps RbacSchemaMigrationIT's scoped seed-role count stable
    // regardless of test execution order (see RoleAssignmentIT's seedRole Javadoc).
    return roleRepository.save(new Role(uuidGenerator.newId(), tenantId, name, tag, false));
  }

  private void grantPermission(UUID roleId, UUID permissionId) {
    rolePermissionRepository.save(new RolePermission(roleId, permissionId));
  }

  private UserRole seedActiveAssignment(UUID tenantId, UUID roleId, UUID assigneeId, UUID assignedById) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), assigneeId, roleId, tenantId, assignedById));
  }

  /** Seeds a user holding exactly one permission, via a freshly created single-permission role. */
  private User seedUserWithRole(UUID tenantId, String tag, String roleName, UUID permissionId) {
    User user = seedUser(tenantId, tag);
    Role role = seedRole(tenantId, roleName, tag);
    grantPermission(role.getId(), permissionId);
    seedActiveAssignment(tenantId, role.getId(), user.getId(), user.getId());
    return user;
  }

  private String mintToken(User user) {
    return jwtPort.issue(user).token();
  }

  /**
   * Builds a validly-signed RS256 JWT with an arbitrary (potentially non-UUID) {@code sub},
   * using the SAME key pair the running application's {@link RsaKeyConfig} bean holds -- see this
   * class's Javadoc on {@link #should_return403WithMalformedAuthentication_notInternalServerError_when_principalIsNotAUuid()}.
   */
  private String forgeJwtWithSubject(String subject, UUID tenantId, List<String> permissions) {
    Instant now = Instant.now();
    return Jwts.builder()
        .header()
        .add("kid", rsaKeyConfig.getKid())
        .add("typ", "JWT")
        .and()
        .subject(subject)
        .claim("tenant_id", tenantId.toString())
        .claim("email_verified", true)
        .claim("roles", List.of())
        .claim("permissions", permissions)
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plusSeconds(900)))
        .id(UUID.randomUUID().toString())
        .claim("token_version", 0)
        .claim("schema_version", JwtClaims.CURRENT_VERSION)
        .signWith(rsaKeyConfig.getKeyPair().getPrivate(), Jwts.SIG.RS256)
        .compact();
  }

  // ── HTTP helpers ─────────────────────────────────────────────────────

  private String baseUrl(String path) {
    return "http://localhost:" + port + path;
  }

  private ResponseEntity<Map> postAssign(String token, UUID pathUserId, UUID roleId) {
    return postAssignRaw(token, pathUserId, roleId.toString());
  }

  /**
   * Same as {@link #postAssign} but accepts the raw {@code roleId} body value as a string, so
   * malformed-UUID-body tests can pass a deliberately invalid value.
   */
  private ResponseEntity<Map> postAssignRaw(String token, UUID pathUserId, String roleId) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    headers.setContentType(MediaType.APPLICATION_JSON);
    return restTemplate.exchange(
        baseUrl("/api/v1/users/" + pathUserId + "/roles"),
        HttpMethod.POST,
        new HttpEntity<>(Map.of("roleId", roleId), headers),
        Map.class);
  }

  private ResponseEntity<Map> getRoles(String token, UUID pathUserId) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    return restTemplate.exchange(
        baseUrl("/api/v1/users/" + pathUserId + "/roles"),
        HttpMethod.GET,
        new HttpEntity<>(headers),
        Map.class);
  }

  private ResponseEntity<Map> deleteRole(String token, UUID pathUserId, UUID roleId) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    return restTemplate.exchange(
        baseUrl("/api/v1/users/" + pathUserId + "/roles/" + roleId),
        HttpMethod.DELETE,
        new HttpEntity<>(headers),
        Map.class);
  }

  @SuppressWarnings("unchecked")
  private static String fieldOfFirstDetail(ResponseEntity<Map> resp) {
    List<Map<String, Object>> details = (List<Map<String, Object>>) resp.getBody().get("details");
    return String.valueOf(details.get(0).get("field"));
  }

  // ── Metric assertion helpers ─────────────────────────────────────────

  /**
   * Reads the CURRENT value of {@code nexus.rbac.permission_denied{permission,reason}} -- the
   * counter {@code GlobalExceptionHandler#handleInsufficientPermission} increments on every
   * {@link com.example.nexus.common.security.InsufficientPermissionException}. Callers capture
   * this BEFORE an action and compare against the value after, since this class's {@code
   * MeterRegistry} is a real Spring-managed bean shared (and cumulative) across every test method
   * in this class -- an absolute-value assertion would be order-dependent and flaky.
   */
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

  // ── UUID <-> BINARY(16) helpers (mirrors RoleAssignmentIT/LastAdminLockoutIT) ────────

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }

  private static UUID toUuid(byte[] bytes) {
    ByteBuffer buf = ByteBuffer.wrap(bytes);
    return new UUID(buf.getLong(), buf.getLong());
  }
}
