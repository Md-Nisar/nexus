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
  // US-018 A1 (V6): the endpoint permission for POST and DELETE /users/{id}/roles.
  private static final UUID USER_ROLE_ASSIGN_PERMISSION_ID =
      UUID.fromString("019f6839-1807-7000-8000-000000000008");
  // Dangerous per RbacDangerousPermissions.NAMES -- used by the T-S7 freshness-on-the-privilege-
  // path extension below to construct a role that is privileged WITHOUT being named TENANT_ADMIN.
  private static final UUID ROLE_WRITE_PERMISSION_ID =
      UUID.fromString("019f6839-1805-7000-8000-000000000006");
  // Dangerous per RbacDangerousPermissions.NAMES -- used by T-007(c)/(d) below to construct a
  // caller who qualifies via RbacAdminEquivalence#isFullyAdminEquivalent (ALL three), never named
  // TENANT_ADMIN.
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
  void should_return404WithUserNotFound_when_postingRoleAssignmentForUserInDifferentTenant() {
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantA, "post-xt-caller", "ASSIGNER", USER_ROLE_ASSIGN_PERMISSION_ID);
    User targetInTenantB = seedUser(tenantB, "post-xt-target");
    UUID someRoleId = uuidGenerator.newId(); // never reached: the tenant check on the user fires first
    String token = mintToken(caller);
    double before = permissionDeniedCount("user:role:assign", "CROSS_TENANT_TARGET");

    ResponseEntity<Map> resp = postAssign(token, targetInTenantB.getId(), someRoleId);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(resp.getBody()).containsEntry("code", "USER_NOT_FOUND");
    assertDenialReasonIncrementedByOne("user:role:assign", "CROSS_TENANT_TARGET", before);
  }

  /**
   * <b>The single most important assertion in this entire test class.</b> A design defect found
   * in threat-model review (T-E8) would have let this endpoint silently return {@code 200
   * {"data": []}} for a cross-tenant probe instead of {@code 404} (US-018 B1) — destroying the only signal
   * (the WARN log + {@code nexus.rbac.permission_denied{reason="CROSS_TENANT_TARGET"}} counter)
   * that makes cross-tenant probing on {@code GET} detectable. This must be {@code 404}, never
   * {@code 200} with an empty (or any) {@code data} array.
   */
  @Test
  void should_return404WithUserNotFound_notEmptyList_when_gettingRolesForUserInDifferentTenant() {
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantA, "get-xt-caller", "READER", USER_READ_PERMISSION_ID);
    User targetInTenantB = seedUser(tenantB, "get-xt-target");
    String token = mintToken(caller);
    double before = permissionDeniedCount("user:read", "CROSS_TENANT_TARGET");

    ResponseEntity<Map> resp = getRoles(token, targetInTenantB.getId());

    assertThat(resp.getStatusCode())
        .as("cross-tenant GET must be the genuine-not-found 404 -- explicitly NOT 200 with an"
            + " empty (or any) data array (T-E8)")
        .isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(resp.getStatusCode()).isNotEqualTo(HttpStatus.OK);
    assertThat(resp.getBody()).containsEntry("code", "USER_NOT_FOUND");
    assertDenialReasonIncrementedByOne("user:read", "CROSS_TENANT_TARGET", before);
  }

  @Test
  void should_return404WithUserNotFound_when_deletingRoleAssignmentForUserInDifferentTenant() {
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantA, "delete-xt-caller", "ASSIGNER", USER_ROLE_ASSIGN_PERMISSION_ID);
    User targetInTenantB = seedUser(tenantB, "delete-xt-target");
    UUID someRoleId = uuidGenerator.newId(); // never reached: the tenant check on the user fires first
    String token = mintToken(caller);
    double before = permissionDeniedCount("user:role:assign", "CROSS_TENANT_TARGET");

    ResponseEntity<Map> resp = deleteRole(token, targetInTenantB.getId(), someRoleId);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(resp.getBody()).containsEntry("code", "USER_NOT_FOUND");
    assertDenialReasonIncrementedByOne("user:role:assign", "CROSS_TENANT_TARGET", before);
  }

  // ── Nonexistent user (distinct from cross-tenant): 404 on all three verbs ──────────────

  @Test
  void should_return404_when_postingRoleAssignmentForNonexistentUser() {
    UUID tenantA = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantA, "post-404-caller", "ASSIGNER", USER_ROLE_ASSIGN_PERMISSION_ID);
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
    User caller = seedUserWithRole(tenantA, "delete-404-caller", "ASSIGNER", USER_ROLE_ASSIGN_PERMISSION_ID);
    UUID nonexistentUserId = uuidGenerator.newId();
    UUID someRoleId = uuidGenerator.newId();
    String token = mintToken(caller);

    ResponseEntity<Map> resp = deleteRole(token, nonexistentUserId, someRoleId);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(resp.getBody()).containsEntry("code", "USER_NOT_FOUND");
  }

  // ═══════════════════════════════════════════════════════════════════
  // T-E7: self-escalation (the design's Critical-risk control). US-018 M3 (T-016): the name-or-ANY
  // gate is gone; these cases are A2 / revoke-subset cases against the same threats, and the
  // stale-JWT / out-of-band-revocation proof (T-E7) is KEPT, on the set-lock path.
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Was {@code ..._attemptsToGrantTenantAdmin} with reason NOT_TENANT_ADMIN. The control that now
   * enforces the assertion is A2 (ADR-0021 D2): {@code TENANT_ADMIN} carries the whole catalogue,
   * so a caller holding only {@code user:role:assign} cannot grant it, and the denial is
   * GRANT_EXCEEDS_CALLER. The 403 outcome and its RBAC_001 body are unchanged.
   */
  @Test
  void should_return403WithGrantExceedsCaller_when_nonAdminHoldingUserRoleAssignAttemptsToGrantTenantAdmin() {
    UUID tenantC = uuidGenerator.newId();
    // Holds the endpoint permission (user:role:assign since US-018 A1) via a role NOT named
    // TENANT_ADMIN, seeded directly per 04-tasks.md T-019's own instruction.
    User nonAdminWriter =
        seedUserWithRole(tenantC, "self-esc-caller", "ROLE_ASSIGNER", USER_ROLE_ASSIGN_PERMISSION_ID);
    Role tenantAdminRole = seedRole(tenantC, "TENANT_ADMIN", "self-esc");
    grantWholeCatalogue(tenantAdminRole.getId());
    User target = seedUser(tenantC, "self-esc-target");
    String token = mintToken(nonAdminWriter);
    double before = permissionDeniedCount("user:role:assign", "GRANT_EXCEEDS_CALLER");

    ResponseEntity<Map> resp = postAssign(token, target.getId(), tenantAdminRole.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("user:role:assign", "GRANT_EXCEEDS_CALLER", before);
  }

  /**
   * T-E17 / T-E34 over HTTP: {@code revoke()} of an administrator role by a non-administrator is
   * 403 NOT_TENANT_ADMIN (the administrator requirement of revoke-subset, decided from the set
   * lock's own rows). The target here genuinely holds the active administrator assignment being
   * revoked, so a wrongly-permissive rule would actually strip the tenant's last administrator
   * rather than merely failing an assertion. Fixture change from the former test: {@code
   * TENANT_ADMIN} carries the whole catalogue, as the real one does.
   */
  @Test
  void should_return403WithNotTenantAdmin_when_nonAdminHoldingUserRoleAssignAttemptsToRevokeAnActiveTenantAdmin() {
    UUID tenantF = uuidGenerator.newId();
    User nonAdminWriter =
        seedUserWithRole(tenantF, "revoke-esc-caller", "ROLE_ASSIGNER", USER_ROLE_ASSIGN_PERMISSION_ID);
    Role tenantAdminRole = seedRole(tenantF, "TENANT_ADMIN", "revoke-esc");
    grantWholeCatalogue(tenantAdminRole.getId());
    User admin = seedUser(tenantF, "revoke-esc-target");
    seedActiveAssignment(tenantF, tenantAdminRole.getId(), admin.getId(), admin.getId());
    String token = mintToken(nonAdminWriter);
    double before = permissionDeniedCount("user:role:assign", "NOT_TENANT_ADMIN");

    ResponseEntity<Map> resp = deleteRole(token, admin.getId(), tenantAdminRole.getId());

    assertThat(resp.getStatusCode())
        .as("the administrator requirement must deny this at the controller boundary (403), never"
            + " fall through to a 409 lockout or a silent 204 that would strip the tenant's last"
            + " admin")
        .isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("user:role:assign", "NOT_TENANT_ADMIN", before);
  }

  /**
   * The positive half of the pair above: an actual administrator caller revoking a role that
   * carries {@code role:write} from a DIFFERENT user must succeed -- without this, the 403 test
   * above could pass for the wrong reason (e.g. a rule that denies every revoke unconditionally).
   */
  @Test
  void should_return204_when_activeTenantAdminRevokesARoleWriteRoleFromAnotherUser() {
    UUID tenantG = uuidGenerator.newId();
    Role tenantAdminRole = seedRole(tenantG, "TENANT_ADMIN", "revoke-pos");
    // Revoke-subset: the admin must hold every permission of the role it revokes (role:write
    // below) and the endpoint permission; the whole catalogue covers both.
    grantWholeCatalogue(tenantAdminRole.getId());
    User admin = seedUser(tenantG, "revoke-pos-admin");
    seedActiveAssignment(tenantG, tenantAdminRole.getId(), admin.getId(), admin.getId());
    Role dangerousRole = seedRole(tenantG, "CUSTOM-ROLE-WRITE", "revoke-pos");
    grantPermission(dangerousRole.getId(), ROLE_WRITE_PERMISSION_ID);
    User target = seedUser(tenantG, "revoke-pos-target");
    seedActiveAssignment(tenantG, dangerousRole.getId(), target.getId(), admin.getId());
    String token = mintToken(admin);

    ResponseEntity<Map> resp = deleteRole(token, target.getId(), dangerousRole.getId());

    assertThat(resp.getStatusCode())
        .as("a genuine administrator must still be able to revoke a role from someone else -- the"
            + " revoke-subset rule must not be a de facto ban")
        .isEqualTo(HttpStatus.NO_CONTENT);
  }

  /**
   * <b>The stale-JWT test -- the only test in this story that catches a claim-based (as opposed
   * to live-DB-read) implementation of the assignment rules. KEPT by US-018 M3 and moved onto the
   * set-lock path (the target is {@code TENANT_ADMIN}, which carries the whole catalogue, so
   * assign() classifies it as admin-defining and takes the set lock before it decides).</b> Mints
   * a valid JWT for a user who, at mint time, holds an active administrator assignment (so the
   * JWT's own {@code permissions[]} legitimately includes {@code user:role:assign}, and would,
   * under a claims-based implementation, still "look" like an administrator). The assignment is
   * then revoked directly via the repository, bypassing the API/service entirely, simulating an
   * out-of-band revocation. The SAME still-valid, unexpired JWT is then used to attempt granting
   * {@code TENANT_ADMIN} to a third user. {@link
   * com.example.nexus.rbac.application.RoleAssignmentService#assign} MUST reject this from its
   * live reads -- if it trusted {@code authentication.getAuthorities()} or any JWT claim, this
   * request would incorrectly succeed. The reason is now PERMISSION_ABSENT (the live holdings no
   * longer contain {@code user:role:assign}); the 403 outcome is unchanged.
   */
  @Test
  void should_return403_when_staleJwtStillClaimsAdminAfterOutOfBandRevocation() {
    UUID tenantD = uuidGenerator.newId();
    Role adminRole = seedRole(tenantD, "TENANT_ADMIN", "stale-jwt");
    grantWholeCatalogue(adminRole.getId());
    User admin = seedUser(tenantD, "stale-jwt-admin");
    UserRole assignment = seedActiveAssignment(tenantD, adminRole.getId(), admin.getId(), admin.getId());

    // Minted WHILE admin genuinely holds an active administrator assignment.
    String staleToken = mintToken(admin);

    // Out-of-band revocation: directly via the repository (M6), bypassing the controller/service
    // entirely -- simulates an incident responder or a raw admin action outside this API.
    // revokeById is a bulk @Modifying UPDATE, which Spring Data JPA refuses to run without an
    // active JPA transaction -- this test method itself isn't @Transactional (deliberately: the
    // whole point is an out-of-band revocation outside any request-scoped transaction), so one
    // must be opened manually purely to satisfy that requirement.
    revokeOutOfBand(assignment.getId());

    User target = seedUser(tenantD, "stale-jwt-target");
    double before = permissionDeniedCount("user:role:assign", "PERMISSION_ABSENT");

    // Same token, still cryptographically valid and unexpired.
    ResponseEntity<Map> resp = postAssign(staleToken, target.getId(), adminRole.getId());

    assertThat(resp.getStatusCode())
        .as("a JWT minted while the caller was an administrator must NOT still be honored once"
            + " that assignment is revoked out-of-band -- the rules must be live DB reads, never"
            + " trust the JWT's own claims (T-E7)")
        .isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("user:role:assign", "PERMISSION_ABSENT", before);
    assertThat(activeAssignmentCount(target.getId(), adminRole.getId()))
        .as("the stale token must not have minted an administrator")
        .isZero();
  }

  /**
   * The same proof for a SELF-assignment with a stale token: A4 and the independent check are
   * never reached (the live-holdings check denies first), and the stale caller does not become an
   * administrator again. The caller's administrator role is NOT named TENANT_ADMIN: names do not
   * matter (replaces the former "all three dangerous permissions" caller-qualifying variant).
   */
  @Test
  void should_return403_when_staleJwtOfACustomAdminDefiningRoleHolderSelfAssignsAfterOutOfBandRevocation() {
    UUID tenantD3 = uuidGenerator.newId();
    // Deliberately NOT named TENANT_ADMIN: a custom role carrying the whole catalogue.
    Role customAdminRole = seedRole(tenantD3, "CUSTOM-ADMIN-DEFINING", "stale-jwt-custom");
    grantWholeCatalogue(customAdminRole.getId());
    User caller = seedUser(tenantD3, "stale-jwt-custom-caller");
    UserRole assignment =
        seedActiveAssignment(tenantD3, customAdminRole.getId(), caller.getId(), caller.getId());
    String staleToken = mintToken(caller);

    revokeOutOfBand(assignment.getId());

    Role adminRole = seedRole(tenantD3, "TENANT_ADMIN", "stale-jwt-custom");
    grantWholeCatalogue(adminRole.getId());
    double before = permissionDeniedCount("user:role:assign", "PERMISSION_ABSENT");

    ResponseEntity<Map> resp = postAssign(staleToken, caller.getId(), adminRole.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertDenialReasonIncrementedByOne("user:role:assign", "PERMISSION_ABSENT", before);
    assertThat(activeAssignmentCount(caller.getId(), adminRole.getId())).isZero();
  }

  /** The stale-token proof for revoke(): an ex-administrator cannot strip the real one. */
  @Test
  void should_return403_when_staleJwtOfAnExAdministratorRevokesTheCurrentAdministratorAfterOutOfBandRevocation() {
    UUID tenantD4 = uuidGenerator.newId();
    Role adminRole = seedRole(tenantD4, "TENANT_ADMIN", "stale-jwt-revoke");
    grantWholeCatalogue(adminRole.getId());
    User exAdmin = seedUser(tenantD4, "stale-jwt-revoke-exadmin");
    UserRole exAssignment =
        seedActiveAssignment(tenantD4, adminRole.getId(), exAdmin.getId(), exAdmin.getId());
    User currentAdmin = seedUser(tenantD4, "stale-jwt-revoke-current");
    seedActiveAssignment(tenantD4, adminRole.getId(), currentAdmin.getId(), currentAdmin.getId());
    String staleToken = mintToken(exAdmin);

    revokeOutOfBand(exAssignment.getId());
    double before = permissionDeniedCount("user:role:assign", "NOT_TENANT_ADMIN");

    ResponseEntity<Map> resp = deleteRole(staleToken, currentAdmin.getId(), adminRole.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertDenialReasonIncrementedByOne("user:role:assign", "NOT_TENANT_ADMIN", before);
    assertThat(activeAssignmentCount(currentAdmin.getId(), adminRole.getId()))
        .as("the current administrator must still hold the role")
        .isEqualTo(1);
  }

  // ═══════════════════════════════════════════════════════════════════
  // US-018 T-018 (row 7, row 9): a legitimate administrator self-assignment neither trips the
  // independent check nor registers any retired meter
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Replaces the US-017 T-007(d) acceptance test of the re-derived canary. An administrator whose
   * role is NOT named {@code TENANT_ADMIN} (it carries the whole catalogue) self-assigns {@code
   * TENANT_ADMIN}: this must succeed, count {@code
   * nexus.rbac.admin_role_assigned{selfTarget=true}} once, and leave {@code
   * nexus.rbac.self_assign_admin_disagreement} (the paging series) untouched.
   */
  @Test
  void should_notTripTheIndependentCheck_when_anAdministratorWithACustomRoleSelfAssignsTenantAdmin() {
    UUID tenantK = uuidGenerator.newId();
    Role customAdminRole = seedRole(tenantK, "CANARY-CUSTOM-ADMIN", "canary");
    grantWholeCatalogue(customAdminRole.getId());
    User caller = seedUser(tenantK, "canary-caller");
    seedActiveAssignment(tenantK, customAdminRole.getId(), caller.getId(), caller.getId());
    String token = mintToken(caller);

    Role adminRole = seedRole(tenantK, "TENANT_ADMIN", "canary");
    grantWholeCatalogue(adminRole.getId());
    double assignedBefore = counterValue("nexus.rbac.admin_role_assigned", "selfTarget", "true");
    double disagreementBefore = counterValue("nexus.rbac.self_assign_admin_disagreement", null, null);

    ResponseEntity<Map> resp = postAssign(token, caller.getId(), adminRole.getId());

    assertThat(resp.getStatusCode())
        .as("the caller is an administrator by holding a role that carries the whole catalogue,"
            + " so this self-assignment must succeed")
        .isEqualTo(HttpStatus.CREATED);
    assertThat(counterValue("nexus.rbac.admin_role_assigned", "selfTarget", "true") - assignedBefore)
        .isEqualTo(1.0);
    assertThat(counterValue("nexus.rbac.self_assign_admin_disagreement", null, null))
        .as("the independent per-role check must agree with A4 on a real administrator (RC-28.1)")
        .isEqualTo(disagreementBefore);
  }

  // ═══════════════════════════════════════════════════════════════════
  // T-E11: paired positive/negative permission controls, per endpoint
  // ═══════════════════════════════════════════════════════════════════

  @Test
  void should_return403_when_callerLacksUserRoleAssignForAssign() {
    UUID tenantE = uuidGenerator.newId();
    User callerWithNoPermissions = seedUser(tenantE, "pair-post-neg-caller");
    User target = seedUser(tenantE, "pair-post-neg-target");
    Role role = seedRole(tenantE, "REGULAR", "pair-post-neg");
    String token = mintToken(callerWithNoPermissions);
    double before = permissionDeniedCount("user:role:assign", "PERMISSION_ABSENT");

    ResponseEntity<Map> resp = postAssign(token, target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertDenialReasonIncrementedByOne("user:role:assign", "PERMISSION_ABSENT", before);
  }

  @Test
  void should_return201_when_callerHasUserRoleAssignForAssign() {
    UUID tenantE = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantE, "pair-post-pos-caller", "ASSIGNER", USER_ROLE_ASSIGN_PERMISSION_ID);
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

  /**
   * US-018 FR-A1.b (ADR-0021 D1): {@code user:write} now means "edit user accounts" only. A caller
   * holding it, but not {@code user:role:assign}, is denied at the endpoint boundary.
   */
  @Test
  void should_return403PermissionAbsent_when_callerHoldsOnlyUserWriteForAssign() {
    UUID tenantE = uuidGenerator.newId();
    User caller =
        seedUserWithRole(tenantE, "a1b-post-caller", "USER_WRITER", USER_WRITE_PERMISSION_ID);
    User target = seedUser(tenantE, "a1b-post-target");
    Role role = seedRole(tenantE, "REGULAR", "a1b-post");
    String token = mintToken(caller);
    double before = permissionDeniedCount("user:role:assign", "PERMISSION_ABSENT");

    ResponseEntity<Map> resp = postAssign(token, target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("requiredPermission", "user:role:assign");
    assertDenialReasonIncrementedByOne("user:role:assign", "PERMISSION_ABSENT", before);
  }

  @Test
  void should_return403PermissionAbsent_when_callerHoldsOnlyUserWriteForRevoke() {
    UUID tenantE = uuidGenerator.newId();
    User caller =
        seedUserWithRole(tenantE, "a1b-delete-caller", "USER_WRITER", USER_WRITE_PERMISSION_ID);
    User target = seedUser(tenantE, "a1b-delete-target");
    Role role = seedRole(tenantE, "REGULAR", "a1b-delete");
    seedActiveAssignment(tenantE, role.getId(), target.getId(), caller.getId());
    String token = mintToken(caller);
    double before = permissionDeniedCount("user:role:assign", "PERMISSION_ABSENT");

    ResponseEntity<Map> resp = deleteRole(token, target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertDenialReasonIncrementedByOne("user:role:assign", "PERMISSION_ABSENT", before);
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
  void should_return403_when_callerLacksUserRoleAssignForRevoke() {
    UUID tenantE = uuidGenerator.newId();
    User callerWithNoPermissions = seedUser(tenantE, "pair-delete-neg-caller");
    User target = seedUser(tenantE, "pair-delete-neg-target");
    Role role = seedRole(tenantE, "REGULAR", "pair-delete-neg");
    String token = mintToken(callerWithNoPermissions);
    double before = permissionDeniedCount("user:role:assign", "PERMISSION_ABSENT");

    ResponseEntity<Map> resp = deleteRole(token, target.getId(), role.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertDenialReasonIncrementedByOne("user:role:assign", "PERMISSION_ABSENT", before);
  }

  @Test
  void should_return204_when_callerHasUserRoleAssignForRevoke() {
    UUID tenantE = uuidGenerator.newId();
    User caller = seedUserWithRole(tenantE, "pair-delete-pos-caller", "ASSIGNER", USER_ROLE_ASSIGN_PERMISSION_ID);
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
    User caller = seedUserWithRole(tenantF, "provenance-caller", "ASSIGNER", USER_ROLE_ASSIGN_PERMISSION_ID);
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
   * path. This test therefore builds a real, validly-signed RS256 JWT directly with the same
   * {@link RsaKeyConfig} key pair the running application uses (autowired from the real Spring
   * context), with every other required claim present and valid, but a non-UUID {@code sub}.
   *
   * <p>US-018 T-005 (RC-40.1 / T-S10) moved the rejection to its source: {@link
   * com.example.nexus.identity.infrastructure.security.JwtRs256Service#verify} now rejects a
   * non-UUID {@code sub}, so through the real filter chain the request fails at authentication
   * with 401 {@code AUTH_003} and never reaches {@code UserRoleController}. The controller's own
   * fail-closed principal parsing (T-S4, 403 {@code MALFORMED_AUTHENTICATION}) stays as defence in
   * depth and is covered by {@code RbacControllerSupportTest} and {@code UserRoleControllerTest}.
   */
  @Test
  void should_return401Auth003_notInternalServerError_when_jwtSubIsNotAUuid() {
    UUID tenantG = uuidGenerator.newId();
    String malformedToken =
        forgeJwtWithSubject("not-a-uuid-subject", tenantG, List.of("user:read", "user:write"));
    double before = tokenRejectedCount("sub");

    ResponseEntity<Map> resp = getRoles(malformedToken, uuidGenerator.newId());

    assertThat(resp.getStatusCode())
        .as("a non-UUID sub must be rejected at authentication with 401, never surface as an"
            + " unhandled 500 (T-S10)")
        .isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(resp.getBody()).containsEntry("code", "AUTH_003");
    assertThat(tokenRejectedCount("sub") - before)
        .as("nexus.auth.token_rejected{reason=sub} must increment by exactly 1")
        .isEqualTo(1.0);
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
    User caller = seedUserWithRole(tenantH, "malformed-path-role-caller", "ASSIGNER", USER_ROLE_ASSIGN_PERMISSION_ID);
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
    User caller = seedUserWithRole(tenantH, "malformed-body-role-caller", "ASSIGNER", USER_ROLE_ASSIGN_PERMISSION_ID);
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
    // Row 16: the caller is an administrator by holding a role that carries the whole catalogue
    // (which includes user:read), whatever the role is named.
    User admin = seedUser(tenantI, "assignedby-admin-caller");
    Role adminRole = seedRole(tenantI, "TENANT_ADMIN", "assignedby-admin-caller");
    grantWholeCatalogue(adminRole.getId());
    seedActiveAssignment(tenantI, adminRole.getId(), admin.getId(), admin.getId());
    User target = seedUser(tenantI, "assignedby-admin-target");
    Role role = seedRole(tenantI, "ORDINARY", "assignedby-admin");
    User grantor = seedUser(tenantI, "assignedby-admin-grantor");
    seedActiveAssignment(tenantI, role.getId(), target.getId(), grantor.getId());
    String token = mintToken(admin);

    ResponseEntity<Map> resp = getRoles(token, target.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
    List<Map<String, Object>> data = (List<Map<String, Object>>) resp.getBody().get("data");
    assertThat(data)
        .as("a caller who is an administrator (admin-defining role) must see assignedBy (O-10)")
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
        .as("a caller who is not an administrator must never see a real assignedBy"
            + " value (T-I5: admin-roster enumeration)")
        .allSatisfy(row -> assertThat(row.get("assignedBy")).isNull());
  }

  /** Row 16: a union-holder (the whole catalogue only across two roles) is not an administrator. */
  @Test
  @SuppressWarnings("unchecked")
  void should_omitAssignedBy_when_callerHoldsTheWholeCatalogueOnlyAcrossTwoRoles() {
    UUID tenantU = uuidGenerator.newId();
    User unionHolder = seedUser(tenantU, "assignedby-union-caller");
    Role halfA = seedRole(tenantU, "HALF-A", "assignedby-union");
    Role halfB = seedRole(tenantU, "HALF-B", "assignedby-union");
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions"
            + " WHERE id = ?",
        toBytes(halfA.getId()),
        toBytes(USER_READ_PERMISSION_ID));
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions"
            + " WHERE id <> ?",
        toBytes(halfB.getId()),
        toBytes(USER_READ_PERMISSION_ID));
    seedActiveAssignment(tenantU, halfA.getId(), unionHolder.getId(), unionHolder.getId());
    seedActiveAssignment(tenantU, halfB.getId(), unionHolder.getId(), unionHolder.getId());
    User target = seedUser(tenantU, "assignedby-union-target");
    Role role = seedRole(tenantU, "ORDINARY", "assignedby-union");
    User grantor = seedUser(tenantU, "assignedby-union-grantor");
    seedActiveAssignment(tenantU, role.getId(), target.getId(), grantor.getId());

    ResponseEntity<Map> resp = getRoles(mintToken(unionHolder), target.getId());

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
    List<Map<String, Object>> data = (List<Map<String, Object>>) resp.getBody().get("data");
    assertThat(data).allSatisfy(row -> assertThat(row.get("assignedBy")).isNull());
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

  /** Makes {@code roleId} admin-defining (US-018 §2.1): attaches every catalogue permission. */
  private void grantWholeCatalogue(UUID roleId) {
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions",
        toBytes(roleId));
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
   * class's Javadoc on {@link #should_return401Auth003_notInternalServerError_when_jwtSubIsNotAUuid()}.
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

  /**
   * Reads the CURRENT value of a counter that carries at most one tag (and none for {@code
   * tagKey == null}); compared as a before/after delta for the same shared-registry reason as
   * {@link #permissionDeniedCount}. The M3 meters carry no tenant tag (B3).
   */
  private double counterValue(String name, String tagKey, String tagValue) {
    var search = meterRegistry.find(name);
    if (tagKey != null) {
      search = search.tag(tagKey, tagValue);
    }
    Counter counter = search.counter();
    return counter == null ? 0.0 : counter.count();
  }

  /** Out-of-band revocation, outside any request-scoped transaction (T-E7's technique). */
  private void revokeOutOfBand(UUID assignmentId) {
    int[] affectedHolder = new int[1];
    new org.springframework.transaction.support.TransactionTemplate(transactionManager)
        .executeWithoutResult(
            status ->
                affectedHolder[0] = userRoleRepository.revokeById(assignmentId, Instant.now()));
    assertThat(affectedHolder[0]).as("the out-of-band revoke itself must succeed").isEqualTo(1);
  }

  private int activeAssignmentCount(UUID userId, UUID roleId) {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ? AND revoked_at IS"
                + " NULL",
            Integer.class,
            toBytes(userId),
            toBytes(roleId));
    return count == null ? 0 : count;
  }

  /**
   * Reads the CURRENT value of {@code nexus.auth.token_rejected{reason}} (US-018 T-005); compared
   * as a before/after delta for the same shared-registry reason as {@link #permissionDeniedCount}.
   */
  private double tokenRejectedCount(String reason) {
    Counter counter =
        meterRegistry.find("nexus.auth.token_rejected").tag("reason", reason).counter();
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
