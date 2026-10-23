package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.security.AuthenticationDetailKeys;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import com.jayway.jsonpath.JsonPath;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * US-019 T-008 (design §6, B4, T-S13): {@code GET /api/v1/users/me/authorization} against real
 * MySQL. Every answer is read live from the database, never from the token: the caller's
 * authentication below carries claims (roles, permissions) that the database contradicts, and the
 * response follows the database. Fixtures use fresh tenants and custom roles only.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class CallerAuthorizationIT {

  private static final String PATH = "/api/v1/users/me/authorization";
  private static final String AUDIT_READ = "audit:read";
  private static final String ROLE_READ = "role:read";

  @Autowired private WebApplicationContext context;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  private MockMvc mvc;

  @BeforeEach
  void setUp() {
    mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
  }

  @Test
  void should_dropTheRevokedRoleAndItsPermissions_when_calledWithTheTokenMintedBeforeTheRevoke()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUser(tenantId);
    Role kept = seedRole(tenantId, "a-kept", ROLE_READ);
    Role revoked = seedRole(tenantId, "b-revoked", AUDIT_READ);
    assign(caller, kept, tenantId);
    UserRole revokedAssignment = assign(caller, revoked, tenantId);
    jdbc.update(
        "UPDATE user_roles SET revoked_at = CURRENT_TIMESTAMP(6) WHERE id = ?",
        (Object) toBytes(revokedAssignment.getId()));

    String body = read(caller, tenantId, List.of(ROLE_READ, AUDIT_READ));

    assertThat(roleIds(body)).containsExactly(kept.getId().toString());
    assertThat(permissions(body)).containsExactly(ROLE_READ);
  }

  @Test
  void should_answerAdministrator_when_aCustomRoleHoldsTheFullCatalogue() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUser(tenantId);
    Role full = seedRole(tenantId, "full", null);
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions",
        (Object) toBytes(full.getId()));
    assign(caller, full, tenantId);

    String body = read(caller, tenantId, List.of());

    assertThat((Boolean) JsonPath.read(body, "$.isAdministrator")).isTrue();
    assertThat(permissions(body)).containsExactlyElementsOf(catalogueNames());
  }

  @Test
  void should_answerNotAdministrator_when_onlyTheUnionOfTwoRolesCoversTheCatalogue()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUser(tenantId);
    Role first = seedRole(tenantId, "half-1", null);
    Role second = seedRole(tenantId, "half-2", null);
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE name <> ?",
        toBytes(first.getId()),
        AUDIT_READ);
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE name = ?",
        toBytes(second.getId()),
        AUDIT_READ);
    assign(caller, first, tenantId);
    assign(caller, second, tenantId);

    String body = read(caller, tenantId, List.of());

    assertThat(permissions(body)).containsExactlyElementsOf(catalogueNames());
    assertThat((Boolean) JsonPath.read(body, "$.isAdministrator")).isFalse();
  }

  @Test
  void should_omitASoftDeletedRoleAndItsPermissions_when_theAssignmentIsStillActive()
      throws Exception {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUser(tenantId);
    Role live = seedRole(tenantId, "live", ROLE_READ);
    Role deleted = seedRole(tenantId, "deleted", AUDIT_READ);
    assign(caller, live, tenantId);
    assign(caller, deleted, tenantId);
    jdbc.update(
        "UPDATE roles SET deleted_at = CURRENT_TIMESTAMP(6) WHERE id = ?",
        (Object) toBytes(deleted.getId()));

    String body = read(caller, tenantId, List.of());

    assertThat(roleIds(body)).containsExactly(live.getId().toString());
    assertThat(permissions(body)).containsExactly(ROLE_READ);
  }

  @Test
  void should_returnOnlyTheTokensTenant_when_theUserHoldsRolesInAnotherTenant() throws Exception {
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    User caller = seedUser(tenantA);
    Role inA = seedRole(tenantA, "in-a", ROLE_READ);
    Role inB = seedRole(tenantB, "in-b", AUDIT_READ);
    assign(caller, inA, tenantA);
    assign(caller, inB, tenantB);
    User otherUserInA = seedUser(tenantA);
    assign(otherUserInA, seedRole(tenantA, "other-user", AUDIT_READ), tenantA);

    String body = read(caller, tenantA, List.of());

    assertThat(roleIds(body)).containsExactly(inA.getId().toString());
    assertThat(permissions(body)).containsExactly(ROLE_READ);
  }

  @Test
  void should_listRolesByNameWithTheirNames_when_theCallerHoldsSeveral() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUser(tenantId);
    Role second = seedRole(tenantId, "zz", AUDIT_READ);
    Role first = seedRole(tenantId, "aa", ROLE_READ);
    assign(caller, second, tenantId);
    assign(caller, first, tenantId);

    String body = read(caller, tenantId, List.of());

    assertThat(roleIds(body)).containsExactly(first.getId().toString(), second.getId().toString());
    assertThat((List<String>) JsonPath.read(body, "$.roles[*].name"))
        .containsExactly(first.getName(), second.getName());
    assertThat(permissions(body)).containsExactly(AUDIT_READ, ROLE_READ);
  }

  @Test
  void should_returnTheEmptyShapeUncached_when_theCallerHoldsNoRole() throws Exception {
    UUID tenantId = uuidGenerator.newId();
    User caller = seedUser(tenantId);

    MockHttpServletResponse response = perform(caller, tenantId, List.of(ROLE_READ));

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL)).contains("no-store");
    String body = response.getContentAsString();
    assertThat((Map<String, Object>) JsonPath.read(body, "$"))
        .containsOnlyKeys("userId", "roles", "permissions", "isAdministrator");
    assertThat((String) JsonPath.read(body, "$.userId")).isEqualTo(caller.getId().toString());
    assertThat(roleIds(body)).isEmpty();
    assertThat(permissions(body)).isEmpty();
    assertThat((Boolean) JsonPath.read(body, "$.isAdministrator")).isFalse();
  }

  // ── helpers ───────────────────────────────────────────────────────────────────────────

  private String read(User caller, UUID tenantId, List<String> tokenPermissions) throws Exception {
    MockHttpServletResponse response = perform(caller, tenantId, tokenPermissions);
    assertThat(response.getStatus()).as(response.getContentAsString()).isEqualTo(200);
    return response.getContentAsString();
  }

  private MockHttpServletResponse perform(
      User caller, UUID tenantId, List<String> tokenPermissions) throws Exception {
    return mvc.perform(get(PATH).with(authentication(token(caller, tenantId, tokenPermissions))))
        .andReturn()
        .getResponse();
  }

  /** The caller's token: its role and permission claims are whatever it was minted with. */
  private static Authentication token(User caller, UUID tenantId, List<String> permissions) {
    UsernamePasswordAuthenticationToken authentication =
        UsernamePasswordAuthenticationToken.authenticated(
            caller.getId().toString(), null, AuthorityUtils.createAuthorityList("ROLE_STALE"));
    authentication.setDetails(
        Map.of(
            AuthenticationDetailKeys.TENANT_ID, tenantId.toString(),
            AuthenticationDetailKeys.EMAIL_VERIFIED, true,
            AuthenticationDetailKeys.TOKEN_VERSION, 2,
            AuthenticationDetailKeys.PERMISSIONS, permissions));
    return authentication;
  }

  private static List<String> roleIds(String body) {
    return JsonPath.read(body, "$.roles[*].roleId");
  }

  private static List<String> permissions(String body) {
    return JsonPath.read(body, "$.permissions");
  }

  private List<String> catalogueNames() {
    return jdbc.queryForList("SELECT name FROM permissions", String.class).stream()
        .sorted()
        .toList();
  }

  private User seedUser(UUID tenantId) {
    String email = "ca-" + UUID.randomUUID() + "@example.test";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRepository.save(
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  /** A custom role named {@code tag-<random>}, granted {@code permissionName} when not null. */
  private Role seedRole(UUID tenantId, String tag, String permissionName) {
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, tag + "-" + UUID.randomUUID(), null, false));
    if (permissionName != null) {
      jdbc.update(
          "INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE name = ?",
          toBytes(role.getId()),
          permissionName);
    }
    return role;
  }

  private UserRole assign(User user, Role role, UUID tenantId) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), user.getId(), role.getId(), tenantId, user.getId()));
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
