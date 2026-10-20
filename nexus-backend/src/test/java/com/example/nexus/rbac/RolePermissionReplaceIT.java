package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.RolePermissionSetVersion;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.Set;
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
 * US-019 T-018 (B8, design §10.3 role-row path, §10.5, §10.8): {@code PUT
 * /api/v1/roles/{roleId}/permissions} end to end, through the real filter chain with minted JWTs
 * against MySQL and Redis. Every test uses a fresh tenant, so audit-row counts are per tenant.
 *
 * <p>The ordering properties are the point: 400, 428, 404, 409, 404 permission, then 403, then
 * 412, then the no-op. An unauthorised caller gets 403 for every combination of body and tag that
 * removes something (RC-58.3), so 412 versus 200 never reveals R's set (T-I20).
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class RolePermissionReplaceIT {

  private static final UUID ROLE_READ = RbacSeededPermissionIds.ROLE_READ;
  private static final UUID ROLE_WRITE = RbacSeededPermissionIds.ROLE_WRITE;
  private static final UUID USER_READ = RbacSeededPermissionIds.USER_READ;
  private static final UUID USER_WRITE = RbacSeededPermissionIds.USER_WRITE;
  private static final UUID AUDIT_READ = RbacSeededPermissionIds.AUDIT_READ;
  private static final UUID TENANT_WRITE = RbacSeededPermissionIds.TENANT_WRITE;
  private static final Set<String> STANDARD_PROBLEM_FIELDS =
      Set.of("type", "title", "status", "detail", "instance", "code", "traceId");

  @Value("${local.server.port}")
  private int port;

  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JwtPort jwtPort;
  @Autowired private PermissionEpochPort epochPort;
  @Autowired private JdbcTemplate jdbc;

  private RestTemplate restTemplate;
  private UUID tenantId;

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
    tenantId = uuidGenerator.newId();
  }

  // ── Success, ETag and audit ──────────────────────────────────────────────────────────

  @Test
  void should_replaceTheSetAndServeAnETagThatTheNextGetRepeats_when_ifMatchIsCurrent() {
    String token = editorToken(ROLE_READ, ROLE_WRITE, USER_READ, AUDIT_READ);
    Role target = seedRole("target", USER_READ);
    String etag = getPermissions(token, target.getId()).getHeaders().getETag();

    ResponseEntity<Map> put = putPermissions(token, target.getId(), List.of(AUDIT_READ), etag);

    assertThat(put.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(dataIds(put)).containsExactly(AUDIT_READ.toString());
    assertThat(put.getHeaders().getETag())
        .isEqualTo(quoted(RolePermissionSetVersion.of(target.getId(), List.of(AUDIT_READ))));
    assertThat(rolePermissionIds(target.getId())).containsExactly(AUDIT_READ);
    assertThat(getPermissions(token, target.getId()).getHeaders().getETag())
        .as("the GET ETag equals the PUT ETag")
        .isEqualTo(put.getHeaders().getETag());
  }

  @Test
  void should_writeOneAuditRowPerChangeSharingOneServerReplaceId_when_replacing() {
    String token = editorToken(ROLE_READ, ROLE_WRITE, USER_READ, AUDIT_READ, USER_WRITE);
    Role target = seedRole("audit", USER_READ, USER_WRITE);

    ResponseEntity<Map> put =
        putPermissions(
            token,
            target.getId(),
            List.of(USER_READ, AUDIT_READ),
            versionOf(target, USER_READ, USER_WRITE));

    assertThat(put.getStatusCode()).isEqualTo(HttpStatus.OK);
    List<Map<String, Object>> rows =
        jdbc.queryForList(
            "SELECT event_type, "
                + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.operation')) AS operation, "
                + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.replaceId')) AS replace_id, "
                + "JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.permissionId')) AS permission_id "
                + "FROM auth_events WHERE tenant_id = ? AND event_type IN "
                + "('ROLE_PERMISSION_GRANTED', 'ROLE_PERMISSION_REVOKED')",
            (Object) toBytes(tenantId));
    assertThat(rows)
        .extracting(r -> r.get("event_type") + ":" + r.get("permission_id"))
        .containsExactlyInAnyOrder(
            "ROLE_PERMISSION_GRANTED:" + AUDIT_READ, "ROLE_PERMISSION_REVOKED:" + USER_WRITE);
    assertThat(rows).extracting(r -> r.get("operation")).containsOnly("REPLACE");
    Set<Object> replaceIds = new HashSet<>(rows.stream().map(r -> r.get("replace_id")).toList());
    assertThat(replaceIds).hasSize(1);
    assertThat(UUID.fromString(String.valueOf(replaceIds.iterator().next())).version())
        .as("the replaceId is a server-generated UUIDv7")
        .isEqualTo(7);
  }

  @Test
  void should_acceptAnEmptySet_when_theRoleIsCustom() {
    String token = editorToken(ROLE_READ, ROLE_WRITE, USER_READ, AUDIT_READ);
    Role target = seedRole("empty", USER_READ, AUDIT_READ);

    ResponseEntity<Map> put =
        putPermissions(token, target.getId(), List.of(), versionOf(target, USER_READ, AUDIT_READ));

    assertThat(put.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(dataIds(put)).isEmpty();
    assertThat(rolePermissionIds(target.getId())).isEmpty();
  }

  /** A no-op is 200 with the GET's body and ETag, no audit row and no epoch bump. */
  @Test
  void should_return200WithoutAuditOrEpochBump_when_theSetIsUnchanged() {
    String token = editorToken(ROLE_READ, ROLE_WRITE, USER_READ);
    Role target = seedRole("noop", USER_READ);
    User holder = seedUser("noop-holder");
    assign(holder, target);
    epochPort.bump(tenantId, List.of(holder.getId()));
    OptionalLong epochBefore = epochPort.current(tenantId, holder.getId());
    String etag = versionOf(target, USER_READ);

    ResponseEntity<Map> put = putPermissions(token, target.getId(), List.of(USER_READ), etag);

    assertThat(put.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(put.getHeaders().getETag()).isEqualTo(etag);
    assertThat(dataIds(put)).containsExactly(USER_READ.toString());
    assertThat(epochBefore).isPresent();
    assertThat(epochPort.current(tenantId, holder.getId())).isEqualTo(epochBefore);
    assertThat(rolePermissionAuditRows()).isZero();
  }

  // ── 412 and 428 ──────────────────────────────────────────────────────────────────────

  @Test
  void should_return412WithNoStateInTheBody_when_ifMatchIsAnOldETag() {
    String token = editorToken(ROLE_READ, ROLE_WRITE, USER_READ, AUDIT_READ);
    Role target = seedRole("stale", USER_READ);
    String oldEtag = versionOf(target, USER_READ);
    assertThat(
            putPermissions(token, target.getId(), List.of(USER_READ, AUDIT_READ), oldEtag)
                .getStatusCode())
        .isEqualTo(HttpStatus.OK);

    ResponseEntity<Map> stale = putPermissions(token, target.getId(), List.of(), oldEtag);

    assertThat(stale.getStatusCode()).isEqualTo(HttpStatus.PRECONDITION_FAILED);
    assertThat(stale.getBody()).containsEntry("code", "PRECONDITION_FAILED");
    assertThat(stale.getBody().keySet()).isSubsetOf(STANDARD_PROBLEM_FIELDS);
    assertThat(stale.getHeaders().getETag()).isNull();
    assertThat(rolePermissionIds(target.getId())).containsExactlyInAnyOrder(USER_READ, AUDIT_READ);
  }

  @Test
  void should_return428WithNoStateInTheBody_when_ifMatchIsNotExactlyOneStrongTag() {
    String token = editorToken(ROLE_READ, ROLE_WRITE, USER_READ);
    Role target = seedRole("428", USER_READ);
    String current = versionOf(target, USER_READ);

    List<String> unusable =
        Arrays.asList(
            null,
            "*",
            quoted(current) + ", " + quoted(current),
            "W/" + quoted(current),
            "",
            "garbage");
    for (String ifMatch : unusable) {
      ResponseEntity<Map> response = putPermissions(token, target.getId(), List.of(), ifMatch);

      assertThat(response.getStatusCode()).as("If-Match: %s", ifMatch)
          .isEqualTo(HttpStatus.PRECONDITION_REQUIRED);
      assertThat(response.getBody()).containsEntry("code", "PRECONDITION_REQUIRED");
      assertThat(response.getBody().keySet()).isSubsetOf(STANDARD_PROBLEM_FIELDS);
      assertThat(response.getHeaders().getETag()).isNull();
    }
    assertThat(rolePermissionIds(target.getId())).containsExactly(USER_READ);
  }

  // ── 403 before 412 and before the no-op (RC-58.1, RC-58.3, T-I20) ───────────────────

  /** One added id the caller does not hold denies the whole PUT: no row and no audit row. */
  @Test
  void should_return403AndChangeNothing_when_oneAddedPermissionIsNotHeld() {
    String token = editorToken(ROLE_READ, ROLE_WRITE, USER_READ, AUDIT_READ);
    Role target = seedRole("grant-subset", USER_READ);

    ResponseEntity<Map> put =
        putPermissions(
            token,
            target.getId(),
            List.of(USER_READ, AUDIT_READ, TENANT_WRITE),
            versionOf(target, USER_READ));

    assertThat(put.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(put.getBody()).containsEntry("code", "RBAC_001");
    assertThat(rolePermissionIds(target.getId())).containsExactly(USER_READ);
    assertThat(rolePermissionAuditRows()).isZero();
  }

  /**
   * RC-58.3: a role:write holder who lacks one of R's permissions gets 403 for every body that
   * removes something, whatever valid-looking tag it sends: never 412, never 200.
   */
  @Test
  void should_return403ForEveryRemovingCombination_when_theCallerLacksOneOfTheRolesPermissions() {
    String token = editorToken(ROLE_READ, ROLE_WRITE, USER_READ);
    Role target = seedRole("subset", USER_READ, AUDIT_READ);
    Role otherRole = seedRole("subset-other", USER_READ);
    List<String> tags =
        List.of(
            versionOf(target, USER_READ, AUDIT_READ),
            versionOf(target, USER_READ),
            versionOf(otherRole, USER_READ));
    List<List<UUID>> removingBodies = List.of(List.of(), List.of(USER_READ), List.of(AUDIT_READ));

    for (String tag : tags) {
      for (List<UUID> body : removingBodies) {
        ResponseEntity<Map> put = putPermissions(token, target.getId(), body, tag);

        assertThat(put.getStatusCode()).as("body %s, tag %s", body, tag)
            .isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(put.getHeaders().getETag()).isNull();
      }
    }
    assertThat(rolePermissionIds(target.getId())).containsExactlyInAnyOrder(USER_READ, AUDIT_READ);
    assertThat(rolePermissionAuditRows()).isZero();
  }

  /** L-1: the JWT still says role:write, the live holdings no longer do; even a no-op is 403. */
  @Test
  void should_return403OnANoOp_when_theLiveHoldingsNoLongerCarryRoleWrite() {
    User editor = seedUser("stale-jwt");
    Role editorRole = seedRole("stale-jwt-role", ROLE_READ, ROLE_WRITE, USER_READ);
    assign(editor, editorRole);
    String token = jwtPort.issue(editor).token();
    jdbc.update(
        "DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?",
        toBytes(editorRole.getId()),
        toBytes(ROLE_WRITE));
    Role target = seedRole("stale-jwt-target", USER_READ);

    ResponseEntity<Map> put =
        putPermissions(token, target.getId(), List.of(USER_READ), versionOf(target, USER_READ));

    assertThat(put.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(put.getBody()).containsEntry("code", "RBAC_001");
  }

  /** RC-58.4: a caller without role:read gets 403 on a no-op instead of learning the set. */
  @Test
  void should_return403OnANoOp_when_theCallerLacksRoleRead() {
    String token = editorToken(ROLE_WRITE, USER_READ);
    Role target = seedRole("no-read", USER_READ);

    ResponseEntity<Map> put =
        putPermissions(token, target.getId(), List.of(USER_READ), versionOf(target, USER_READ));

    assertThat(put.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(put.getHeaders().getETag()).isNull();
  }

  // ── 404 and 409 ──────────────────────────────────────────────────────────────────────

  @Test
  void should_return404PermissionNotFound_when_anIdIsNotInTheCatalogue() {
    String token = editorToken(ROLE_READ, ROLE_WRITE, USER_READ);
    Role target = seedRole("unknown-id", USER_READ);

    ResponseEntity<Map> put =
        putPermissions(
            token,
            target.getId(),
            List.of(USER_READ, uuidGenerator.newId()),
            versionOf(target, USER_READ));

    assertThat(put.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(put.getBody()).containsEntry("code", "PERMISSION_NOT_FOUND");
  }

  @Test
  void should_return404RoleNotFound_when_theRoleIsInAnotherTenant() {
    String token = editorToken(ROLE_READ, ROLE_WRITE, USER_READ);
    Role foreign =
        roleRepository.save(
            new Role(uuidGenerator.newId(), uuidGenerator.newId(), "RPR-foreign-" + UUID.randomUUID(),
                null, false));

    ResponseEntity<Map> put = putPermissions(token, foreign.getId(), List.of(), versionOf(foreign));

    assertThat(put.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(put.getBody()).containsEntry("code", "ROLE_NOT_FOUND");
  }

  @Test
  void should_return409Rbac003_when_theRoleIsASystemRole() {
    String token = editorToken(ROLE_READ, ROLE_WRITE, USER_READ);
    Role system =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, "RPR-SYS-" + UUID.randomUUID(), null, true));

    ResponseEntity<Map> put =
        putPermissions(token, system.getId(), List.of(USER_READ), versionOf(system));

    assertThat(put.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    assertThat(put.getBody()).containsEntry("code", "RBAC_003");
  }

  /** Interim (T-018 until T-019): a change that would make R admin-defining is refused, unlocked. */
  @Test
  void should_return409InterimGuard_when_theReplaceWouldMakeTheRoleAdminDefining() {
    List<UUID> catalogue = catalogueIds();
    String token = editorToken(catalogue.toArray(UUID[]::new));
    List<UUID> allButOne = catalogue.subList(1, catalogue.size());
    Role target = seedRole("promote", allButOne.toArray(UUID[]::new));

    ResponseEntity<Map> put =
        putPermissions(
            token, target.getId(), catalogue, versionOf(target, allButOne.toArray(UUID[]::new)));

    assertThat(put.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    assertThat(put.getBody()).containsEntry("code", "RBAC_REPLACE_SET_LOCK_PATH_PENDING");
    assertThat(rolePermissionIds(target.getId())).containsExactlyInAnyOrderElementsOf(allButOne);
  }

  // ── Atomicity (US-018 TS-5 trigger) ──────────────────────────────────────────────────

  @Test
  void should_return500AndChangeNothing_when_theAuditWriteFails() {
    String token = editorToken(ROLE_READ, ROLE_WRITE, USER_READ, AUDIT_READ);
    Role target = seedRole("audit-fails", USER_READ);
    jdbc.execute(
        "CREATE TRIGGER trg_t018_block_replace_audit BEFORE INSERT ON auth_events FOR EACH ROW "
            + "BEGIN IF NEW.event_type = 'ROLE_PERMISSION_GRANTED' THEN "
            + "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'T-018 test-only block'; "
            + "END IF; END");
    try {
      ResponseEntity<Map> put =
          putPermissions(
              token, target.getId(), List.of(AUDIT_READ), versionOf(target, USER_READ));

      assertThat(put.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    } finally {
      jdbc.execute("DROP TRIGGER IF EXISTS trg_t018_block_replace_audit");
    }
    assertThat(rolePermissionIds(target.getId())).containsExactly(USER_READ);
    assertThat(rolePermissionAuditRows()).isZero();
  }

  // ── Fixtures ─────────────────────────────────────────────────────────────────────────

  /** A user of this test's tenant holding {@code permissionIds} through one custom role. */
  private String editorToken(UUID... permissionIds) {
    User editor = seedUser("editor");
    assign(editor, seedRole("editor-role", permissionIds));
    return jwtPort.issue(editor).token();
  }

  private User seedUser(String tag) {
    String email = "rpr-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRepository.save(
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  private Role seedRole(String tag, UUID... permissionIds) {
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, "RPR-" + tag + "-" + UUID.randomUUID(), null,
                false));
    for (UUID permissionId : permissionIds) {
      rolePermissionRepository.save(new RolePermission(role.getId(), permissionId));
    }
    return role;
  }

  private void assign(User user, Role role) {
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), user.getId(), role.getId(), tenantId, user.getId()));
  }

  private String versionOf(Role role, UUID... permissionIds) {
    return quoted(RolePermissionSetVersion.of(role.getId(), List.of(permissionIds)));
  }

  private static String quoted(String opaqueTag) {
    return "\"" + opaqueTag + "\"";
  }

  private List<UUID> catalogueIds() {
    return jdbc.queryForList("SELECT id FROM permissions ORDER BY name", byte[].class).stream()
        .map(RolePermissionReplaceIT::fromBytes)
        .toList();
  }

  private List<UUID> rolePermissionIds(UUID roleId) {
    return jdbc
        .queryForList(
            "SELECT permission_id FROM role_permissions WHERE role_id = ?",
            byte[].class,
            (Object) toBytes(roleId))
        .stream()
        .map(RolePermissionReplaceIT::fromBytes)
        .toList();
  }

  private int rolePermissionAuditRows() {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM auth_events WHERE tenant_id = ? AND event_type IN "
                + "('ROLE_PERMISSION_GRANTED', 'ROLE_PERMISSION_REVOKED')",
            Integer.class,
            (Object) toBytes(tenantId));
    return count == null ? 0 : count;
  }

  @SuppressWarnings("unchecked")
  private static List<String> dataIds(ResponseEntity<Map> response) {
    List<String> ids = new ArrayList<>();
    for (Map<String, Object> item : (List<Map<String, Object>>) response.getBody().get("data")) {
      ids.add((String) item.get("id"));
    }
    return ids;
  }

  // ── HTTP ─────────────────────────────────────────────────────────────────────────────

  private ResponseEntity<Map> getPermissions(String token, UUID roleId) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/roles/" + roleId + "/permissions",
        HttpMethod.GET,
        new HttpEntity<>(headers),
        Map.class);
  }

  private ResponseEntity<Map> putPermissions(
      String token, UUID roleId, List<UUID> permissionIds, String ifMatch) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    headers.setContentType(MediaType.APPLICATION_JSON);
    if (ifMatch != null) {
      headers.set(HttpHeaders.IF_MATCH, ifMatch);
    }
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/roles/" + roleId + "/permissions",
        HttpMethod.PUT,
        new HttpEntity<>(
            Map.of("permissionIds", permissionIds.stream().map(UUID::toString).toList()), headers),
        Map.class);
  }

  private static byte[] toBytes(UUID uuid) {
    return ByteBuffer.allocate(16)
        .putLong(uuid.getMostSignificantBits())
        .putLong(uuid.getLeastSignificantBits())
        .array();
  }

  private static UUID fromBytes(byte[] bytes) {
    ByteBuffer buf = ByteBuffer.wrap(bytes);
    return new UUID(buf.getLong(), buf.getLong());
  }
}
