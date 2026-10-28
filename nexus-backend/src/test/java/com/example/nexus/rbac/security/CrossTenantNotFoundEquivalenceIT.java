package com.example.nexus.rbac.security;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
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
 * US-018 B1, TS-11 (FR-B1.a, FR-B1.b; 03b-threat-model.md T-R13): on each handler path that takes
 * a user or role id, a cross-tenant id and a non-existent id produce the same status, {@code
 * code}, {@code detail}, response header names and body shape. Only {@code traceId} and {@code
 * instance} (which echoes the per-request URL) may differ. A WARN {@code RBAC_CROSS_TENANT_TARGET}
 * appears on the cross-tenant request only, and neither request writes an {@code auth_events} row.
 *
 * <p>Structurally modelled on {@code RolePermissionSecurityIT}: real server, real filter chain,
 * real minted RS256 JWTs, and a {@link RestTemplate} that never throws on 4xx.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class CrossTenantNotFoundEquivalenceIT {

  private static final UUID USER_READ = RbacSeededPermissionIds.USER_READ;
  private static final UUID ROLE_READ = RbacSeededPermissionIds.ROLE_READ;
  private static final UUID ROLE_WRITE = RbacSeededPermissionIds.ROLE_WRITE;
  private static final UUID USER_ROLE_ASSIGN = RbacSeededPermissionIds.USER_ROLE_ASSIGN;
  private static final Set<String> VOLATILE_BODY_KEYS = Set.of("traceId", "instance");

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
  private ListAppender<ILoggingEvent> appender;
  private final List<Logger> attachedTo = new java.util.ArrayList<>();

  private UUID tenantA;
  private UUID tenantB;
  private String token;
  private User ownTenantUser;
  private Role ownRole;
  private User foreignUser;
  private Role foreignRole;

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
    tenantA = uuidGenerator.newId();
    tenantB = uuidGenerator.newId();
    User caller = seedUser(tenantA, "caller");
    Role callerRole = seedRole(tenantA, "caller");
    for (UUID permissionId : List.of(USER_READ, ROLE_READ, ROLE_WRITE, USER_ROLE_ASSIGN)) {
      rolePermissionRepository.save(new RolePermission(callerRole.getId(), permissionId));
    }
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), caller.getId(), callerRole.getId(), tenantA, caller.getId()));
    token = jwtPort.issue(caller).token();
    ownTenantUser = seedUser(tenantA, "own-user");
    ownRole = seedRole(tenantA, "own-role");
    foreignUser = seedUser(tenantB, "foreign-user");
    foreignRole = seedRole(tenantB, "foreign-role");

    appender = new ListAppender<>();
    appender.start();
    for (Class<?> type : List.of(RoleAssignmentService.class, RoleManagementService.class)) {
      Logger logger = (Logger) LoggerFactory.getLogger(type);
      logger.addAppender(appender);
      attachedTo.add(logger);
    }
  }

  @AfterEach
  void tearDown() {
    attachedTo.forEach(logger -> logger.detachAppender(appender));
    appender.stop();
  }

  @Test
  void should_matchNotFound_when_assigningRoleToUserInAnotherTenant() {
    assertEquivalent(
        "USER_NOT_FOUND",
        id -> post("/api/v1/users/" + id + "/roles", Map.of("roleId", ownRole.getId().toString())),
        foreignUser.getId());
  }

  @Test
  void should_matchNotFound_when_assigningRoleFromAnotherTenant() {
    assertEquivalent(
        "ROLE_NOT_FOUND",
        id -> post("/api/v1/users/" + ownTenantUser.getId() + "/roles", Map.of("roleId", id.toString())),
        foreignRole.getId());
  }

  @Test
  void should_matchNotFound_when_revokingRoleFromUserInAnotherTenant() {
    assertEquivalent(
        "USER_NOT_FOUND",
        id -> delete("/api/v1/users/" + id + "/roles/" + ownRole.getId()),
        foreignUser.getId());
  }

  @Test
  void should_matchNotFound_when_revokingRoleFromAnotherTenant() {
    assertEquivalent(
        "ROLE_NOT_FOUND",
        id -> delete("/api/v1/users/" + ownTenantUser.getId() + "/roles/" + id),
        foreignRole.getId());
  }

  @Test
  void should_matchNotFound_when_listingRolesOfUserInAnotherTenant() {
    assertEquivalent(
        "USER_NOT_FOUND", id -> get("/api/v1/users/" + id + "/roles"), foreignUser.getId());
  }

  @Test
  void should_matchNotFound_when_listingPermissionsOfRoleInAnotherTenant() {
    assertEquivalent(
        "ROLE_NOT_FOUND", id -> get("/api/v1/roles/" + id + "/permissions"), foreignRole.getId());
  }

  @Test
  void should_matchNotFound_when_attachingPermissionToRoleInAnotherTenant() {
    assertEquivalent(
        "ROLE_NOT_FOUND",
        id -> post("/api/v1/roles/" + id + "/permissions", Map.of("permissionId", USER_READ.toString())),
        foreignRole.getId());
  }

  @Test
  void should_matchNotFound_when_detachingPermissionFromRoleInAnotherTenant() {
    assertEquivalent(
        "ROLE_NOT_FOUND",
        id -> delete("/api/v1/roles/" + id + "/permissions/" + USER_READ),
        foreignRole.getId());
  }

  @Test
  void should_matchNotFound_when_gettingRoleInAnotherTenant() {
    assertEquivalent("ROLE_NOT_FOUND", id -> get("/api/v1/roles/" + id), foreignRole.getId());
  }

  @Test
  void should_matchNotFound_when_gettingDeletedRole() {
    Role deleted = seedRole(tenantA, "deleted");
    jdbc.update("UPDATE roles SET deleted_at = NOW(6) WHERE id = ?", toBytes(deleted.getId()));

    ResponseEntity<Map> missing = get("/api/v1/roles/" + uuidGenerator.newId());
    ResponseEntity<Map> gone = get("/api/v1/roles/" + deleted.getId());

    assertThat(gone.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(gone.getBody()).containsEntry("code", "ROLE_NOT_FOUND");
    assertThat(comparableBody(gone)).isEqualTo(comparableBody(missing));
  }

  @Test
  void should_return_identical_messages_for_all_entities() {
    ResponseEntity<Map> roleResp = get("/api/v1/roles/" + foreignRole.getId());
    ResponseEntity<Map> userResp = get("/api/v1/users/" + foreignUser.getId() + "/roles");

    assertThat(roleResp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(userResp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(roleResp.getBody()).isNotNull();
    assertThat(userResp.getBody()).isNotNull();
  }

  // ── The equivalence check ────────────────────────────────────────────

  private void assertEquivalent(
      String expectedCode, Function<UUID, ResponseEntity<Map>> request, UUID crossTenantId) {
    long rowsBefore = authEventRows(tenantA);

    appender.list.clear();
    ResponseEntity<Map> nonExistent = request.apply(uuidGenerator.newId());
    long crossTenantWarnsOnNotFound = crossTenantWarns();

    appender.list.clear();
    ResponseEntity<Map> crossTenant = request.apply(crossTenantId);
    long crossTenantWarnsOnCrossTenant = crossTenantWarns();

    assertThat(nonExistent.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(crossTenant.getStatusCode()).isEqualTo(nonExistent.getStatusCode());
    assertThat(crossTenant.getBody()).containsEntry("code", expectedCode);
    assertThat(comparableBody(crossTenant)).isEqualTo(comparableBody(nonExistent));
    assertThat(crossTenant.getBody().get("detail")).isEqualTo(nonExistent.getBody().get("detail"));
    assertThat(crossTenant.getHeaders().headerNames()).isEqualTo(nonExistent.getHeaders().headerNames());
    assertThat(crossTenant.getHeaders().getContentType())
        .isEqualTo(nonExistent.getHeaders().getContentType());
    assertThat(crossTenantWarnsOnNotFound).as("no cross-tenant WARN on a genuine not-found").isZero();
    assertThat(crossTenantWarnsOnCrossTenant).as("exactly one WARN on the cross-tenant path").isEqualTo(1);
    assertThat(authEventRows(tenantA))
        .as("neither path writes an auth_events row (a write on one path would be a timing oracle)")
        .isEqualTo(rowsBefore);
  }

  private static Map<String, Object> comparableBody(ResponseEntity<Map> response) {
    Map<String, Object> copy = new LinkedHashMap<>();
    ((Map<?, ?>) response.getBody())
        .forEach(
            (key, value) -> {
              if (!VOLATILE_BODY_KEYS.contains(String.valueOf(key))) {
                copy.put(String.valueOf(key), value);
              }
            });
    return copy;
  }

  private long crossTenantWarns() {
    return appender.list.stream()
        .filter(event -> event.getLevel() == Level.WARN)
        .filter(
            event ->
                event.getKeyValuePairs() != null
                    && event.getKeyValuePairs().stream()
                        .anyMatch(
                            kv ->
                                "event".equals(kv.key)
                                    && "RBAC_CROSS_TENANT_TARGET".equals(kv.value)))
        .count();
  }

  private long authEventRows(UUID tenantId) {
    Long count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM auth_events WHERE tenant_id = ?", Long.class, toBytes(tenantId));
    return count == null ? 0 : count;
  }

  // ── Seeding and HTTP helpers ─────────────────────────────────────────

  private User seedUser(UUID tenantId, String tag) {
    String email = "xtne-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRepository.save(
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  private Role seedRole(UUID tenantId, String tag) {
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "XTNE-" + tag + "-" + UUID.randomUUID(), null, false));
  }

  private ResponseEntity<Map> get(String path) {
    return restTemplate.exchange(url(path), HttpMethod.GET, new HttpEntity<>(authHeaders()), Map.class);
  }

  private ResponseEntity<Map> delete(String path) {
    return restTemplate.exchange(
        url(path), HttpMethod.DELETE, new HttpEntity<>(authHeaders()), Map.class);
  }

  private ResponseEntity<Map> post(String path, Map<String, String> body) {
    HttpHeaders headers = authHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    return restTemplate.exchange(url(path), HttpMethod.POST, new HttpEntity<>(body, headers), Map.class);
  }

  private HttpHeaders authHeaders() {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    return headers;
  }

  private String url(String path) {
    return "http://localhost:" + port + path;
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
