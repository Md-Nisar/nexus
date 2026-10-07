package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.security.RsaKeyConfig;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import io.jsonwebtoken.Jwts;
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
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * End-to-end A9 token freshness against MySQL and Redis (US-018 T-009, TS-8, RC-24.3, RC-44.4).
 *
 * <p>Every request goes over real HTTP and carries the access token the way the SPA attaches it:
 * an {@code Authorization: Bearer} header on every API call, including {@code POST /auth/refresh}
 * and {@code /auth/logout}, with the refresh token in its cookie. The revocation runs through the
 * real, transactional {@link RoleAssignmentService}, so the epoch bump fires from {@code
 * afterCommit} as in production. Redis comes from {@link TestcontainersConfiguration}'s service
 * connection, which the dedicated epoch connections must follow (RC-45.2).
 *
 * <p>The degraded-closed cases are T-011's.
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "nexus.identity.encryption.password=test-enc-password-32-chars-long!!",
        "nexus.identity.encryption.salt=cafebabecafebabecafebabecafebabe",
        "nexus.identity.hmac-key=test-not-a-secret-hmac-key-min-32-bytes!!",
        "nexus.identity.default-tenant-id=00000000-0000-7000-8000-000000000001",
        "nexus.security.rate-limit.ip-max-attempts=10000",
        "nexus.security.rate-limit.ip-window-seconds=60",
        "nexus.security.rate-limit.user-max-attempts=10000",
        "nexus.security.rate-limit.user-window-seconds=900",
        "nexus.security.rate-limit.refresh-max-attempts=10000"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class TokenFreshnessIT {

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");
  /** {@code role:read}, seeded by V5; guards {@code GET /api/v1/roles}. */
  private static final UUID ROLE_READ = UUID.fromString("019f6839-1804-7000-8000-000000000005");
  private static final String PASSWORD = "ValidPassphrase_99!";
  private static final String GUARDED = "/api/v1/roles";

  @Value("${local.server.port:0}") private int port;
  @Value("${nexus.redis.key-prefix:nexus}") private String keyPrefix;

  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private PasswordHasherPort passwordHasher;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private EmailBlindIndexService emailBlindIndexService;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private JwtPort jwtPort;
  @Autowired private RsaKeyConfig rsaKeyConfig;
  @Autowired private StringRedisTemplate redisTemplate;

  private RestTemplate http;

  @BeforeEach
  void setUp() {
    http = new RestTemplate();
    http.setErrorHandler(new DefaultResponseErrorHandler() {
      @Override
      public boolean hasError(ClientHttpResponse response) {
        return false;
      }
    });
  }

  // ── TS-8 ──────────────────────────────────────────────────────────────────

  @Test
  void should_reject401ThenRefreshWithoutPermission_withinOneSecond_when_roleRevoked() {
    Holder holder = seedHolder("ts8");
    Session session = login(holder.email());
    assertThat(get(GUARDED, session.accessToken()).getStatusCode().value()).isEqualTo(200);

    long start = System.nanoTime();
    revoke(holder);

    ResponseEntity<Map> stale = get(GUARDED, session.accessToken());
    assertThat(stale.getStatusCode().value()).isEqualTo(401);
    assertThat(stale.getBody()).containsEntry("code", "AUTH_003");

    ResponseEntity<Map> refreshed = refresh(session.accessToken(), session.refreshCookie());
    assertThat(refreshed.getStatusCode().value()).isEqualTo(200);
    String newToken = (String) refreshed.getBody().get("accessToken");
    JwtClaims claims = jwtPort.verify(newToken);
    assertThat(claims.permissions()).doesNotContain("role:read");
    assertThat(claims.permEpoch()).isEqualTo(storedEpoch(holder.user().getId()));

    ResponseEntity<Map> replay = get(GUARDED, newToken);
    long elapsedMs = (System.nanoTime() - start) / 1_000_000;
    assertThat(replay.getStatusCode().value())
        .as("the refreshed token passes the epoch check and is denied by permission")
        .isEqualTo(403);
    assertThat(elapsedMs).as("revoke to refreshed, permission-free token").isLessThan(1000L);
  }

  @Test
  void should_beFresh_when_epochKeyAbsent() {
    Holder holder = seedHolder("absent");
    Session session = login(holder.email());

    assertThat(redisTemplate.hasKey(epochKey(holder.user().getId()))).isFalse();
    assertThat(jwtPort.verify(session.accessToken()).permEpoch()).isZero();
    assertThat(get(GUARDED, session.accessToken()).getStatusCode().value()).isEqualTo(200);
  }

  @Test
  void should_return401_when_v2TokenForRecentlyRevokedUser() {
    Holder holder = seedHolder("v2");
    revoke(holder);
    Instant now = Instant.now();
    String v2 = token(holder.user().getId(), 2, null, now, now.plusSeconds(900));

    ResponseEntity<Map> response = get(GUARDED, v2);

    assertThat(response.getStatusCode().value()).isEqualTo(401);
    assertThat(response.getBody()).containsEntry("code", "AUTH_003");
  }

  @Test
  void should_keepOtherUsersTokenFresh_when_anotherUserRevoked() {
    Holder revoked = seedHolder("iso-gone");
    Holder bystander = seedHolder("iso-by");
    Session bystanderSession = login(bystander.email());
    revoke(revoked);

    assertThat(get(GUARDED, bystanderSession.accessToken()).getStatusCode().value())
        .isEqualTo(200);
  }

  @Test
  void should_return401Auth003_when_staleEpochBearerOnNonPublicHandlerWhileHealthy() {
    Holder holder = seedHolder("stale-guarded");
    Session session = login(holder.email());
    revoke(holder);

    ResponseEntity<Map> response = get(GUARDED, session.accessToken());

    assertThat(response.getStatusCode().value()).isEqualTo(401);
    assertThat(response.getBody()).containsEntry("code", "AUTH_003");
  }

  // ── RC-24.3: public endpoints are never rejected by the bearer filter ──────

  @Test
  void should_return200_when_refreshCarriesStaleEpochBearer() {
    Holder holder = seedHolder("refresh-stale");
    Session session = login(holder.email());
    revoke(holder);

    assertThat(refresh(session.accessToken(), session.refreshCookie()).getStatusCode().value())
        .isEqualTo(200);
  }

  @Test
  void should_return200_when_refreshCarriesExpiredBearer() {
    Holder holder = seedHolder("refresh-expired");
    Session session = login(holder.email());
    Instant issued = Instant.now().minusSeconds(3600);
    String expired =
        token(holder.user().getId(), 3, 0L, issued, issued.plusSeconds(900));

    assertThat(refresh(expired, session.refreshCookie()).getStatusCode().value()).isEqualTo(200);
  }

  @Test
  void should_revokeFamilyServerSide_when_logoutCarriesStaleEpochBearer() {
    Holder holder = seedHolder("logout-stale");
    Session session = login(holder.email());
    revoke(holder);

    ResponseEntity<Map> logout = logout(session.accessToken(), session.refreshCookie());

    assertThat(logout.getStatusCode().value()).isEqualTo(204);
    assertThat(refresh(null, session.refreshCookie()).getStatusCode().value())
        .as("the logged-out refresh family must be revoked server-side")
        .isEqualTo(401);
  }

  @Test
  void should_revokeEveryFamily_when_logoutHasStaleEpochBearerAndNoCookie() {
    Holder holder = seedHolder("logout-nocookie");
    Session first = login(holder.email());
    Session second = login(holder.email());
    revoke(holder);

    ResponseEntity<Map> logout = logout(first.accessToken(), null);

    assertThat(logout.getStatusCode().value()).isEqualTo(204);
    assertThat(refresh(null, first.refreshCookie()).getStatusCode().value()).isEqualTo(401);
    assertThat(refresh(null, second.refreshCookie()).getStatusCode().value()).isEqualTo(401);
  }

  // ── fixtures ──────────────────────────────────────────────────────────────

  private record Holder(User user, String email, Role role, RoleChangeActor admin) {}

  private record Session(String accessToken, String refreshCookie) {}

  /**
   * An active user holding a custom role with {@code role:read}, and an administrator who may
   * revoke it: it holds {@code user:role:assign} and {@code role:read} (grant subset, M2).
   */
  private Holder seedHolder(String tag) {
    String email = "freshness-" + tag + "-" + UUID.randomUUID() + "@example.com";
    User user = activeUser(email);
    User adminUser = activeUser("freshness-admin-" + UUID.randomUUID() + "@example.com");

    Role readerRole = role("READER");
    rolePermissionRepository.save(new RolePermission(readerRole.getId(), ROLE_READ));
    Role adminRole = role("ADMIN");
    rolePermissionRepository.save(
        new RolePermission(adminRole.getId(), RbacSeededPermissionIds.USER_ROLE_ASSIGN));
    rolePermissionRepository.save(new RolePermission(adminRole.getId(), ROLE_READ));
    userRoleRepository.save(new UserRole(
        uuidGenerator.newId(), adminUser.getId(), adminRole.getId(), TENANT_ID, adminUser.getId()));
    userRoleRepository.save(new UserRole(
        uuidGenerator.newId(), user.getId(), readerRole.getId(), TENANT_ID, adminUser.getId()));
    return new Holder(user, email, readerRole,
        new RoleChangeActor(adminUser.getId(), TENANT_ID));
  }

  private User activeUser(String email) {
    User user = new User(uuidGenerator.newId(), TENANT_ID, new EmailCipher(email),
        emailBlindIndexService.blindIndex(email), passwordHasher.hash(PASSWORD), null);
    user = userRegistrationPort.save(user);
    user.verify(Instant.now());
    return userRegistrationPort.save(user);
  }

  private Role role(String tag) {
    return roleRepository.save(new Role(
        uuidGenerator.newId(), TENANT_ID, "FRESH-" + tag + "-" + UUID.randomUUID(), null, false));
  }

  private void revoke(Holder holder) {
    roleAssignmentService.revoke(
        holder.admin(), holder.user().getId(), holder.role().getId(),
        RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "JUnit"));
  }

  private long storedEpoch(UUID userId) {
    return Long.parseLong(redisTemplate.opsForValue().get(epochKey(userId)));
  }

  private String epochKey(UUID userId) {
    return keyPrefix + ":rbac:epoch:" + TENANT_ID + ":" + userId;
  }

  /** A token signed with the application's own key, as an earlier mint would have produced. */
  private String token(
      UUID userId, int schemaVersion, Long permEpoch, Instant issuedAt, Instant expiresAt) {
    var builder = Jwts.builder()
        .header().add("kid", rsaKeyConfig.getKid()).add("typ", "JWT").and()
        .subject(userId.toString())
        .claim("tenant_id", TENANT_ID.toString())
        .claim("email_verified", true)
        .claim("roles", List.of())
        .claim("permissions", List.of("role:read"))
        .issuedAt(Date.from(issuedAt))
        .expiration(Date.from(expiresAt))
        .id(UUID.randomUUID().toString())
        .claim("token_version", 0)
        .claim("schema_version", schemaVersion);
    if (permEpoch != null) {
      builder.claim("perm_epoch", permEpoch);
    }
    return builder.signWith(rsaKeyConfig.getKeyPair().getPrivate(), Jwts.SIG.RS256).compact();
  }

  // ── HTTP, as the SPA sends it ─────────────────────────────────────────────

  @SuppressWarnings("rawtypes")
  private Session login(String email) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    ResponseEntity<Map> response = http.exchange(url("/api/v1/auth/login"), HttpMethod.POST,
        new HttpEntity<>(Map.of("email", email, "password", PASSWORD), headers), Map.class);
    assertThat(response.getStatusCode().value()).as("login").isEqualTo(200);
    return new Session((String) response.getBody().get("accessToken"), refreshCookie(response));
  }

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> get(String path, String accessToken) {
    return http.exchange(url(path), HttpMethod.GET,
        new HttpEntity<>(null, headers(accessToken, null)), Map.class);
  }

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> refresh(String accessToken, String refreshCookie) {
    return http.exchange(url("/api/v1/auth/refresh"), HttpMethod.POST,
        new HttpEntity<>(null, headers(accessToken, refreshCookie)), Map.class);
  }

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> logout(String accessToken, String refreshCookie) {
    return http.exchange(url("/api/v1/auth/logout"), HttpMethod.POST,
        new HttpEntity<>(null, headers(accessToken, refreshCookie)), Map.class);
  }

  private static HttpHeaders headers(String accessToken, String refreshCookie) {
    HttpHeaders headers = new HttpHeaders();
    if (accessToken != null) {
      headers.setBearerAuth(accessToken);
    }
    if (refreshCookie != null) {
      headers.add(HttpHeaders.COOKIE, "refresh_token=" + refreshCookie);
    }
    return headers;
  }

  @SuppressWarnings("rawtypes")
  private static String refreshCookie(ResponseEntity<Map> response) {
    return response.getHeaders().get(HttpHeaders.SET_COOKIE).stream()
        .filter(cookie -> cookie.startsWith("refresh_token="))
        .map(cookie -> cookie.substring("refresh_token=".length(), cookie.indexOf(';')))
        .findFirst()
        .orElseThrow();
  }

  private String url(String path) {
    return "http://localhost:" + port + path;
  }
}
