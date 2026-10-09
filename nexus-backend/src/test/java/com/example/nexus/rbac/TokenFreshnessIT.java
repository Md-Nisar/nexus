package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.reset;

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
import com.example.nexus.rbac.application.DegradedState;
import com.example.nexus.rbac.application.PermissionFreshnessService;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import io.jsonwebtoken.Jwts;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.containers.GenericContainer;

/**
 * End-to-end A9 token freshness against MySQL and Redis (US-018 T-009, TS-8, RC-24.3, RC-44.4) and
 * the A10 holder fan-out (T-010, TS-9, the design §9.4 race, RC-29.3, T-E40).
 *
 * <p>Every request goes over real HTTP and carries the access token the way the SPA attaches it:
 * an {@code Authorization: Bearer} header on every API call, including {@code POST /auth/refresh}
 * and {@code /auth/logout}, with the refresh token in its cookie. The revocation runs through the
 * real, transactional {@link RoleAssignmentService}, and detach and attach through the real {@link
 * RoleManagementService}, so the epoch bumps and evictions fire from {@code afterCommit} as in
 * production. Redis comes from {@link TestcontainersConfiguration}'s service connection, which the
 * dedicated epoch connections must follow (RC-45.2).
 *
 * <p>The permission cache is a Mockito spy that calls through, so a test can pause a mint between
 * its DB read and its cache write ({@link PermissionCachePort#put}) to reproduce the races.
 *
 * <p>The outage cases (T-011) stub the read side of {@link PermissionEpochPort} to fail and run
 * with a 3 s fail-open window and a 2 s recovery sustain, so the state machine reaches
 * degraded-closed in seconds; the real 1 s probe task restores Healthy afterwards. The replay
 * cases (T-012) pause the Redis container for real, or fail one bump on the spy, and expect the
 * 1 s scheduled drain to apply the lost bump.
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
        "nexus.security.rate-limit.refresh-ip-max-attempts=10000",
        "nexus.rbac.epoch.fail-open-window=PT3S",
        "nexus.rbac.epoch.recovery-sustain=PT2S"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class TokenFreshnessIT {

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");
  /** {@code role:read}, seeded by V5; guards {@code GET /api/v1/roles}. */
  private static final UUID ROLE_READ = UUID.fromString("019f6839-1804-7000-8000-000000000005");
  /** {@code audit:read}, seeded by V5; not dangerous, so any holder of it may attach it (A3). */
  private static final UUID AUDIT_READ = UUID.fromString("019f6839-1806-7000-8000-000000000007");
  private static final long LATCH_TIMEOUT_SECONDS = 30;
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
  @Autowired private RoleManagementService roleManagementService;
  @MockitoSpyBean private PermissionCachePort permissionCache;
  @MockitoSpyBean private PermissionEpochPort epochPort;
  @MockitoSpyBean private UserRoleAssignmentPort userRoleAssignmentPort;
  @Autowired private PermissionFreshnessService freshness;
  @Autowired private JwtPort jwtPort;
  @Autowired private RsaKeyConfig rsaKeyConfig;
  @Autowired private StringRedisTemplate redisTemplate;
  @Autowired @Qualifier("redisContainer") private GenericContainer<?> redisContainer;

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

  @AfterEach
  void restoreHealthyState() throws InterruptedException {
    reset(epochPort);
    reset(userRoleAssignmentPort);
    awaitState(DegradedState.HEALTHY);
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

  // ── T-011: Redis outage policy (A9, design §9.5) ───────────────────────────

  @Test
  void should_return200_when_refreshCarriesBearerWhileDegradedClosed() throws Exception {
    Holder holder = seedHolder("closed-refresh");
    Session session = login(holder.email());
    driveToDegradedClosed();

    assertThat(refresh(session.accessToken(), session.refreshCookie()).getStatusCode().value())
        .isEqualTo(200);
  }

  @Test
  void should_return503Auth005_when_staleEpochBearerOnNonPublicHandlerWhileDegradedClosed()
      throws Exception {
    Holder holder = seedHolder("closed-guarded");
    Session session = login(holder.email());
    revoke(holder);
    driveToDegradedClosed();

    ResponseEntity<Map> response = get(GUARDED, session.accessToken());

    assertThat(response.getStatusCode().value()).isEqualTo(503);
    assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("30");
    assertThat(response.getBody())
        .containsEntry("code", "AUTH_005")
        .containsEntry("status", 503)
        .containsEntry("title", "Service Unavailable")
        .containsKeys("type", "detail", "instance", "traceId");
  }

  @Test
  void should_notServeRevokedToken_when_readsFailAfterTheBumpWasSeen() throws Exception {
    // Security review M-1: an induced read failure must not turn a known revocation into a pass.
    Holder holder = seedHolder("outage-revoked");
    Session session = login(holder.email());
    Holder bystander = seedHolder("outage-bystander");
    Session bystanderSession = login(bystander.email());
    revoke(holder);
    failReads();

    ResponseEntity<Map> replay = get(GUARDED, session.accessToken());
    assertThat(replay.getStatusCode().value()).isEqualTo(401);
    assertThat(get(GUARDED, bystanderSession.accessToken()).getStatusCode().value())
        .as("other users still fail open for the one request")
        .isEqualTo(200);
  }

  /** Reads and probes fail until {@link #restoreHealthyState()} resets the spy. */
  private void failReads() {
    doReturn(OptionalLong.empty()).when(epochPort).current(any(), any());
    doReturn(false).when(epochPort).probe();
  }

  private void driveToDegradedClosed() throws InterruptedException {
    Holder bystander = seedHolder("outage-trip");
    Session bystanderSession = login(bystander.email());
    failReads();
    for (int i = 0; i < 3; i++) {
      get(GUARDED, bystanderSession.accessToken());
    }
    awaitState(DegradedState.DEGRADED_CLOSED);
  }

  private void awaitState(DegradedState expected) throws InterruptedException {
    long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
    while (freshness.state() != expected) {
      assertThat(System.nanoTime()).as("state " + expected + ", was " + freshness.state())
          .isLessThan(deadline);
      Thread.sleep(50);
    }
  }

  // ── T-012: a bump lost to a Redis failure is replayed (RC-30, RC-42.4) ────

  @Test
  void should_replayLostBumpAndRejectOldToken_when_redisRecoversAfterBeingPaused()
      throws Exception {
    Holder holder = seedHolder("replay-paused");
    Session session = login(holder.email());
    assertThat(get(GUARDED, session.accessToken()).getStatusCode().value()).isEqualTo(200);
    String containerId = redisContainer.getContainerId();
    redisContainer.getDockerClient().pauseContainerCmd(containerId).exec();
    try {
      // The post-commit bump times out against the paused server and is queued, not lost.
      revoke(holder);
      assertThat(redisContainer.getDockerClient().inspectContainerCmd(containerId).exec()
          .getState().getPaused()).isTrue();
    } finally {
      redisContainer.getDockerClient().unpauseContainerCmd(containerId).exec();
    }

    awaitEpochKey(holder.user().getId(), Duration.ofSeconds(30));

    ResponseEntity<Map> stale = get(GUARDED, session.accessToken());
    assertThat(stale.getStatusCode().value()).isEqualTo(401);
    assertThat(stale.getBody()).containsEntry("code", "AUTH_003");
  }

  @Test
  void should_replayWithinTwoSeconds_when_singleBumpFailsAndInstanceStaysHealthy()
      throws Exception {
    Holder holder = seedHolder("replay-single");
    Session session = login(holder.email());
    assertThat(get(GUARDED, session.accessToken()).getStatusCode().value()).isEqualTo(200);
    doThrow(new QueryTimeoutException("bump timeout"))
        .doCallRealMethod()
        .when(epochPort).bump(any(), anyCollection());

    revoke(holder);

    assertThat(redisTemplate.hasKey(epochKey(holder.user().getId()))).isFalse();
    awaitEpochKey(holder.user().getId(), Duration.ofSeconds(2));
    assertThat(freshness.state()).isEqualTo(DegradedState.HEALTHY);
    assertThat(get(GUARDED, session.accessToken()).getStatusCode().value()).isEqualTo(401);
  }

  /**
   * Security review part 2, M-2: the post-commit holder read fails twice, so the request thread
   * bumps nobody; the 1 s tick then reads the holders and revokes them.
   */
  @Test
  void should_revokeEveryHolderByTick_when_detachHolderReadFailsTwice() throws Exception {
    Role reader = readerRole("M2READ");
    RoleChangeActor admin = seedAdmin();
    String email = "freshness-m2-" + UUID.randomUUID() + "@example.com";
    User holder = activeUser(email);
    assign(holder, reader, admin);
    Session session = login(email);
    assertThat(get(GUARDED, session.accessToken()).getStatusCode().value()).isEqualTo(200);
    doThrow(new QueryTimeoutException("db down"))
        .doThrow(new QueryTimeoutException("db down"))
        .doCallRealMethod()
        .when(userRoleAssignmentPort).findActiveUserIdsForRole(reader.getId());

    detach(admin, reader, ROLE_READ);

    awaitEpochKey(holder.getId(), Duration.ofSeconds(5));
    assertThat(get(GUARDED, session.accessToken()).getStatusCode().value()).isEqualTo(401);
  }

  private void awaitEpochKey(UUID userId, Duration within) throws InterruptedException {
    long deadline = System.nanoTime() + within.toNanos();
    while (!Boolean.TRUE.equals(redisTemplate.hasKey(epochKey(userId)))) {
      assertThat(System.nanoTime()).as("epoch key of the replayed bump").isLessThan(deadline);
      Thread.sleep(50);
    }
  }

  // ── T-010: detach fans out to every holder (TS-9) ─────────────────────────

  @Test
  void should_removePermissionFromEveryHolderIncludingAfterRefresh_when_permissionDetached() {
    Role reader = readerRole("TS9");
    RoleChangeActor admin = seedAdmin();
    List<User> holders = new ArrayList<>();
    List<Session> sessions = new ArrayList<>();
    for (int i = 0; i < 3; i++) {
      String email = "freshness-ts9-" + i + "-" + UUID.randomUUID() + "@example.com";
      User holder = activeUser(email);
      assign(holder, reader, admin);
      holders.add(holder);
      sessions.add(login(email));
    }
    for (int i = 0; i < 3; i++) {
      assertThat(redisTemplate.hasKey(permsetKey(holders.get(i).getId(), 0L)))
          .as("login warmed the holder's cache entry under epoch 0")
          .isTrue();
      assertThat(get(GUARDED, sessions.get(i).accessToken()).getStatusCode().value())
          .isEqualTo(200);
    }

    detach(admin, reader, ROLE_READ);

    for (int i = 0; i < 3; i++) {
      UUID holderId = holders.get(i).getId();
      assertThat(redisTemplate.hasKey(permsetKey(holderId, 0L)))
          .as("the bump deleted the entry under the replaced epoch")
          .isFalse();
      ResponseEntity<Map> stale = get(GUARDED, sessions.get(i).accessToken());
      assertThat(stale.getStatusCode().value()).isEqualTo(401);
      assertThat(stale.getBody()).containsEntry("code", "AUTH_003");

      ResponseEntity<Map> refreshed =
          refresh(sessions.get(i).accessToken(), sessions.get(i).refreshCookie());
      assertThat(refreshed.getStatusCode().value()).isEqualTo(200);
      String newToken = (String) refreshed.getBody().get("accessToken");
      JwtClaims claims = jwtPort.verify(newToken);
      assertThat(claims.permissions()).doesNotContain("role:read");
      assertThat(claims.permEpoch()).isEqualTo(storedEpoch(holderId));
      assertThat(get(GUARDED, newToken).getStatusCode().value())
          .as("the refreshed token is fresh and no longer carries the detached permission")
          .isEqualTo(403);
    }
  }

  /**
   * Design §9.4: a mint reads epoch E and the pre-detach permissions, the detach commits and bumps
   * to R, then the mint writes the stale set. Keying the entry by E keeps every later mint, which
   * reads R, from being served it.
   */
  @Test
  void should_notServeStaleSetAfterRefresh_when_mintRacesDetach() throws Exception {
    Role reader = readerRole("RACE");
    RoleChangeActor admin = seedAdmin();
    String email = "freshness-race-" + UUID.randomUUID() + "@example.com";
    User holder = activeUser(email);
    assign(holder, reader, admin);

    Session raced = loginRacingDetach(email, holder, admin, reader);

    JwtClaims racedClaims = jwtPort.verify(raced.accessToken());
    assertThat(racedClaims.permissions())
        .as("the paused mint read the pre-commit permissions")
        .contains("role:read");
    assertThat(redisTemplate.opsForSet().members(permsetKey(holder.getId(), 0L)))
        .as("the stale set was written back after the bump, under the old epoch")
        .contains("role:read");
    ResponseEntity<Map> stale = get(GUARDED, raced.accessToken());
    assertThat(stale.getStatusCode().value()).isEqualTo(401);
    assertThat(stale.getBody()).containsEntry("code", "AUTH_003");

    ResponseEntity<Map> refreshed = refresh(raced.accessToken(), raced.refreshCookie());
    assertThat(refreshed.getStatusCode().value()).isEqualTo(200);
    JwtClaims claims = jwtPort.verify((String) refreshed.getBody().get("accessToken"));
    assertThat(claims.permEpoch()).isEqualTo(storedEpoch(holder.getId()));
    assertThat(claims.permissions()).doesNotContain("role:read");
  }

  /**
   * RC-29.3, the first-bump race at key expiry: the racing mint read epoch 0 (no key yet), so its
   * stale set sits under {@code :0}, which is what every mint reads once the epoch key has
   * expired. The key must therefore outlive the stale entry. Redis time cannot be advanced, so the
   * test shifts both TTLs down by the same amount, lets the stale entry expire, checks the key is
   * still there, and then deletes the key to stand for its own, later expiry.
   *
   * <p>Residual risk (accepted, design §9.2): the entry's TTL starts at its write and the key's at
   * the bump, so a mint whose DB read to cache write takes 60 s or more (the key-TTL margin) leaves
   * a stale {@code :0} entry that outlives the key.
   */
  @Test
  void should_notMintRevokedPermission_when_firstBumpRaceOutlivedByEpochKey() throws Exception {
    Role reader = readerRole("RC293");
    RoleChangeActor admin = seedAdmin();
    String email = "freshness-rc293-" + UUID.randomUUID() + "@example.com";
    User holder = activeUser(email);
    assign(holder, reader, admin);
    UUID holderId = holder.getId();

    Session raced = loginRacingDetach(email, holder, admin, reader);

    assertThat(jwtPort.verify(raced.accessToken()).permEpoch()).isZero();
    List<String> staleKeys = List.of(permsetKey(holderId, 0L), rolesetKey(holderId, 0L));
    long staleTtl = redisTemplate.getExpire(permsetKey(holderId, 0L), TimeUnit.MILLISECONDS);
    long keyTtl = redisTemplate.getExpire(epochKey(holderId), TimeUnit.MILLISECONDS);
    assertThat(staleTtl).isPositive().isLessThan(keyTtl);

    long shift = staleTtl - 200;
    for (String key : staleKeys) {
      shiftTtl(key, shift);
    }
    shiftTtl(epochKey(holderId), shift);
    awaitAbsent(staleKeys);

    assertThat(redisTemplate.hasKey(epochKey(holderId)))
        .as("the epoch key outlives the stale entry written under its old epoch")
        .isTrue();
    redisTemplate.delete(epochKey(holderId));
    ResponseEntity<Map> refreshed = refresh(null, raced.refreshCookie());
    assertThat(refreshed.getStatusCode().value()).isEqualTo(200);
    JwtClaims claims = jwtPort.verify((String) refreshed.getBody().get("accessToken"));
    assertThat(claims.permEpoch()).isZero();
    assertThat(claims.permissions()).doesNotContain("role:read");
  }

  /** T-E40 (Decision 15): attach evicts the holders' entries but never bumps their epochs. */
  @Test
  void should_notStaleHolderTokens_when_permissionAttached() {
    Role reader = readerRole("ATTACH");
    RoleChangeActor admin = seedAdmin();
    String email = "freshness-attach-" + UUID.randomUUID() + "@example.com";
    User holder = activeUser(email);
    assign(holder, reader, admin);
    Session session = login(email);
    assertThat(redisTemplate.hasKey(permsetKey(holder.getId(), 0L))).isTrue();

    roleManagementService.attachPermission(admin, reader.getId(), AUDIT_READ, context());

    assertThat(redisTemplate.hasKey(epochKey(holder.getId())))
        .as("attach never bumps")
        .isFalse();
    assertThat(redisTemplate.hasKey(permsetKey(holder.getId(), 0L)))
        .as("attach evicted the holder's entry")
        .isFalse();
    assertThat(get(GUARDED, session.accessToken()).getStatusCode().value())
        .as("the holder's existing token stays fresh")
        .isEqualTo(200);
    ResponseEntity<Map> refreshed = refresh(session.accessToken(), session.refreshCookie());
    assertThat(jwtPort.verify((String) refreshed.getBody().get("accessToken")).permissions())
        .contains("role:read", "audit:read");
  }

  /**
   * Logs in on another thread and pauses that mint inside its cache write, after it read the epoch
   * and the permissions; detaches {@code role:read} from {@code reader} meanwhile; then lets the
   * mint finish.
   */
  private Session loginRacingDetach(
      String email, User holder, RoleChangeActor admin, Role reader) throws Exception {
    CountDownLatch paused = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    doAnswer(invocation -> {
      if (holder.getId().equals(invocation.getArgument(1))) {
        paused.countDown();
        assertThat(release.await(LATCH_TIMEOUT_SECONDS, TimeUnit.SECONDS)).isTrue();
      }
      return invocation.callRealMethod();
    }).when(permissionCache).put(any(), any(), anyLong(), any());
    ExecutorService minter = Executors.newSingleThreadExecutor();
    try {
      Future<Session> racing = minter.submit(() -> login(email));
      assertThat(paused.await(LATCH_TIMEOUT_SECONDS, TimeUnit.SECONDS))
          .as("the mint reached its cache write")
          .isTrue();
      detach(admin, reader, ROLE_READ);
      assertThat(storedEpoch(holder.getId())).isPositive();
      release.countDown();
      return racing.get(LATCH_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    } finally {
      release.countDown();
      minter.shutdownNow();
    }
  }

  private void shiftTtl(String key, long shiftMillis) {
    long ttl = redisTemplate.getExpire(key, TimeUnit.MILLISECONDS);
    redisTemplate.expire(key, Duration.ofMillis(ttl - shiftMillis));
  }

  private void awaitAbsent(List<String> keys) throws InterruptedException {
    long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
    while (keys.stream().anyMatch(redisTemplate::hasKey)) {
      assertThat(System.nanoTime()).as("stale entry expired within 10 s").isLessThan(deadline);
      Thread.sleep(50);
    }
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

  /** A custom role carrying {@code role:read}. */
  private Role readerRole(String tag) {
    Role reader = role(tag);
    rolePermissionRepository.save(new RolePermission(reader.getId(), ROLE_READ));
    return reader;
  }

  /**
   * An administrator for detach and attach: it holds {@code role:write} (the endpoint permission
   * A3 re-checks) and {@code audit:read} (so it may attach it).
   */
  private RoleChangeActor seedAdmin() {
    User adminUser = activeUser("freshness-admin-" + UUID.randomUUID() + "@example.com");
    Role adminRole = role("RADMIN");
    rolePermissionRepository.save(
        new RolePermission(adminRole.getId(), RbacSeededPermissionIds.ROLE_WRITE));
    rolePermissionRepository.save(new RolePermission(adminRole.getId(), AUDIT_READ));
    userRoleRepository.save(new UserRole(
        uuidGenerator.newId(), adminUser.getId(), adminRole.getId(), TENANT_ID, adminUser.getId()));
    return new RoleChangeActor(adminUser.getId(), TENANT_ID);
  }

  private void assign(User holder, Role role, RoleChangeActor admin) {
    userRoleRepository.save(new UserRole(
        uuidGenerator.newId(), holder.getId(), role.getId(), TENANT_ID, admin.userId()));
  }

  private void detach(RoleChangeActor admin, Role role, UUID permissionId) {
    roleManagementService.detachPermission(admin, role.getId(), permissionId, context());
  }

  private static RequestContext context() {
    return RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "JUnit");
  }

  private String permsetKey(UUID userId, long epoch) {
    return keyPrefix + ":rbac:permset:" + TENANT_ID + ":" + userId + ":" + epoch;
  }

  private String rolesetKey(UUID userId, long epoch) {
    return keyPrefix + ":rbac:roleset:" + TENANT_ID + ":" + userId + ":" + epoch;
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
