package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.UserDirectoryService;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
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
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * US-019 T-004/T-005 (design §4.2–§4.4, §4.7): the user directory's list, batch, by-id and
 * exact-email lookup reads through the real server and filter chain against MySQL, with two
 * tenants. Each test seeds fresh tenants, so the tests are independent of each other and of the
 * migration seed.
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
      "nexus.identity.encryption.password=test-enc-password-32-chars-long!!",
      "nexus.identity.encryption.salt=cafebabecafebabecafebabecafebabe",
      "nexus.identity.hmac-key=test-not-a-secret-hmac-key-min-32-bytes!!",
      "nexus.identity.default-tenant-id=00000000-0000-7000-8000-000000000001"
    })
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class UserDirectoryIT {

  private static final Set<String> ENTRY_FIELDS =
      Set.of("userId", "email", "status", "emailVerified", "createdAt");
  private static final ObjectMapper JSON = JsonMapper.builder().build();

  @Value("${local.server.port}")
  private int port;

  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JwtPort jwtPort;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private EmailBlindIndexService blindIndex;

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

  // ── list ──────────────────────────────────────────────────────────────────────────────

  @Test
  void should_listOnlyTheCallersTenantIncludingDisabledUsers_when_listing() {
    Tenant a = tenantWithReader();
    User active = seedUser(a.id(), "active", true);
    User disabled = seedUser(a.id(), "disabled", false);
    jdbc.update("UPDATE users SET status = 'DISABLED' WHERE id = ?", (Object) toBytes(disabled.getId()));
    Tenant b = tenantWithReader();
    seedUser(b.id(), "foreign", true);

    ResponseEntity<String> response = get(a.token(), "/api/v1/users?size=100");

    assertThat(response.getStatusCode().value()).isEqualTo(200);
    JsonNode body = JSON.readTree(response.getBody());
    Map<String, String> statusById = new HashMap<>();
    body.get("data").forEach(e -> statusById.put(e.get("userId").asString(), e.get("status").asString()));
    assertThat(statusById)
        .containsOnlyKeys(
            a.reader().getId().toString(), active.getId().toString(), disabled.getId().toString())
        .containsEntry(disabled.getId().toString(), "DISABLED");
    assertThat(body.get("page").get("totalElements").asLong()).isEqualTo(3);
  }

  @Test
  void should_filterByStatusAndEchoItInLinks_when_statusIsGiven() {
    Tenant a = tenantWithReader();
    User first = seedUser(a.id(), "first", true);
    User second = seedUser(a.id(), "second", true);

    ResponseEntity<String> response = get(a.token(), "/api/v1/users?status=ACTIVE&page=0&size=1");

    JsonNode body = JSON.readTree(response.getBody());
    assertThat(body.get("data")).hasSize(1);
    assertThat(body.get("data").get(0).get("userId").asString())
        .isIn(first.getId().toString(), second.getId().toString(), a.reader().getId().toString());
    assertThat(body.get("links").get("next").asString())
        .isEqualTo("/api/v1/users?status=ACTIVE&page=1&size=1");
    assertThat(body.get("links").get("prev").isNull()).isTrue();
  }

  @Test
  void should_serializeExactlyTheFiveFields_when_listingAndReadingById() {
    Tenant a = tenantWithReader();
    User active = seedUser(a.id(), "five-fields", true);

    JsonNode listed = JSON.readTree(get(a.token(), "/api/v1/users").getBody());
    JsonNode byId = JSON.readTree(get(a.token(), "/api/v1/users/" + active.getId()).getBody());

    listed.get("data").forEach(entry -> assertThat(keys(entry)).isEqualTo(new TreeSet<>(ENTRY_FIELDS)));
    assertThat(keys(byId)).isEqualTo(new TreeSet<>(ENTRY_FIELDS));
    assertThat(byId.get("email").asString()).isEqualTo(active.getEmailCipher().value());
    assertThat(byId.get("status").asString()).isEqualTo("ACTIVE");
    assertThat(byId.get("emailVerified").asBoolean()).isTrue();
    assertThat(Instant.parse(byId.get("createdAt").asString())).isNotNull();
  }

  // ── by id ─────────────────────────────────────────────────────────────────────────────

  @Test
  void should_answerByteIdenticalNotFound_when_theIdIsForeignOrMissing() {
    Tenant a = tenantWithReader();
    Tenant b = tenantWithReader();
    User foreign = seedUser(b.id(), "foreign", true);

    ResponseEntity<String> crossTenant = get(a.token(), "/api/v1/users/" + foreign.getId());
    ResponseEntity<String> missing = get(a.token(), "/api/v1/users/" + uuidGenerator.newId());

    assertThat(crossTenant.getStatusCode().value()).isEqualTo(404).isEqualTo(missing.getStatusCode().value());
    assertThat(JSON.readTree(crossTenant.getBody()).get("code").asString()).isEqualTo("USER_NOT_FOUND");
    assertThat(normalised(crossTenant.getBody())).isEqualTo(normalised(missing.getBody()));
  }

  // ── batch ─────────────────────────────────────────────────────────────────────────────

  @Test
  void should_returnAnUnchangedResponseAndWarnBatch_when_aBatchCarriesAForeignId() {
    Tenant a = tenantWithReader();
    User own = seedUser(a.id(), "own", true);
    Tenant b = tenantWithReader();
    User foreign = seedUser(b.id(), "foreign", true);

    ResponseEntity<String> ownOnly = get(a.token(), "/api/v1/users?ids=" + own.getId());
    ListAppender<ILoggingEvent> appender = startLogCapture();
    ResponseEntity<String> withForeign;
    try {
      withForeign = get(a.token(), "/api/v1/users?ids=" + own.getId() + "," + foreign.getId());
    } finally {
      stopLogCapture(appender);
    }

    assertThat(withForeign.getStatusCode().value()).isEqualTo(200);
    assertThat(withForeign.getBody()).isEqualTo(ownOnly.getBody());
    assertThat(JSON.readTree(withForeign.getBody()).get("page").toString())
        .isEqualTo("{\"size\":1,\"number\":0,\"totalElements\":1,\"totalPages\":1}");
    assertThat(appender.list)
        .filteredOn(e -> e.getLevel() == Level.WARN)
        .singleElement()
        .satisfies(
            event ->
                assertThat(keyValues(event))
                    .containsEntry("event", "IDENTITY_DIRECTORY_CROSS_TENANT_TARGET")
                    .containsEntry("operation", "BATCH")
                    .containsEntry("omittedCount", 1L));
  }

  // ── validation ────────────────────────────────────────────────────────────────────────

  @Test
  void should_return400ValidationFailed_when_paramsAreOutOfBounds() {
    Tenant a = tenantWithReader();
    String hundredAndOneIds =
        IntStream.range(0, 101).mapToObj(i -> uuidGenerator.newId().toString()).collect(Collectors.joining(","));
    List<String> uris =
        List.of(
            "/api/v1/users?size=101",
            "/api/v1/users?ids=" + hundredAndOneIds,
            "/api/v1/users?email=sentinel-local@example.test",
            "/api/v1/users?page=101&size=100",
            "/api/v1/users?status=active",
            "/api/v1/users?ids=" + a.reader().getId() + "&status=ACTIVE",
            "/api/v1/users/not-a-uuid");

    List<String> failures = new ArrayList<>();
    for (String uri : uris) {
      ResponseEntity<String> response = get(a.token(), uri);
      String code = response.getBody() == null ? null : JSON.readTree(response.getBody()).path("code").asString();
      if (response.getStatusCode().value() != 400 || !"VALIDATION_FAILED".equals(code)) {
        failures.add(uri + " -> " + response.getStatusCode().value() + " " + code);
      }
      assertThat(response.getBody()).doesNotContain("sentinel-local");
    }
    assertThat(failures).isEmpty();
  }

  // ── lookup ────────────────────────────────────────────────────────────────────────────

  @Test
  void should_returnTheOneEntryWithTheFiveFields_when_theEmailMatchesAUserOfTheTenant() {
    Tenant a = tenantWithReader();
    User target = seedUserWithEmail(a.id(), "lookup-hit-" + UUID.randomUUID() + "@example.test");

    ResponseEntity<String> response = lookup(a.token(), emailBody(target.getEmailCipher().value()));

    assertThat(response.getStatusCode().value()).isEqualTo(200);
    JsonNode data = JSON.readTree(response.getBody()).get("data");
    assertThat(data).hasSize(1);
    assertThat(keys(data.get(0))).isEqualTo(new TreeSet<>(ENTRY_FIELDS));
    assertThat(data.get(0).get("userId").asString()).isEqualTo(target.getId().toString());
    assertThat(keys(JSON.readTree(response.getBody()))).containsExactly("data");
  }

  @Test
  void should_answerByteIdenticalEmptyData_when_theEmailIsMissingOrBelongsToAnotherTenant() {
    Tenant a = tenantWithReader();
    Tenant b = tenantWithReader();
    User foreign = seedUserWithEmail(b.id(), "lookup-foreign-" + UUID.randomUUID() + "@example.test");

    ResponseEntity<String> otherTenantHit = lookup(a.token(), emailBody(foreign.getEmailCipher().value()));
    ResponseEntity<String> miss =
        lookup(a.token(), emailBody("lookup-missing-" + UUID.randomUUID() + "@example.test"));

    assertThat(otherTenantHit.getStatusCode().value()).isEqualTo(200).isEqualTo(miss.getStatusCode().value());
    assertThat(otherTenantHit.getBody()).isEqualTo("{\"data\":[]}").isEqualTo(miss.getBody());
  }

  @Test
  void should_hit_when_theEmailDiffersOnlyInCaseWhitespaceOrUnicodeNormalisation() {
    Tenant a = tenantWithReader();
    String suffix = UUID.randomUUID().toString().substring(0, 8);
    // Stored in NFC (precomposed U+00E9); one variant sends the NFD form (e + U+0301).
    User target = seedUserWithEmail(a.id(), "jos\u00e9-" + suffix + "@example.test");
    List<String> variants =
        List.of(
            "JOS\u00c9-" + suffix.toUpperCase(Locale.ROOT) + "@EXAMPLE.TEST",
            "  jos\u00e9-" + suffix + "@example.test\t",
            "jose\u0301-" + suffix + "@example.test");

    for (String variant : variants) {
      ResponseEntity<String> response = lookup(a.token(), emailBody(variant));
      assertThat(response.getStatusCode().value()).as(variant).isEqualTo(200);
      JsonNode data = JSON.readTree(response.getBody()).get("data");
      assertThat(data).as(variant).hasSize(1);
      assertThat(data.get(0).get("userId").asString()).isEqualTo(target.getId().toString());
    }
  }

  @Test
  void should_return400ValidationFailedWithoutEchoingTheValue_when_theLookupBodyIsInvalid() {
    Tenant a = tenantWithReader();
    String tooLong = "sentinel-local" + "a".repeat(321 - 14 - "@example.test".length()) + "@example.test";
    String oversized = "{\"email\":\"sentinel-local@example.test\"" + " ".repeat(1100) + "}";
    Map<String, String> bodies =
        Map.of(
            "blank", emailBody("   "),
            "321 characters", emailBody(tooLong),
            "malformed", emailBody("sentinel-local-at-example.test"),
            "over 1 KiB", oversized,
            "missing email", "{}");
    assertThat(tooLong).hasSize(321);
    assertThat(oversized.getBytes(StandardCharsets.UTF_8).length).isGreaterThan(1024);

    List<String> failures = new ArrayList<>();
    bodies.forEach(
        (name, body) -> {
          ResponseEntity<String> response = lookup(a.token(), body);
          String code = response.getBody() == null ? null : JSON.readTree(response.getBody()).path("code").asString();
          if (response.getStatusCode().value() != 400 || !"VALIDATION_FAILED".equals(code)) {
            failures.add(name + " -> " + response.getStatusCode().value() + " " + code);
          }
          assertThat(response.getBody()).as(name).doesNotContain("sentinel-local");
        });
    assertThat(failures).isEmpty();
  }

  @Test
  void should_return400_when_aChunkedBodyWithoutContentLengthExceeds1KiB() throws Exception {
    Tenant a = tenantWithReader();
    byte[] oversized =
        ("{\"email\":\"sentinel-local@example.test\"" + " ".repeat(1100) + "}")
            .getBytes(StandardCharsets.UTF_8);
    HttpRequest request =
        HttpRequest.newBuilder(
                URI.create("http://localhost:" + port + "/api/v1/users/lookup"))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + a.token())
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .POST(
                HttpRequest.BodyPublishers.ofInputStream(
                    () -> new ByteArrayInputStream(oversized)))
            .build();

    HttpResponse<String> response;
    try (HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build()) {
      response = client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    assertThat(response.statusCode()).isEqualTo(400);
    assertThat(JSON.readTree(response.body()).path("code").asString()).isEqualTo("VALIDATION_FAILED");
    assertThat(response.body()).doesNotContain("sentinel-local");
  }

  @Test
  void should_return415_when_theLookupBodyIsNotJson() {
    Tenant a = tenantWithReader();
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(a.token());
    headers.setContentType(MediaType.TEXT_PLAIN);

    ResponseEntity<String> response =
        restTemplate.exchange(
            "http://localhost:" + port + "/api/v1/users/lookup",
            HttpMethod.POST,
            new HttpEntity<>(emailBody("sentinel-local@example.test"), headers),
            String.class);

    assertThat(response.getStatusCode().value()).isEqualTo(415);
    assertThat(response.getBody()).doesNotContain("sentinel-local");
  }

  // ── decryption failure ────────────────────────────────────────────────────────────────

  @Test
  void should_return500WithNoPartialPage_when_anEmailCipherIsTampered() {
    Tenant a = tenantWithReader();
    User tampered = seedUser(a.id(), "tampered", true);
    jdbc.update(
        "UPDATE users SET email_cipher = 'not-a-valid-ciphertext' WHERE id = ?",
        (Object) toBytes(tampered.getId()));

    ResponseEntity<String> response = get(a.token(), "/api/v1/users");

    assertThat(response.getStatusCode().value()).isEqualTo(500);
    JsonNode body = JSON.readTree(response.getBody());
    assertThat(body.path("code").asString()).isEqualTo("INTERNAL_ERROR");
    assertThat(body.has("data")).isFalse();
  }

  // ── plan and headers ──────────────────────────────────────────────────────────────────

  @Test
  void should_useTheTenantStatusIndex_when_theListIsFilteredByStatus() {
    Tenant a = tenantWithReader();
    for (int i = 0; i < 5; i++) {
      seedUser(a.id(), "plan-" + i, true);
    }

    // With a handful of rows the optimizer prefers PRIMARY by cost, which says nothing about the
    // index. FORCE INDEX proves what the design needs: the (tenant_id, status) index returns rows
    // already ordered by id (the implicit primary-key suffix), so no filesort is needed.
    List<Map<String, Object>> plan =
        jdbc.queryForList(
            "EXPLAIN SELECT * FROM users FORCE INDEX (idx_users_tenant_id_status)"
                + " WHERE tenant_id = ? AND status = ? ORDER BY id LIMIT 20",
            toBytes(a.id()),
            "ACTIVE");

    assertThat(plan).singleElement().satisfies(row -> {
      assertThat(row.get("key")).isEqualTo("idx_users_tenant_id_status");
      assertThat(String.valueOf(row.get("Extra"))).doesNotContain("filesort");
    });
  }

  @Test
  void should_keepTheDefaultNoStoreCacheControl_when_aDirectoryRouteAnswers() {
    Tenant a = tenantWithReader();

    ResponseEntity<String> list = get(a.token(), "/api/v1/users");
    ResponseEntity<String> byId = get(a.token(), "/api/v1/users/" + a.reader().getId());

    assertThat(list.getHeaders().getCacheControl()).contains("no-store");
    assertThat(byId.getHeaders().getCacheControl()).contains("no-store");
  }

  // ── fixtures ──────────────────────────────────────────────────────────────────────────

  private record Tenant(UUID id, User reader, String token) {}

  /** A fresh tenant with one ACTIVE user holding {@code user:directory:read} through a custom role. */
  private Tenant tenantWithReader() {
    UUID tenantId = uuidGenerator.newId();
    User reader = seedUser(tenantId, "reader", true);
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, "DIR-READER-" + UUID.randomUUID(), null, false));
    rolePermissionRepository.save(
        new RolePermission(role.getId(), RbacSeededPermissionIds.USER_DIRECTORY_READ));
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), reader.getId(), role.getId(), tenantId, reader.getId()));
    return new Tenant(tenantId, reader, jwtPort.issue(reader).token());
  }

  private User seedUser(UUID tenantId, String tag, boolean verified) {
    String email = "dir-" + tag + "-" + UUID.randomUUID() + "@example.test";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user = new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    if (verified) {
      user.verify(Instant.now().truncatedTo(ChronoUnit.MICROS));
    }
    return userRepository.save(user);
  }

  private User seedUserWithEmail(UUID tenantId, String email) {
    User user =
        new User(
            uuidGenerator.newId(), tenantId, new EmailCipher(email), blindIndex.blindIndex(email), "test-hash", null);
    user.verify(Instant.now().truncatedTo(ChronoUnit.MICROS));
    return userRepository.save(user);
  }

  private ResponseEntity<String> lookup(String token, String body) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    headers.setContentType(MediaType.APPLICATION_JSON);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/users/lookup",
        HttpMethod.POST,
        new HttpEntity<>(body, headers),
        String.class);
  }

  private static String emailBody(String email) {
    return JSON.writeValueAsString(Map.of("email", email));
  }

  private ResponseEntity<String> get(String token, String uri) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    return restTemplate.exchange(
        "http://localhost:" + port + uri, HttpMethod.GET, new HttpEntity<>(headers), String.class);
  }

  /** Byte equality apart from the per-request {@code traceId} and per-path {@code instance} (T-I25). */
  private static String normalised(String body) {
    return body.replaceAll("\"traceId\":\"[^\"]*\"", "\"traceId\":\"-\"")
        .replaceAll("\"instance\":\"[^\"]*\"", "\"instance\":\"-\"");
  }

  private static Set<String> keys(JsonNode node) {
    return new TreeSet<>(node.propertyNames());
  }

  private static ListAppender<ILoggingEvent> startLogCapture() {
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    ((Logger) LoggerFactory.getLogger(UserDirectoryService.class)).addAppender(appender);
    return appender;
  }

  private static void stopLogCapture(ListAppender<ILoggingEvent> appender) {
    ((Logger) LoggerFactory.getLogger(UserDirectoryService.class)).detachAppender(appender);
    appender.stop();
  }

  private static Map<String, Object> keyValues(ILoggingEvent event) {
    Map<String, Object> map = new HashMap<>();
    if (event.getKeyValuePairs() != null) {
      event.getKeyValuePairs().forEach(kv -> map.put(kv.key, kv.value));
    }
    return map;
  }

  private static byte[] toBytes(UUID uuid) {
    return ByteBuffer.allocate(16)
        .putLong(uuid.getMostSignificantBits())
        .putLong(uuid.getLeastSignificantBits())
        .array();
  }
}
