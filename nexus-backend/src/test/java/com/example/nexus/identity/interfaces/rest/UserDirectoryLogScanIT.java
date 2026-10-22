package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.EmailBlindIndexService;
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
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/*
 * US-019 T-005 (design §4.5, NF-S5): the per-actor lookup throttle of 30 per 60 s through the
 * real server. The 31st lookup gets 429 {@code USER_DIR_001} with {@code Retry-After}, and a burst
 * of rejections leaves exactly one WARN {@code IDENTITY_DIRECTORY_THROTTLED}, the exception handler
 * logging each rejection at DEBUG only. Same context configuration as {@link UserDirectoryIT}.
 */

/**
 * US-019 T-006 (design §4.7, RC-59.2, NF-O3): a lookup with a sentinel email, a list, a by-id read
 * and a batch, then the malformed lookup bodies, leave neither the sentinel, its local part, any
 * blind index nor a seeded email in the console output or in the audit rows. Same context
 * configuration as {@link UserDirectoryLookupThrottleIT}.
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
@ExtendWith(OutputCaptureExtension.class)
class UserDirectoryLogScanIT {

  private static final String SENTINEL_LOCAL = "sentinel.zq7x9k";
  private static final String SENTINEL = SENTINEL_LOCAL + "@example.test";

  @Value("${local.server.port}")
  private int port;

  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JwtPort jwtPort;
  @Autowired private EmailBlindIndexService blindIndexService;
  @Autowired private JdbcTemplate jdbc;

  @Test
  void should_leaveNoEmailLocalPartOrBlindIndexInLogsOrAudit_when_readingAndSendingMalformedLookups(
      CapturedOutput output) {
    UUID tenantId = uuidGenerator.newId();
    String seededEmail = "seeded.zq7x9k-" + UUID.randomUUID() + "@example.test";
    User seeded = user(tenantId, seededEmail);
    user(tenantId, SENTINEL);
    String token = readerToken(tenantId);

    List<Integer> statuses = new ArrayList<>();
    statuses.add(post(token, MediaType.APPLICATION_JSON, "{\"email\": \"" + SENTINEL + "\"}"));
    statuses.add(get(token, "/api/v1/users?size=5"));
    statuses.add(get(token, "/api/v1/users/" + seeded.getId()));
    statuses.add(get(token, "/api/v1/users?ids=" + seeded.getId()));
    List<Integer> rejected = new ArrayList<>();
    rejected.add(post(token, MediaType.APPLICATION_JSON, "{\"email\": " + SENTINEL + "}"));
    rejected.add(post(token, MediaType.APPLICATION_JSON, "{\"email\": [\"" + SENTINEL + "\"]}"));
    rejected.add(post(token, MediaType.APPLICATION_JSON, "{\"email\": \"" + SENTINEL));
    rejected.add(post(token, MediaType.TEXT_PLAIN, "{\"email\": \"" + SENTINEL + "\"}"));
    rejected.add(
        post(
            token,
            MediaType.APPLICATION_JSON,
            "{\"email\": \"" + SENTINEL_LOCAL + "x".repeat(1100) + "@example.test\"}"));

    assertThat(statuses).containsOnly(200);
    assertThat(rejected).containsExactly(400, 400, 400, 415, 400);
    String logs = output.getAll().toLowerCase();
    assertThat(logs).as("the console output of the run").contains("directory read");
    assertThat(logs)
        .doesNotContain(SENTINEL_LOCAL, seededEmail.toLowerCase(), "seeded.zq7x9k")
        .doesNotContain(blindIndexService.blindIndex(SENTINEL))
        .doesNotContain(blindIndexService.blindIndex(seededEmail));
    List<String> auditRows =
        jdbc.queryForList(
            "SELECT metadata FROM auth_events WHERE event_type = 'USER_DIRECTORY_READ'"
                + " AND tenant_id = ?",
            String.class,
            toBytes(tenantId));
    assertThat(auditRows).hasSize(4);
    assertThat(String.join(" ", auditRows).toLowerCase())
        .doesNotContain(SENTINEL_LOCAL, "seeded.zq7x9k", blindIndexService.blindIndex(SENTINEL));
  }

  private User user(UUID tenantId, String email) {
    String hmac = blindIndexService.blindIndex(email);
    return userRepository.save(
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  private String readerToken(UUID tenantId) {
    User reader = user(tenantId, "dir-logscan-reader-" + UUID.randomUUID() + "@example.test");
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, "DIR-READER-" + UUID.randomUUID(), null, false));
    rolePermissionRepository.save(
        new RolePermission(role.getId(), RbacSeededPermissionIds.USER_DIRECTORY_READ));
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), reader.getId(), role.getId(), tenantId, reader.getId()));
    return jwtPort.issue(reader).token();
  }

  private int post(String token, MediaType contentType, String body) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    headers.setContentType(contentType);
    return exchange("/api/v1/users/lookup", HttpMethod.POST, new HttpEntity<>(body, headers));
  }

  private int get(String token, String path) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    return exchange(path, HttpMethod.GET, new HttpEntity<>(headers));
  }

  private int exchange(String path, HttpMethod method, HttpEntity<String> entity) {
    RestTemplate restTemplate = new RestTemplate();
    restTemplate.setErrorHandler(
        new DefaultResponseErrorHandler() {
          @Override
          public boolean hasError(ClientHttpResponse response) {
            return false;
          }
        });
    return restTemplate
        .exchange("http://localhost:" + port + path, method, entity, String.class)
        .getStatusCode()
        .value();
  }

  private static byte[] toBytes(UUID id) {
    return java.nio.ByteBuffer.allocate(16)
        .putLong(id.getMostSignificantBits())
        .putLong(id.getLeastSignificantBits())
        .array();
  }
}
