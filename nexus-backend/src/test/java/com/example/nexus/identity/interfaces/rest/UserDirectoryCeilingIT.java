package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.DirectoryAccessGuard;
import com.example.nexus.common.web.GlobalExceptionHandler;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * US-019 T-005 (design §4.5, NF-S5): the per-actor lookup throttle of 30 per 60 s through the
 * real server. The 31st lookup gets 429 {@code USER_DIR_001} with {@code Retry-After}, and a burst
 * of rejections leaves exactly one WARN {@code IDENTITY_DIRECTORY_THROTTLED}, the exception handler
 * logging each rejection at DEBUG only. Same context configuration as {@link UserDirectoryIT}.
 */

/**
 * US-019 T-006 (design §4.5, RC-61.3): the per-actor ceiling of 600 directory requests per 60 s
 * through the real server. The 601st request gets 429 {@code USER_DIR_002} with {@code Retry-After},
 * and a burst of rejections leaves exactly one WARN. Same context configuration as {@link
 * UserDirectoryLookupThrottleIT}.
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
class UserDirectoryCeilingIT {

  private static final int CEILING = 600;
  private static final ObjectMapper JSON = JsonMapper.builder().build();

  @Value("${local.server.port}")
  private int port;

  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JwtPort jwtPort;

  @Test
  void should_return429UserDir002WithRetryAfterAndWarnOnce_when_theActorExceeds600RequestsInAWindow() {
    String token = readerToken();
    UUID absent = uuidGenerator.newId();
    List<Integer> permittedStatuses = new ArrayList<>();
    for (int i = 0; i < CEILING; i++) {
      permittedStatuses.add(getUser(token, absent).getStatusCode().value());
    }

    ListAppender<ILoggingEvent> guard = capture(DirectoryAccessGuard.class);
    ListAppender<ILoggingEvent> handler = capture(GlobalExceptionHandler.class);
    List<ResponseEntity<String>> rejected = new ArrayList<>();
    try {
      for (int i = 0; i < 3; i++) {
        rejected.add(getUser(token, absent));
      }
    } finally {
      release(DirectoryAccessGuard.class, guard);
      release(GlobalExceptionHandler.class, handler);
    }

    assertThat(permittedStatuses).containsOnly(404);
    ResponseEntity<String> first = rejected.getFirst();
    assertThat(first.getStatusCode().value()).isEqualTo(429);
    assertThat(JSON.readTree(first.getBody()).path("code").asString()).isEqualTo("USER_DIR_002");
    assertThat(Long.parseLong(first.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)))
        .isGreaterThanOrEqualTo(1);
    assertThat(rejected).allSatisfy(r -> assertThat(r.getStatusCode().value()).isEqualTo(429));
    assertThat(guard.list)
        .filteredOn(e -> e.getLevel() == Level.WARN)
        .singleElement()
        .satisfies(
            e ->
                assertThat(keyValues(e))
                    .containsEntry("event", "IDENTITY_DIRECTORY_THROTTLED")
                    .containsEntry("bucket", "DIR_ALL"));
    assertThat(handler.list).noneMatch(e -> e.getLevel().isGreaterOrEqual(Level.WARN));
  }

  private String readerToken() {
    UUID tenantId = uuidGenerator.newId();
    String email = "dir-ceiling-reader-" + UUID.randomUUID() + "@example.test";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User reader =
        userRepository.save(
            new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, "DIR-READER-" + UUID.randomUUID(), null, false));
    rolePermissionRepository.save(
        new RolePermission(role.getId(), RbacSeededPermissionIds.USER_DIRECTORY_READ));
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), reader.getId(), role.getId(), tenantId, reader.getId()));
    return jwtPort.issue(reader).token();
  }

  private ResponseEntity<String> getUser(String token, UUID id) {
    RestTemplate restTemplate = new RestTemplate();
    restTemplate.setErrorHandler(
        new DefaultResponseErrorHandler() {
          @Override
          public boolean hasError(ClientHttpResponse response) {
            return false;
          }
        });
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    return restTemplate.exchange(
        "http://localhost:" + port + "/api/v1/users/" + id,
        HttpMethod.GET,
        new HttpEntity<>(headers),
        String.class);
  }

  private static ListAppender<ILoggingEvent> capture(Class<?> type) {
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    ((Logger) LoggerFactory.getLogger(type)).addAppender(appender);
    return appender;
  }

  private static void release(Class<?> type, ListAppender<ILoggingEvent> appender) {
    ((Logger) LoggerFactory.getLogger(type)).detachAppender(appender);
    appender.stop();
  }

  private static Map<String, Object> keyValues(ILoggingEvent event) {
    Map<String, Object> map = new HashMap<>();
    if (event.getKeyValuePairs() != null) {
      event.getKeyValuePairs().forEach(kv -> map.put(kv.key, kv.value));
    }
    return map;
  }
}
