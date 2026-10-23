package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaAuthEventRepository;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.RbacSeededPermissionIds;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * US-019 audit gap (test audit, open gap 3): the directory read is best-effort about its audit row
 * (design §4.5). This forces the {@code auth_events} write to fail through the real server, filter
 * chain, service and {@code SecureEventService}, and asserts the read still answers 200 with its
 * data. (The port's own catch and counter are not reached on a store outage: {@code
 * SecureEventService.recordEvent} is itself best-effort and buffers the row for retry; the counter
 * covers serialisation failures, which {@code DirectoryReadAuthEventAdapterTest} pins.)
 *
 * <p>Own class because the {@code @MockitoSpyBean} gives it its own application context.
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
class UserDirectoryAuditFailureIT {

  @Value("${local.server.port}")
  private int port;

  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaRolePermissionRepository rolePermissionRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JwtPort jwtPort;
  @MockitoSpyBean private JpaAuthEventRepository authEventRepository;

  @AfterEach
  void restoreAuditStore() {
    Mockito.reset(authEventRepository);
  }

  @Test
  void should_answer200WithTheData_when_theAuditStoreRejectsTheRowWrite() {
    UUID tenantId = uuidGenerator.newId();
    User reader = seedUser(tenantId);
    grantDirectoryRead(tenantId, reader);
    String token = jwtPort.issue(reader).token();
    doThrow(new TransientDataAccessResourceException("simulated audit-store outage"))
        .when(authEventRepository)
        .save(any());

    ResponseEntity<String> response = get(token, "/api/v1/users/" + reader.getId());

    assertThat(response.getStatusCode().value()).isEqualTo(200);
    assertThat(response.getBody()).contains(reader.getId().toString());
    verify(authEventRepository, atLeastOnce()).save(any());
  }

  private void grantDirectoryRead(UUID tenantId, User reader) {
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantId, "DIR-READER-" + UUID.randomUUID(), null, false));
    rolePermissionRepository.save(
        new RolePermission(role.getId(), RbacSeededPermissionIds.USER_DIRECTORY_READ));
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), reader.getId(), role.getId(), tenantId, reader.getId()));
  }

  private User seedUser(UUID tenantId) {
    String email = "dir-audit-fail-" + UUID.randomUUID() + "@example.test";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user = new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    user.verify(Instant.now().truncatedTo(ChronoUnit.MICROS));
    return userRepository.save(user);
  }

  private ResponseEntity<String> get(String token, String uri) {
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
        "http://localhost:" + port + uri, HttpMethod.GET, new HttpEntity<>(headers), String.class);
  }
}
