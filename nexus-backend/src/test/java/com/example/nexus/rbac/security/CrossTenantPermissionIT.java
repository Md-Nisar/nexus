package com.example.nexus.rbac.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRolePermissionRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import com.example.nexus.support.web.GuardedTestControllerConfig;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
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
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * US-011/T-014 (design threat-model T-02): end-to-end proof, through the real embedded server and
 * production filter chain (no MockMvc), that {@link
 * com.example.nexus.common.security.TenantAwarePermissionEvaluator} never lets a permission
 * granted in one tenant leak into a request authenticated under a different tenant — because the
 * JWT's {@code permissions} claim is resolved once, at mint time, against the token's own {@code
 * tenant_id} ({@code JwtRs256Service#issue}), and the evaluator trusts that claim verbatim rather
 * than re-querying RBAC state per-request.
 *
 * <p>Both tests share one seed: user U is a real, persisted {@link User} in the migration-seeded
 * bootstrap tenant (tenant A), holding the migration-seeded {@code MEMBER} role there (grants
 * {@code user:read} only). U is separately granted a custom role in a freshly generated tenant B
 * that carries {@code tenant:write} — the permission {@link
 * com.example.nexus.support.web.GuardedTestController#guarded()} requires.
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "nexus.identity.encryption.password=test-enc-password-32-chars-long!!",
        "nexus.identity.encryption.salt=cafebabecafebabecafebabecafebabe",
        "nexus.identity.hmac-key=test-not-a-secret-hmac-key-min-32-bytes!!",
        "nexus.identity.default-tenant-id=00000000-0000-7000-8000-000000000001"
    })
@Import({TestcontainersConfiguration.class, GuardedTestControllerConfig.class})
@ActiveProfiles("test")
class CrossTenantPermissionIT {

  // Seeded literals — V5__rbac_schema.sql header comment.
  private static final UUID BOOTSTRAP_TENANT_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final UUID MEMBER_ROLE_ID =
      UUID.fromString("019f6839-1811-7000-8000-00000000000b");
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

  private RestTemplate restTemplate;

  @BeforeEach
  void setUp() {
    restTemplate = new RestTemplate();
    // Suppress RestTemplate's default behaviour of throwing on 4xx/5xx so we can assert the
    // status directly (mirrors RegistrationControllerIT).
    restTemplate.setErrorHandler(
        new DefaultResponseErrorHandler() {
          @Override
          public boolean hasError(ClientHttpResponse response) {
            return false;
          }
        });
  }

  @Test
  @SuppressWarnings("rawtypes")
  void should_return403WithRbac001_when_tokenMintedInDifferentTenantThanThePermissionGrant() {
    Seed seed = seedUserWithCrossTenantGrants();

    String tokenA = jwtPort.issue(seed.user()).token();

    ResponseEntity<Map> resp = getGuarded(tokenA, Map.class);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(resp.getBody()).containsEntry("code", "RBAC_001");
    assertThat(resp.getBody()).containsEntry("requiredPermission", "tenant:write");
  }

  @Test
  void should_return200_when_tokenMintedForTheTenantWherePermissionIsGranted() {
    Seed seed = seedUserWithCrossTenantGrants();
    User userA = seed.user();

    // Unpersisted value object sharing U's id, but tenantId=tenantB — JwtRs256Service.issue only
    // reads getId(), getTenantId(), getStatus(), getTokenVersion(), none of which require
    // persistence, so this never needs to be saved.
    User userInTenantB =
        new User(
            userA.getId(),
            seed.tenantB(),
            userA.getEmailCipher(),
            userA.getEmailHmac(),
            userA.getPasswordHash(),
            null);

    String tokenB = jwtPort.issue(userInTenantB).token();

    ResponseEntity<Void> resp = getGuarded(tokenB, Void.class);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  // ── Shared seeding ──────────────────────────────────────────────────

  /** The persisted user U and the freshly generated tenant B in which U's second role was granted. */
  private record Seed(User user, UUID tenantB) {}

  /**
   * Persists user U in tenant A with the migration-seeded {@code MEMBER} role ({@code user:read}
   * only), then grants U a custom role in a freshly generated tenant B carrying {@code
   * tenant:write}.
   */
  private Seed seedUserWithCrossTenantGrants() {
    String email = "cross-tenant-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        userRepository.save(
            new User(
                uuidGenerator.newId(),
                BOOTSTRAP_TENANT_ID,
                new EmailCipher(email),
                hmac,
                "test-hash",
                null));

    userRoleRepository.save(
        new UserRole(
            uuidGenerator.newId(), user.getId(), MEMBER_ROLE_ID, BOOTSTRAP_TENANT_ID,
            user.getId()));

    UUID tenantB = uuidGenerator.newId();
    Role roleB =
        roleRepository.save(
            new Role(uuidGenerator.newId(), tenantB, "CROSS_TENANT_WRITER", null, false));
    rolePermissionRepository.save(new RolePermission(roleB.getId(), TENANT_WRITE_PERMISSION_ID));
    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), user.getId(), roleB.getId(), tenantB, user.getId()));

    return new Seed(user, tenantB);
  }

  // ── HTTP helper ──────────────────────────────────────────────────────

  private <T> ResponseEntity<T> getGuarded(String bearerToken, Class<T> responseType) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(bearerToken);
    return restTemplate.exchange(
        "http://localhost:" + port + "/internal-test/guarded",
        HttpMethod.GET,
        new HttpEntity<>(headers),
        responseType);
  }
}
