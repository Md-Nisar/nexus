package com.example.nexus.identity.application.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.TokenGenerator;
import com.example.nexus.identity.application.TokenHasher;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.application.port.out.PasswordHasherPort;
import com.example.nexus.identity.application.port.out.RefreshTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.identity.domain.LoginResult;
import com.example.nexus.identity.domain.RefreshToken;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * US-010 AC6/Test Scenario 6: a role assigned after the original login is reflected in the next
 * {@code POST /api/v1/auth/refresh}-issued access token — proving {@link RefreshTokenUseCase}'s
 * existing {@code jwtPort.issue(user)} call (unchanged by this story) automatically re-resolves
 * roles/permissions on every refresh, since {@link
 * com.example.nexus.identity.infrastructure.security.JwtRs256Service#issue} now calls {@code
 * RoleResolutionService} fresh each time.
 *
 * <p>Runs against a real Testcontainers Redis (wired via {@code spring.data.redis.*} dynamic
 * properties) rather than relying on the default {@code localhost:6379}, which is routinely
 * absent in test environments — {@link
 * com.example.nexus.rbac.infrastructure.cache.RedisPermissionCacheAdapter}'s fail-open behavior
 * would otherwise let this test pass by accident (every cache read silently missing) without
 * ever exercising the cache-hit path this scenario needs to prove. With a genuinely reachable
 * cache, this test proves {@link com.example.nexus.rbac.application.RoleResolutionService}'s
 * live-role-read freshness check (not just an empty/miss cache) correctly bypasses a stale
 * cached (permission-less) entry the moment a role is assigned.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Testcontainers
@Tag("IT")
class RefreshTokenPermissionResolutionIT {

  @Container
  private static final GenericContainer<?> REDIS =
      new GenericContainer<>(DockerImageName.parse("redis:7.4-alpine")).withExposedPorts(6379);

  @DynamicPropertySource
  static void redisProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.data.redis.host", REDIS::getHost);
    registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
  }

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final UUID MEMBER_ROLE_ID =
      UUID.fromString("019f6839-1811-7000-8000-00000000000b");
  private static final String TEST_PASSWORD = "TestPass99!";

  @Autowired private RefreshTokenUseCase refreshTokenUseCase;
  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private RefreshTokenPort refreshTokenPort;
  @Autowired private PasswordHasherPort passwordHasher;
  @Autowired private TokenGenerator tokenGenerator;
  @Autowired private TokenHasher tokenHasher;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JwtPort jwtPort;

  @Test
  void should_reflectNewlyAssignedRole_when_tokenRefreshedAfterAssignment() {
    User user = seedActiveUser("refresh-perm");
    String rawToken = seedRefreshToken(user);

    LoginResult beforeAssignment = refreshTokenUseCase.execute(rawToken, "127.0.0.1");
    JwtClaims claimsBefore = jwtPort.verify(beforeAssignment.accessToken());
    assertThat(claimsBefore.roles()).isEmpty();
    assertThat(claimsBefore.permissions()).isEmpty();

    userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), user.getId(), MEMBER_ROLE_ID, TENANT_ID, user.getId()));

    LoginResult afterAssignment =
        refreshTokenUseCase.execute(beforeAssignment.rawRefreshToken(), "127.0.0.1");
    JwtClaims claimsAfter = jwtPort.verify(afterAssignment.accessToken());

    assertThat(claimsAfter.roles()).containsExactly("MEMBER");
    assertThat(claimsAfter.permissions()).containsExactly("user:read");
  }

  private User seedActiveUser(String tag) {
    String email = "rot-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    String hash = passwordHasher.hash(TEST_PASSWORD);
    User user = new User(uuidGenerator.newId(), TENANT_ID, new EmailCipher(email), hmac, hash, null);
    user = userRegistrationPort.save(user);
    user.verify(Instant.now());
    return userRegistrationPort.save(user);
  }

  private String seedRefreshToken(User user) {
    String rawToken = tokenGenerator.generate();
    String tokenHash = tokenHasher.hash(rawToken);
    UUID familyId = uuidGenerator.newId();
    Instant expiresAt = Instant.now().plus(14, ChronoUnit.DAYS);
    refreshTokenPort.save(
        new RefreshToken(uuidGenerator.newId(), user.getId(), tokenHash, familyId, expiresAt));
    return rawToken;
  }
}
