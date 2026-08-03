package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.application.port.out.RbacAuditPort;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.DuplicateRoleAssignmentException;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.cache.RedisPermissionCacheAdapter;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * US-012 T-020 (03-design.md §6.5/R-7): proves {@link RoleAssignmentService#assign}/{@link
 * RoleAssignmentService#revoke} evict the two <b>real</b> Redis keys {@link
 * RedisPermissionCacheAdapter} maintains — confirmed by reading that class's {@code roleKey}/{@code
 * permKey} methods directly:
 *
 * <pre>{@code
 * {keyPrefix}:rbac:roleset:{tenantId}:{userId}
 * {keyPrefix}:rbac:permset:{tenantId}:{userId}
 * }</pre>
 *
 * with {@code keyPrefix} sourced from {@code nexus.redis.key-prefix} (default {@code nexus}).
 * <b>Deliberately not</b> the story's AC6 literal {@code permissions:{tenant_id}:{user_id}} — that
 * key does not exist anywhere in production code, and a test asserting against it would pass
 * vacuously (deleting a key that was never there), silently failing to catch a real eviction
 * regression. All key-presence assertions below go through a raw {@link StringRedisTemplate}
 * querying the exact key names above — never through {@link PermissionCachePort}'s own get/put,
 * which would only prove the adapter agrees with itself.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@Tag("IT")
class RoleAssignmentCacheIT {

  private static final String SENTINEL_ROLE = "SENTINEL_ROLE";
  private static final String SENTINEL_PERMISSION = "sentinel:permission";

  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private UserRoleAssignmentPort userRoleAssignmentPort;
  @Autowired private UserDirectoryPort userDirectoryPort;
  @Autowired private RbacAuditPort rbacAuditPort;
  @Autowired private PermissionCachePort permissionCachePort;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private StringRedisTemplate redisTemplate;
  @Autowired private PlatformTransactionManager transactionManager;

  @Value("${nexus.redis.key-prefix:nexus}")
  private String keyPrefix;

  @Value("${nexus.rbac.permission-cache-ttl-seconds:900}")
  private long ttlSeconds;

  // ── Scenario 1: successful assign evicts both real keys ──────────────

  @Test
  void should_deleteBothRealRedisKeys_when_assignSucceeds() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = seedActor(tenantId, "assign-evict");
    User target = seedUser(tenantId, "assign-evict");
    Role role = seedRole(tenantId, "ASSIGN-EVICT");
    seedCacheEntry(tenantId, target.getId());

    roleAssignmentService.assign(actor, target.getId(), role.getId(), requestContext());

    assertThat(redisTemplate.hasKey(roleKey(tenantId, target.getId())))
        .as("roleset key must be deleted after a successful assign")
        .isFalse();
    assertThat(redisTemplate.hasKey(permKey(tenantId, target.getId())))
        .as("permset key must be deleted after a successful assign")
        .isFalse();
  }

  // ── Scenario 2: successful revoke evicts both real keys ───────────────

  @Test
  void should_deleteBothRealRedisKeys_when_revokeSucceeds() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = seedActor(tenantId, "revoke-evict");
    User target = seedUser(tenantId, "revoke-evict");
    Role role = seedRole(tenantId, "REVOKE-EVICT");
    userRoleRepository.save(
        new UserRole(
            uuidGenerator.newId(), target.getId(), role.getId(), tenantId, actor.userId()));
    seedCacheEntry(tenantId, target.getId());

    roleAssignmentService.revoke(actor, target.getId(), role.getId(), requestContext());

    assertThat(redisTemplate.hasKey(roleKey(tenantId, target.getId())))
        .as("roleset key must be deleted after a successful revoke")
        .isFalse();
    assertThat(redisTemplate.hasKey(permKey(tenantId, target.getId())))
        .as("permset key must be deleted after a successful revoke")
        .isFalse();
  }

  // ── Scenario 3: Redis unavailable → assign/revoke still succeed (fail-open) ──

  /**
   * Constructs a fresh, non-Spring-proxied {@link RoleAssignmentService} wired with the real
   * MySQL-backed ports from the application context but a genuinely unreachable Redis (same
   * wrong-port {@link LettuceConnectionFactory} technique {@code RedisPermissionCacheAdapterIT}
   * and {@code RedisRateLimitStoreIT} already use for their own fail-open cases) — so exactly one
   * collaborator fails, while production {@code assign()}/{@code revoke()} logic still runs
   * end-to-end, not just {@link RedisPermissionCacheAdapter} in isolation.
   *
   * <p>Because this instance is never Spring-AOP-proxied, {@code @Transactional} has no effect and
   * {@code TransactionSynchronizationManager.isSynchronizationActive()} is {@code false} inside
   * {@code assign()}/{@code revoke()} — exercising the documented inline-fallback branch
   * (03-design.md §6.4/D14) rather than the {@code afterCommit} branch. That fallback is the only
   * way a test outside a real HTTP request/transaction can observe these post-commit side effects
   * (including the cache evict that must fail open here) firing synchronously at all.
   */
  private RoleAssignmentServiceWithBrokenCache serviceWithBrokenCache() {
    LettuceConnectionFactory brokenFactory = new LettuceConnectionFactory("localhost", 1);
    brokenFactory.afterPropertiesSet();
    StringRedisTemplate brokenTemplate = new StringRedisTemplate(brokenFactory);
    brokenTemplate.afterPropertiesSet();
    PermissionCachePort brokenCache =
        new RedisPermissionCacheAdapter(brokenTemplate, keyPrefix, ttlSeconds);
    RoleAssignmentService service =
        new RoleAssignmentService(
            userRoleAssignmentPort, userDirectoryPort, rbacAuditPort, brokenCache);
    return new RoleAssignmentServiceWithBrokenCache(service, brokenFactory);
  }

  private record RoleAssignmentServiceWithBrokenCache(
      RoleAssignmentService service, LettuceConnectionFactory brokenFactory) {
    void destroy() {
      brokenFactory.destroy();
    }
  }

  @Test
  void should_stillCompleteSuccessfully_when_redisIsUnreachableDuringAssign() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = seedActor(tenantId, "assign-redis-down");
    User target = seedUser(tenantId, "assign-redis-down");
    Role role = seedRole(tenantId, "ASSIGN-REDIS-DOWN");
    RoleAssignmentServiceWithBrokenCache broken = serviceWithBrokenCache();

    try {
      ActiveRoleAssignment result =
          broken.service().assign(actor, target.getId(), role.getId(), requestContext());

      assertThat(result.roleId())
          .as("assign must still complete and return the created assignment (fail-open)")
          .isEqualTo(role.getId());
    } finally {
      broken.destroy();
    }
  }

  @Test
  void should_stillCompleteSuccessfully_when_redisIsUnreachableDuringRevoke() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = seedActor(tenantId, "revoke-redis-down");
    User target = seedUser(tenantId, "revoke-redis-down");
    Role role = seedRole(tenantId, "REVOKE-REDIS-DOWN");
    UUID assignmentId = uuidGenerator.newId();
    userRoleRepository.save(
        new UserRole(assignmentId, target.getId(), role.getId(), tenantId, actor.userId()));
    RoleAssignmentServiceWithBrokenCache broken = serviceWithBrokenCache();

    try {
      // revoke()'s M6 write is a bulk @Modifying UPDATE, which Spring Data JPA explicitly
      // refuses to run without an active JPA transaction -- independent of whether the caller
      // is AOP-proxied. In production this is always satisfied by the real, Spring-managed
      // RoleAssignmentService bean's own @Transactional. This un-proxied broken.service()
      // instance has no such transaction (that absence is exactly what lets it exercise the
      // inline side-effect fallback, per this class's own Javadoc) -- so we open one manually
      // via TransactionTemplate purely to satisfy M6's write, without re-introducing AOP.
      assertThatCode(
              () ->
                  new TransactionTemplate(transactionManager)
                      .executeWithoutResult(
                          status ->
                              broken
                                  .service()
                                  .revoke(actor, target.getId(), role.getId(), requestContext())))
          .as("revoke must not throw even though the cache is unreachable (fail-open)")
          .doesNotThrowAnyException();

      assertThat(userRoleRepository.findById(assignmentId).orElseThrow().getRevokedAt())
          .as("the revoke itself must still have taken effect in MySQL despite the cache outage")
          .isNotNull();
    } finally {
      broken.destroy();
    }
  }

  // ── Scenario 4: a failed request never touches the cache ─────────────

  @Test
  void should_notEvictCache_when_assignFailsWithDuplicateActiveAssignment() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = seedActor(tenantId, "assign-409");
    User target = seedUser(tenantId, "assign-409");
    Role role = seedRole(tenantId, "ASSIGN-409");
    roleAssignmentService.assign(actor, target.getId(), role.getId(), requestContext());
    seedCacheEntry(tenantId, target.getId());

    assertThatThrownBy(
            () -> roleAssignmentService.assign(actor, target.getId(), role.getId(), requestContext()))
        .isInstanceOf(DuplicateRoleAssignmentException.class);

    assertThat(redisTemplate.hasKey(roleKey(tenantId, target.getId())))
        .as("a thrown 409 must never evict — side effects are post-commit only")
        .isTrue();
    assertThat(redisTemplate.hasKey(permKey(tenantId, target.getId()))).isTrue();
  }

  @Test
  void should_notEvictCache_when_assignFailsWithCrossTenantTarget() {
    UUID actorTenantId = uuidGenerator.newId();
    UUID targetTenantId = uuidGenerator.newId();
    RoleChangeActor actor = seedActor(actorTenantId, "assign-403");
    User target = seedUser(targetTenantId, "assign-403");
    Role role = seedRole(actorTenantId, "ASSIGN-403");
    seedCacheEntry(actorTenantId, target.getId());

    assertThatThrownBy(
            () -> roleAssignmentService.assign(actor, target.getId(), role.getId(), requestContext()))
        .isInstanceOf(InsufficientPermissionException.class)
        .satisfies(
            e ->
                assertThat(((InsufficientPermissionException) e).getReason())
                    .isEqualTo(DenialReason.CROSS_TENANT_TARGET));

    assertThat(redisTemplate.hasKey(roleKey(actorTenantId, target.getId())))
        .as("a thrown 403 must never evict — side effects are post-commit only")
        .isTrue();
    assertThat(redisTemplate.hasKey(permKey(actorTenantId, target.getId()))).isTrue();
  }

  @Test
  void should_notEvictCache_when_revokeFailsWithAssignmentNotFound() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = seedActor(tenantId, "revoke-404");
    User target = seedUser(tenantId, "revoke-404");
    Role role = seedRole(tenantId, "REVOKE-404");
    seedCacheEntry(tenantId, target.getId());

    assertThatThrownBy(
            () -> roleAssignmentService.revoke(actor, target.getId(), role.getId(), requestContext()))
        .isInstanceOf(ResourceNotFoundException.class);

    assertThat(redisTemplate.hasKey(roleKey(tenantId, target.getId())))
        .as("a thrown 404 must never evict — side effects are post-commit only")
        .isTrue();
    assertThat(redisTemplate.hasKey(permKey(tenantId, target.getId()))).isTrue();
  }

  // ── Shared seeding / helpers ───────────────────────────────────────────

  private User seedUser(UUID tenantId, String tag) {
    String email = "cache-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRepository.save(
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  /**
   * A bare {@code uuidGenerator.newId()} is NOT a valid actor id: {@code user_roles.assigned_by}
   * has an FK to {@code users.id} ({@code fk_user_roles_assigner}), so every actor must be a real,
   * seeded {@link User} row, never a conjured UUID.
   */
  private RoleChangeActor seedActor(UUID tenantId, String tag) {
    User actorUser = seedUser(tenantId, tag + "-actor");
    return new RoleChangeActor(actorUser.getId(), tenantId);
  }

  private Role seedRole(UUID tenantId, String tag) {
    // is_system_role=false, non-TENANT_ADMIN name: keeps this suite clear of the AC8 live-admin
    // branch entirely — that branch is RoleAssignmentSecurityIT's concern (T-019), not this one's.
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "CACHE-" + tag + "-" + UUID.randomUUID(), null,
            false));
  }

  private void seedCacheEntry(UUID tenantId, UUID userId) {
    permissionCachePort.put(
        tenantId, userId, new ResolvedPermissions(List.of(SENTINEL_ROLE), List.of(SENTINEL_PERMISSION)));
  }

  private RequestContext requestContext() {
    return RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "JUnit");
  }

  private String roleKey(UUID tenantId, UUID userId) {
    return keyPrefix + ":rbac:roleset:" + tenantId + ":" + userId;
  }

  private String permKey(UUID tenantId, UUID userId) {
    return keyPrefix + ":rbac:permset:" + tenantId + ":" + userId;
  }
}
