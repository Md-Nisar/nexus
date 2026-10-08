package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.application.port.out.PermissionCachePort;
import com.example.nexus.rbac.application.port.out.UserRoleQueryPort;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("UnitTest")
class RoleResolutionServiceTest {

  private static final long EPOCH = 1_796_000_000_000L;

  private UserRoleQueryPort userRoleQueryPort;
  private PermissionCachePort permissionCachePort;
  private RoleResolutionService service;

  @BeforeEach
  void setUp() {
    userRoleQueryPort = mock(UserRoleQueryPort.class);
    permissionCachePort = mock(PermissionCachePort.class);
    service = new RoleResolutionService(userRoleQueryPort, permissionCachePort);
  }

  @Test
  void should_returnDbResolvedPermissions_when_cacheMiss() {
    UUID userId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    when(userRoleQueryPort.findActiveRoleNames(userId, tenantId))
        .thenReturn(List.of("TENANT_ADMIN"));
    when(permissionCachePort.get(tenantId, userId, EPOCH)).thenReturn(Optional.empty());
    when(userRoleQueryPort.findActivePermissionNames(userId, tenantId))
        .thenReturn(List.of("tenant:read", "tenant:write"));

    ResolvedPermissions resolved = service.resolve(userId, tenantId, EPOCH);

    assertThat(resolved.roles()).containsExactly("TENANT_ADMIN");
    assertThat(resolved.permissions()).containsExactly("tenant:read", "tenant:write");
    verify(permissionCachePort)
        .put(tenantId, userId, EPOCH, new ResolvedPermissions(List.of("TENANT_ADMIN"),
            List.of("tenant:read", "tenant:write")));
  }

  @Test
  void should_useCachedPermissions_when_cacheHitAndRolesUnchanged() {
    UUID userId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    when(userRoleQueryPort.findActiveRoleNames(userId, tenantId)).thenReturn(List.of("MEMBER"));
    when(permissionCachePort.get(tenantId, userId, EPOCH))
        .thenReturn(Optional.of(new ResolvedPermissions(List.of("MEMBER"), List.of("user:read"))));

    ResolvedPermissions resolved = service.resolve(userId, tenantId, EPOCH);

    assertThat(resolved.permissions()).containsExactly("user:read");
    verify(userRoleQueryPort, never()).findActivePermissionNames(userId, tenantId);
  }

  /**
   * US-010 AC6 / Blocker fix: a role granted after the permission set was cached must be
   * reflected on the very next resolution (login or refresh), not after the cache TTL expires.
   * The live role read (never cached) acting as a freshness fingerprint is what makes this work
   * without needing US-012's write-path cache eviction.
   */
  @Test
  void should_bypassStaleCache_when_liveRolesDifferFromCachedRoles() {
    UUID userId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    // Cached from an earlier resolution when the user had no roles yet.
    when(permissionCachePort.get(tenantId, userId, EPOCH))
        .thenReturn(Optional.of(ResolvedPermissions.empty()));
    // A role has since been assigned — the live role read must reflect it.
    when(userRoleQueryPort.findActiveRoleNames(userId, tenantId)).thenReturn(List.of("MEMBER"));
    when(userRoleQueryPort.findActivePermissionNames(userId, tenantId))
        .thenReturn(List.of("user:read"));

    ResolvedPermissions resolved = service.resolve(userId, tenantId, EPOCH);

    assertThat(resolved.roles()).containsExactly("MEMBER");
    assertThat(resolved.permissions())
        .as("stale cached (empty) permissions must not be returned once roles changed")
        .containsExactly("user:read");
    verify(userRoleQueryPort).findActivePermissionNames(userId, tenantId);
    verify(permissionCachePort)
        .put(tenantId, userId, EPOCH,
            new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));
  }

  @Test
  void should_bypassStaleCache_when_aRoleWasRevokedSinceCaching() {
    UUID userId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    // Cached with TENANT_ADMIN still active.
    when(permissionCachePort.get(tenantId, userId, EPOCH))
        .thenReturn(Optional.of(new ResolvedPermissions(List.of("TENANT_ADMIN"),
            List.of("tenant:read", "tenant:write"))));
    // TENANT_ADMIN has since been revoked — live read now shows no roles.
    when(userRoleQueryPort.findActiveRoleNames(userId, tenantId)).thenReturn(List.of());
    when(userRoleQueryPort.findActivePermissionNames(userId, tenantId)).thenReturn(List.of());

    ResolvedPermissions resolved = service.resolve(userId, tenantId, EPOCH);

    assertThat(resolved.roles()).isEmpty();
    assertThat(resolved.permissions()).isEmpty();
  }

  @Test
  void should_treatRoleOrder_asIrrelevant_forCacheFreshnessComparison() {
    UUID userId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    when(userRoleQueryPort.findActiveRoleNames(userId, tenantId))
        .thenReturn(List.of("MEMBER", "TENANT_ADMIN"));
    when(permissionCachePort.get(tenantId, userId, EPOCH))
        .thenReturn(Optional.of(new ResolvedPermissions(List.of("TENANT_ADMIN", "MEMBER"),
            List.of("user:read"))));

    ResolvedPermissions resolved = service.resolve(userId, tenantId, EPOCH);

    assertThat(resolved.permissions()).containsExactly("user:read");
    verify(userRoleQueryPort, never()).findActivePermissionNames(userId, tenantId);
  }

  @Test
  void should_returnEmptyClaims_when_userHasNoRoles() {
    UUID userId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    when(userRoleQueryPort.findActiveRoleNames(userId, tenantId)).thenReturn(List.of());
    when(permissionCachePort.get(tenantId, userId, EPOCH)).thenReturn(Optional.empty());
    when(userRoleQueryPort.findActivePermissionNames(userId, tenantId)).thenReturn(List.of());

    ResolvedPermissions resolved = service.resolve(userId, tenantId, EPOCH);

    assertThat(resolved.roles()).isEmpty();
    assertThat(resolved.permissions()).isEmpty();
  }

  @Test
  void should_throwNpe_when_tenantIdNull() {
    UUID userId = UUID.randomUUID();

    assertThatThrownBy(() -> service.resolve(userId, null, EPOCH))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throwNpe_when_userIdNull() {
    UUID tenantId = UUID.randomUUID();

    assertThatThrownBy(() -> service.resolve(null, tenantId, EPOCH))
        .isInstanceOf(NullPointerException.class);
  }

  // --- US-018 Decision 17: the cache entry is read and written under the mint's epoch ---

  @Test
  void should_readAndWriteCacheUnderGivenEpoch_when_resolving() {
    UUID userId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    when(userRoleQueryPort.findActiveRoleNames(userId, tenantId)).thenReturn(List.of("MEMBER"));
    when(permissionCachePort.get(tenantId, userId, EPOCH)).thenReturn(Optional.empty());
    when(userRoleQueryPort.findActivePermissionNames(userId, tenantId))
        .thenReturn(List.of("user:read"));

    service.resolve(userId, tenantId, EPOCH);

    verify(permissionCachePort).get(tenantId, userId, EPOCH);
    verify(permissionCachePort)
        .put(tenantId, userId, EPOCH,
            new ResolvedPermissions(List.of("MEMBER"), List.of("user:read")));
    verifyNoMoreInteractions(permissionCachePort);
  }

  /**
   * Design §9.4: a mint that raced a detach writes the stale set under the old epoch E. The next
   * mint reads the bumped epoch R, so the stale entry is never consulted, even though the role
   * fingerprint (unchanged by a detach) would accept it.
   */
  @Test
  void should_missAndRecompute_when_entryCachedUnderOlderEpoch() {
    UUID userId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    long bumped = EPOCH + 1;
    when(userRoleQueryPort.findActiveRoleNames(userId, tenantId)).thenReturn(List.of("READER"));
    when(permissionCachePort.get(tenantId, userId, EPOCH)).thenReturn(Optional.of(
        new ResolvedPermissions(List.of("READER"), List.of("role:read", "user:read"))));
    when(permissionCachePort.get(tenantId, userId, bumped)).thenReturn(Optional.empty());
    when(userRoleQueryPort.findActivePermissionNames(userId, tenantId))
        .thenReturn(List.of("user:read"));

    ResolvedPermissions resolved = service.resolve(userId, tenantId, bumped);

    assertThat(resolved.permissions()).containsExactly("user:read");
    verify(permissionCachePort)
        .put(tenantId, userId, bumped,
            new ResolvedPermissions(List.of("READER"), List.of("user:read")));
  }

  /** The role-name fingerprint is kept: it covers assign and revoke under an unchanged epoch. */
  @Test
  void should_stillRecompute_when_cachedRolesDifferFromLiveUnderSameEpoch() {
    UUID userId = UUID.randomUUID();
    UUID tenantId = UUID.randomUUID();
    when(userRoleQueryPort.findActiveRoleNames(userId, tenantId))
        .thenReturn(List.of("MEMBER", "READER"));
    when(permissionCachePort.get(tenantId, userId, EPOCH))
        .thenReturn(Optional.of(new ResolvedPermissions(List.of("MEMBER"), List.of("user:read"))));
    when(userRoleQueryPort.findActivePermissionNames(userId, tenantId))
        .thenReturn(List.of("role:read", "user:read"));

    ResolvedPermissions resolved = service.resolve(userId, tenantId, EPOCH);

    assertThat(resolved.permissions()).containsExactly("role:read", "user:read");
    verify(userRoleQueryPort).findActivePermissionNames(userId, tenantId);
  }
}
