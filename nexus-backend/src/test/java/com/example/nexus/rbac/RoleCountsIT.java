package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.application.port.out.RoleManagementPort;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleCounts;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import jakarta.persistence.EntityManagerFactory;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

/**
 * US-019 B6 (T-016, 03-design.md §8): {@code memberCount} and {@code permissionCount} come from two
 * grouped statements per page, count only active assignments of live roles, and never cross a
 * tenant. The statement count is read from Hibernate statistics.
 */
@SpringBootTest(properties = "spring.jpa.properties.hibernate.generate_statistics=true")
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RoleCountsIT {

  @Autowired private RoleManagementService service;
  @Autowired private RoleManagementPort port;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private EntityManagerFactory entityManagerFactory;

  @Test
  void should_issueExactlyTwoStatements_when_countingAHundredRolePage() {
    UUID tenantId = uuidGenerator.newId();
    List<UUID> roleIds = new ArrayList<>();
    for (int i = 0; i < 100; i++) {
      roleIds.add(seedRole(tenantId).getId());
    }
    User holder = seedUser(tenantId);
    assign(holder, roleIds.get(0), tenantId);
    grantAnyPermission(roleIds.get(1));
    Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
    statistics.clear();

    Map<UUID, RoleCounts> counts = service.countsForRoles(actor(tenantId), roleIds);

    assertThat(statistics.getPrepareStatementCount()).isEqualTo(2L);
    assertThat(counts.get(roleIds.get(0)).memberCount()).isEqualTo(1L);
    assertThat(counts.get(roleIds.get(1)).permissionCount()).isEqualTo(1);
  }

  @Test
  void should_excludeRevokedAssignments_when_countingMembers() {
    UUID tenantId = uuidGenerator.newId();
    Role role = seedRole(tenantId);
    User active = seedUser(tenantId);
    User revoked = seedUser(tenantId);
    assign(active, role.getId(), tenantId);
    UserRole gone = assign(revoked, role.getId(), tenantId);
    jdbc.update(
        "UPDATE user_roles SET revoked_at = CURRENT_TIMESTAMP(6) WHERE id = ?",
        (Object) toBytes(gone.getId()));

    assertThat(port.countActiveHoldersByRole(tenantId, List.of(role.getId())))
        .containsEntry(role.getId(), 1L);
  }

  @Test
  void should_notCountAssignments_when_theRoleIsSoftDeleted() {
    UUID tenantId = uuidGenerator.newId();
    Role role = seedRole(tenantId);
    grantAnyPermission(role.getId());
    assign(seedUser(tenantId), role.getId(), tenantId);
    jdbc.update(
        "UPDATE roles SET deleted_at = CURRENT_TIMESTAMP(6) WHERE id = ?",
        (Object) toBytes(role.getId()));

    assertThat(port.countActiveHoldersByRole(tenantId, List.of(role.getId()))).isEmpty();
    assertThat(port.countPermissionsByRole(tenantId, List.of(role.getId()))).isEmpty();
  }

  @Test
  void should_countOnlyTheCallersTenant_when_roleIdsBelongToAnotherTenant() {
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    Role foreign = seedRole(tenantB);
    grantAnyPermission(foreign.getId());
    assign(seedUser(tenantB), foreign.getId(), tenantB);

    assertThat(port.countActiveHoldersByRole(tenantA, List.of(foreign.getId()))).isEmpty();
    assertThat(port.countPermissionsByRole(tenantA, List.of(foreign.getId()))).isEmpty();
    assertThat(service.countsForRoles(actor(tenantA), List.of(foreign.getId())).get(foreign.getId()))
        .isEqualTo(new RoleCounts(foreign.getId(), 0L, 0));
  }

  @Test
  void should_issueNoStatement_when_noRoleIdsAreGiven() {
    Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
    statistics.clear();

    assertThat(service.countsForRoles(actor(uuidGenerator.newId()), List.of())).isEmpty();
    assertThat(statistics.getPrepareStatementCount()).isZero();
  }

  // ── fixtures ──────────────────────────────────────────────────────────────────────────────

  private static RoleChangeActor actor(UUID tenantId) {
    return new RoleChangeActor(UUID.randomUUID(), tenantId);
  }

  private User seedUser(UUID tenantId) {
    String email = "rc-" + UUID.randomUUID() + "@example.test";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    user.verify(Instant.now());
    return userRepository.save(user);
  }

  private Role seedRole(UUID tenantId) {
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "RC-" + UUID.randomUUID(), "rc", false));
  }

  private UserRole assign(User user, UUID roleId, UUID tenantId) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), user.getId(), roleId, tenantId, user.getId()));
  }

  private void grantAnyPermission(UUID roleId) {
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions LIMIT 1",
        (Object) toBytes(roleId));
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
