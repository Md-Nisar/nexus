package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.port.out.RoleManagementPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.application.port.out.UserRoleQueryPort;
import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.PermissionHolder;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermissionRef;
import com.example.nexus.rbac.domain.RoleView;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * US-018 MC-9 (T-026, RC-36.3): after a role is soft-deleted it is invisible to every role-reading
 * port method and to the zero-admin reader: M13, M14, M10', M11, M16, {@code RoleResolutionService}'s
 * two reads, the assignment projections, {@code ZeroAdminTenantReader}, {@code findRoleIdByName}
 * and the role listing and cap count, plus the three C3 access-review queries (T-029).
 *
 * <p>The primary control is the invariant "a deleted role has no active holders". These reads are
 * defense in depth, so the fixture deliberately FORGES the invariant break: the role is
 * admin-defining, carries an active assignment, and is then soft-deleted directly. Every read that
 * joins {@code roles} must still not see it. M11 is the exception by design (it locks {@code
 * user_roles} by role id and joins nothing, so a join would widen the lock): it is asserted after
 * the forged row is revoked, which is the state the delete protocol guarantees, and the lock set is
 * built from M10', which this test shows excludes the deleted role.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class SoftDeletedRoleVisibilityIT {

  @Autowired private UserRoleAssignmentPort assignmentPort;
  @Autowired private RoleManagementPort roleManagementPort;
  @Autowired private UserRoleQueryPort userRoleQueryPort;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  @Test
  void should_hideASoftDeletedRoleFromEveryRoleReadingPortMethod_when_itIsDeleted() {
    UUID tenantId = uuidGenerator.newId();
    User user = seedUser(tenantId);
    Role deleted = seedRole(tenantId, "MC9-DELETED");
    grantWholeCatalogue(deleted);
    UserRole forged =
        userRoleRepository.save(
            new UserRole(uuidGenerator.newId(), user.getId(), deleted.getId(), tenantId, user.getId()));
    Role live = seedRole(tenantId, "MC9-LIVE");
    jdbc.update("UPDATE roles SET deleted_at = CURRENT_TIMESTAMP(6) WHERE id = ?", toBytes(deleted.getId()));

    // M13 and M16: what the caller holds, and which held roles are admin-defining.
    assertThat(
            assignmentPort.findHeldRolePermissionIdsForAuthorization(user.getId(), tenantId).stream()
                .map(RolePermissionRef::roleId))
        .doesNotContain(deleted.getId());
    assertThat(assignmentPort.findHeldAdminDefiningRoleIds(user.getId(), tenantId))
        .doesNotContain(deleted.getId());
    // M14 fails closed for the deleted role; M10' does not list it.
    assertThat(assignmentPort.findPermissionIdsForRole(deleted.getId(), tenantId)).isEmpty();
    assertThat(
            assignmentPort.findRolePermissionIdsForTenantRoles(tenantId).stream()
                .map(RolePermissionRef::roleId))
        .doesNotContain(deleted.getId());
    // RoleResolutionService's two reads.
    assertThat(userRoleQueryPort.findActiveRoleNames(user.getId(), tenantId))
        .doesNotContain(deleted.getName());
    assertThat(userRoleQueryPort.findActivePermissionNames(user.getId(), tenantId)).isEmpty();
    // The assignment projections and the role lookups.
    assertThat(assignmentPort.findActiveAssignmentViews(user.getId(), tenantId, 0, 100).items())
        .extracting(ActiveRoleAssignment::roleId)
        .doesNotContain(deleted.getId());
    assertThat(assignmentPort.findActiveAssignmentView(user.getId(), deleted.getId(), tenantId))
        .isEmpty();
    assertThat(assignmentPort.findRole(deleted.getId())).isEmpty();
    assertThat(roleManagementPort.findRole(deleted.getId())).isEmpty();
    assertThat(assignmentPort.findRoleIdByName(tenantId, deleted.getName())).isEmpty();
    // Listing and the cap count see the live role only.
    assertThat(roleManagementPort.findRolesInTenant(tenantId, 0, 100).items())
        .extracting(RoleView::id)
        .containsExactly(live.getId());
    assertThat(roleManagementPort.countRolesInTenant(tenantId)).isEqualTo(1L);
    // The three C3 (access review) queries (T-029): a deleted role has no holders, grants nothing.
    assertThat(assignmentPort.findActiveRoleHolders(deleted.getId(), tenantId, 0, 100).items())
        .isEmpty();
    UUID someCataloguePermission = assignmentPort.findCatalogueIds().iterator().next();
    assertThat(
            assignmentPort.findPermissionHolders(someCataloguePermission, tenantId, 0, 100).items())
        .extracting(PermissionHolder::userId)
        .as("a user whose only route to the permission is a deleted role is not a holder")
        .doesNotContain(user.getId());
    assertThat(userRoleQueryPort.findActivePermissionsViaRoles(user.getId(), tenantId)).isEmpty();
    // ZeroAdminTenantReader: a tenant whose only admin-defining role is deleted has none.
    assertThat(userRoleRepository.findTenantsWithAnAdminDefiningRole()).doesNotContain(tenantId);
    assertThat(userRoleRepository.findTenantsWithActiveAdminDefiningHolders())
        .doesNotContain(tenantId);
    // The detector, in contrast, is the one query that must see the forged row.
    assertThat(userRoleRepository.countActiveAssignmentsOnDeletedRolesInAnyTenant()).isGreaterThanOrEqualTo(1L);

    // M11 after the invariant is restored (the forged row revoked): nothing to lock.
    jdbc.update(
        "UPDATE user_roles SET revoked_at = CURRENT_TIMESTAMP(6) WHERE id = ?",
        toBytes(forged.getId()));
    List<ActiveAssignmentHolder> locked =
        inTransaction(() -> assignmentPort.lockActiveAssignmentHolders(tenantId, List.of(deleted.getId())));
    assertThat(locked).isEmpty();
  }

  // ── fixtures ──────────────────────────────────────────────────────────────────────────────

  @Autowired private org.springframework.transaction.PlatformTransactionManager transactionManager;

  /** M11 must run inside a transaction (it is a locking read). */
  private <T> T inTransaction(java.util.function.Supplier<T> work) {
    return new org.springframework.transaction.support.TransactionTemplate(transactionManager)
        .execute(status -> work.get());
  }

  private User seedUser(UUID tenantId) {
    String email = "mc9-" + UUID.randomUUID() + "@example.test";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null);
    user.verify(Instant.now());
    return userRepository.save(user);
  }

  private Role seedRole(UUID tenantId, String prefix) {
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, prefix + "-" + UUID.randomUUID(), "mc9", false));
  }

  private void grantWholeCatalogue(Role role) {
    jdbc.update(
        "INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions",
        (Object) toBytes(role.getId()));
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
