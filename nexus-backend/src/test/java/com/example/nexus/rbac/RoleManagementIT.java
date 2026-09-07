package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.rbac.application.RoleManagementService;
import com.example.nexus.rbac.domain.PermissionView;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleLimitExceededException;
import com.example.nexus.rbac.domain.RoleView;
import com.example.nexus.rbac.domain.ReservedRoleNameException;
import com.example.nexus.rbac.domain.DuplicateRolePermissionException;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * US-015 T-010 (04-tasks.md; docs/story/2-rbac/US-015.md Scenarios 1-4, 7; 03-design.md §8.1-§8.5;
 * threat-model.md RC-1/RC-4): the CRUD-shaped, non-security-critical happy-path and 404 branches
 * for role/role-permission management. Tested at the SERVICE layer directly ({@link
 * RoleManagementService} autowired), matching {@code RoleAssignmentAuditIT}'s established
 * "scenarios 1-4 don't need the HTTP layer" precedent — this file is about plumbing correctness,
 * not the security-critical AC7/AC11 paths, which live in {@code RolePermissionSecurityIT} and
 * {@code RoleManagementAdminGateIT}.
 *
 * <p><b>RC-1 (reserved role names) and RC-4 (per-tenant role cap)</b> are folded into this file
 * rather than a dedicated one: {@code 04-tasks.md}'s "Files created" list names 7 classes and does
 * not give RC-1/RC-4 their own file; both are single-request creation-time 409 checks, the same
 * shape as Scenario 2's duplicate-name 409 already covered here.
 *
 * <p>Fixture roles are always {@code is_system_role=false} with randomised names, per this
 * story's shared-Spring-context/shared-schema caveat ({@code RbacSchemaMigrationIT}'s Javadoc).
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RoleManagementIT {

  // role:read, not role:write: role:write is one of AC11's 3 dangerous permissions, so
  // attaching it requires an active TENANT_ADMIN caller -- irrelevant machinery for this file's
  // plain-CRUD scope. AC11 itself is RoleManagementAdminGateIT's job.
  private static final String SAFE_PERMISSION_NAME = "role:read";
  private static final UUID SAFE_PERMISSION_ID =
      UUID.fromString("019f6839-1804-7000-8000-000000000005");

  @Autowired private RoleManagementService roleManagementService;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;

  // ── Scenario 1: create role in own tenant ──────────────────────────────────────────────

  @Test
  void should_createRoleWithSystemRoleFalse_when_creatingInOwnTenant() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);
    String name = "RMIT-CREATE-" + UUID.randomUUID();

    RoleView created =
        roleManagementService.createRole(actor, name, "a description", requestContext());

    assertThat(created.name()).isEqualTo(name);
    assertThat(created.tenantId()).isEqualTo(tenantId);
    assertThat(created.systemRole()).as("AC1: custom roles must never be system roles").isFalse();
    assertThat(created.createdAt()).as("createdAt must be DB-generated, not null").isNotNull();
  }

  // ── Scenario 2: duplicate role name in same tenant ─────────────────────────────────────

  @Test
  void should_throwDuplicateRoleNameException_when_creatingWithDuplicateNameInSameTenant() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);
    String name = "RMIT-DUP-" + UUID.randomUUID();
    roleManagementService.createRole(actor, name, null, requestContext());

    assertThatThrownBy(
            () -> roleManagementService.createRole(actor, name, null, requestContext()))
        .isInstanceOf(com.example.nexus.rbac.domain.DuplicateRoleNameException.class);
  }

  // ── Scenario 3: assign permission to a custom role ─────────────────────────────────────

  @Test
  void should_createRolePermissionsRow_when_attachingPermissionToCustomRole() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);
    Role role = seedRole("ATTACH", tenantId);

    PermissionView attached =
        roleManagementService.attachPermission(
            actor, role.getId(), SAFE_PERMISSION_ID, requestContext());

    assertThat(attached.name()).isEqualTo(SAFE_PERMISSION_NAME);
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM role_permissions WHERE role_id = ? AND permission_id = ?",
            Integer.class,
            toBytes(role.getId()),
            toBytes(SAFE_PERMISSION_ID));
    assertThat(count).isEqualTo(1);
  }

  @Test
  void should_throwDuplicateRolePermissionException_when_attachingSamePermissionTwice() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);
    Role role = seedRole("ATTACH-DUP", tenantId);
    roleManagementService.attachPermission(
        actor, role.getId(), SAFE_PERMISSION_ID, requestContext());

    assertThatThrownBy(
            () ->
                roleManagementService.attachPermission(
                    actor, role.getId(), SAFE_PERMISSION_ID, requestContext()))
        .isInstanceOf(DuplicateRolePermissionException.class);
  }

  // ── Scenario 4: remove permission from a custom role ───────────────────────────────────

  @Test
  void should_removeRolePermissionsRow_when_detachingPermissionFromCustomRole() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);
    Role role = seedRole("DETACH", tenantId);
    roleManagementService.attachPermission(
        actor, role.getId(), SAFE_PERMISSION_ID, requestContext());

    roleManagementService.detachPermission(
        actor, role.getId(), SAFE_PERMISSION_ID, requestContext());

    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM role_permissions WHERE role_id = ? AND permission_id = ?",
            Integer.class,
            toBytes(role.getId()),
            toBytes(SAFE_PERMISSION_ID));
    assertThat(count).isZero();
  }

  // ── Scenario 7: list all permissions ────────────────────────────────────────────────────

  /**
   * Asserts CONTAINS, never an exact {@code hasSize(7)}, mirroring {@code
   * RbacSchemaMigrationIT}'s own scoped-count discipline: {@code RbacRepositoryRoundTripIT}
   * legitimately inserts its own fixture {@code Permission} rows into this run's shared
   * Testcontainers schema, so an exact-size assertion here is order-dependent across the whole
   * {@code *IT} suite and would fail whenever that class's fixtures happen to run first.
   */
  @Test
  void should_returnAllSevenSeededPermissions_when_listingAllPermissions() {
    List<PermissionView> all = roleManagementService.listAllPermissions();

    assertThat(all.stream().map(PermissionView::name).toList())
        .contains(
            "tenant:read", "tenant:write", "user:read", "user:write", "role:read", "role:write",
            "audit:read");
  }

  // ── 404 branches ─────────────────────────────────────────────────────────────────────────

  @Test
  void should_throwResourceNotFound_when_listingPermissionsForUnknownRole() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);

    assertThatThrownBy(
            () ->
                roleManagementService.listRolePermissions(actor, uuidGenerator.newId()))
        .isInstanceOf(ResourceNotFoundException.class)
        .satisfies(e -> assertThat(((ResourceNotFoundException) e).code()).isEqualTo("ROLE_NOT_FOUND"));
  }

  @Test
  void should_throwResourceNotFound_when_attachingToUnknownRole() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);

    assertThatThrownBy(
            () ->
                roleManagementService.attachPermission(
                    actor, uuidGenerator.newId(), SAFE_PERMISSION_ID, requestContext()))
        .isInstanceOf(ResourceNotFoundException.class)
        .satisfies(e -> assertThat(((ResourceNotFoundException) e).code()).isEqualTo("ROLE_NOT_FOUND"));
  }

  @Test
  void should_throwResourceNotFound_when_attachingUnknownPermission() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);
    Role role = seedRole("UNKNOWN-PERM", tenantId);

    assertThatThrownBy(
            () ->
                roleManagementService.attachPermission(
                    actor, role.getId(), uuidGenerator.newId(), requestContext()))
        .isInstanceOf(ResourceNotFoundException.class)
        .satisfies(
            e -> assertThat(((ResourceNotFoundException) e).code()).isEqualTo("PERMISSION_NOT_FOUND"));
  }

  @Test
  void should_throwResourceNotFound_when_detachingFromUnknownRole() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);

    assertThatThrownBy(
            () ->
                roleManagementService.detachPermission(
                    actor, uuidGenerator.newId(), SAFE_PERMISSION_ID, requestContext()))
        .isInstanceOf(ResourceNotFoundException.class)
        .satisfies(e -> assertThat(((ResourceNotFoundException) e).code()).isEqualTo("ROLE_NOT_FOUND"));
  }

  /** Gate-1 item: DELETE on a pairing that was never attached must be 404, never a silent 204. */
  @Test
  void should_throwRolePermissionNotFound_when_detachingNeverAttachedPairing() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);
    Role role = seedRole("NEVER-ATTACHED", tenantId);

    assertThatThrownBy(
            () ->
                roleManagementService.detachPermission(
                    actor, role.getId(), SAFE_PERMISSION_ID, requestContext()))
        .isInstanceOf(ResourceNotFoundException.class)
        .satisfies(
            e ->
                assertThat(((ResourceNotFoundException) e).code())
                    .isEqualTo("ROLE_PERMISSION_NOT_FOUND"));
  }

  @Test
  void should_throwRolePermissionNotFound_when_detachingAlreadyDetachedPairing() {
    UUID tenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), tenantId);
    Role role = seedRole("ALREADY-DETACHED", tenantId);
    roleManagementService.attachPermission(
        actor, role.getId(), SAFE_PERMISSION_ID, requestContext());
    roleManagementService.detachPermission(
        actor, role.getId(), SAFE_PERMISSION_ID, requestContext());

    assertThatThrownBy(
            () ->
                roleManagementService.detachPermission(
                    actor, role.getId(), SAFE_PERMISSION_ID, requestContext()))
        .isInstanceOf(ResourceNotFoundException.class)
        .satisfies(
            e ->
                assertThat(((ResourceNotFoundException) e).code())
                    .isEqualTo("ROLE_PERMISSION_NOT_FOUND"));
  }

  // ── RC-1: reserved system role names rejected at creation time ─────────────────────────

  @ParameterizedTest(name = "reserved name (case variant): {0}")
  @ValueSource(strings = {"TENANT_ADMIN", "tenant_admin", "Tenant_Admin", "MEMBER", "member"})
  void should_throwReservedRoleNameException_when_creatingRoleInTenantWithSeededSystemRoles(
      String reservedName) {
    // The bootstrap tenant has seeded TENANT_ADMIN/MEMBER system roles.
    UUID bootstrapTenantId = UUID.fromString("00000000-0000-7000-8000-000000000001");
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), bootstrapTenantId);

    assertThatThrownBy(
            () -> roleManagementService.createRole(actor, reservedName, null, requestContext()))
        .isInstanceOf(ReservedRoleNameException.class);
  }

  @ParameterizedTest(name = "reserved name (case variant), no seeded system roles: {0}")
  @ValueSource(strings = {"TENANT_ADMIN", "MEMBER"})
  void should_throwReservedRoleNameException_when_creatingRoleInTenantWithNoSeededSystemRoles(
      String reservedName) {
    // A freshly generated tenant has NO seeded system roles at all (RC-1's key point: the
    // check is unconditional, not merely "does a system role by this name already exist").
    UUID freshTenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), freshTenantId);

    assertThatThrownBy(
            () -> roleManagementService.createRole(actor, reservedName, null, requestContext()))
        .isInstanceOf(ReservedRoleNameException.class);
  }

  // ── RC-4: per-tenant role cap ────────────────────────────────────────────────────────────

  /**
   * Seeds 500 fixture roles DIRECTLY via {@link JpaRoleRepository#saveAll}, bypassing the
   * service/HTTP layer entirely — this keeps the test fast (no need for 500 real service calls)
   * and, crucially, avoids overriding {@code nexus.rbac.max-roles-per-tenant} via a
   * {@code @SpringBootTest(properties=...)} on this class, which would force Spring to boot a
   * SECOND, uncached context — breaking the shared-context convention every other {@code *IT} in
   * this run relies on. The default cap (500) is used as-is.
   */
  @Test
  void should_throwRoleLimitExceededException_when_creatingTheCapPlusOnethRoleInTenant() {
    UUID atCapTenantId = uuidGenerator.newId();
    RoleChangeActor actor = new RoleChangeActor(uuidGenerator.newId(), atCapTenantId);
    List<Role> fixtureRoles = new ArrayList<>();
    for (int i = 0; i < 500; i++) {
      fixtureRoles.add(
          new Role(uuidGenerator.newId(), atCapTenantId, "RC4-CAP-" + i + "-" + UUID.randomUUID(),
              null, false));
    }
    roleRepository.saveAll(fixtureRoles);

    assertThatThrownBy(
            () ->
                roleManagementService.createRole(
                    actor, "RC4-OVER-CAP-" + UUID.randomUUID(), null, requestContext()))
        .isInstanceOf(RoleLimitExceededException.class);

    // A second, untouched tenant must be unaffected by the first tenant's cap.
    UUID otherTenantId = uuidGenerator.newId();
    RoleChangeActor otherActor = new RoleChangeActor(uuidGenerator.newId(), otherTenantId);
    RoleView created =
        roleManagementService.createRole(
            otherActor, "RC4-OTHER-TENANT-" + UUID.randomUUID(), null, requestContext());
    assertThat(created.tenantId()).isEqualTo(otherTenantId);
  }

  // ── Fixtures / helpers ───────────────────────────────────────────────────────────────────

  private Role seedRole(String tag, UUID tenantId) {
    // is_system_role=false, randomized name: keeps RbacSchemaMigrationIT's scoped seed-role
    // count stable regardless of test execution order (see ActiveAssignmentIT's seedRole
    // Javadoc).
    return roleRepository.save(
        new Role(uuidGenerator.newId(), tenantId, "RMIT-" + tag + "-" + UUID.randomUUID(), null,
            false));
  }

  private RequestContext requestContext() {
    return RequestContext.of("127.0.0.1", "trace-" + UUID.randomUUID(), "RoleManagementIT");
  }

  private static byte[] toBytes(UUID uuid) {
    java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
