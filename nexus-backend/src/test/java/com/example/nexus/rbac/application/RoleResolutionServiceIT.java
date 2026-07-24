package com.example.nexus.rbac.application;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/**
 * US-010 QA scenarios 1-4: {@link RoleResolutionService} resolves the real, migration-seeded
 * {@code TENANT_ADMIN}/{@code MEMBER} roles (and their {@code role_permissions}) against a live
 * MySQL schema — proving the JPQL cross-entity joins in {@link JpaUserRoleRepository} actually
 * work, not just compile.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RoleResolutionServiceIT {

  // Seeded literals — V5__rbac_schema.sql header comment.
  private static final UUID BOOTSTRAP_TENANT_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final UUID TENANT_ADMIN_ROLE_ID =
      UUID.fromString("019f6839-1810-7000-8000-00000000000a");
  private static final UUID MEMBER_ROLE_ID =
      UUID.fromString("019f6839-1811-7000-8000-00000000000b");

  private static final List<String> ALL_SEEDED_PERMISSIONS =
      List.of(
          "audit:read",
          "role:read",
          "role:write",
          "tenant:read",
          "tenant:write",
          "user:read",
          "user:write");

  @Autowired private RoleResolutionService roleResolutionService;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private UuidGenerator uuidGenerator;

  @Test
  void should_resolveAllSevenPermissions_when_userHasTenantAdminRole() {
    User user = seedUser("role-res-admin");
    assignRole(user.getId(), TENANT_ADMIN_ROLE_ID);

    ResolvedPermissions resolved =
        roleResolutionService.resolve(user.getId(), BOOTSTRAP_TENANT_ID);

    assertThat(resolved.roles()).containsExactly("TENANT_ADMIN");
    assertThat(resolved.permissions()).containsExactlyInAnyOrderElementsOf(ALL_SEEDED_PERMISSIONS);
  }

  @Test
  void should_resolveUserReadOnly_when_userHasMemberRole() {
    User user = seedUser("role-res-member");
    assignRole(user.getId(), MEMBER_ROLE_ID);

    ResolvedPermissions resolved =
        roleResolutionService.resolve(user.getId(), BOOTSTRAP_TENANT_ID);

    assertThat(resolved.roles()).containsExactly("MEMBER");
    assertThat(resolved.permissions()).containsExactly("user:read");
  }

  @Test
  void should_resolveEmptyClaims_when_userHasNoRoles() {
    User user = seedUser("role-res-none");

    ResolvedPermissions resolved =
        roleResolutionService.resolve(user.getId(), BOOTSTRAP_TENANT_ID);

    assertThat(resolved.roles()).isEmpty();
    assertThat(resolved.permissions()).isEmpty();
  }

  @Test
  void should_excludeRevokedRole_when_roleWasRevoked() {
    User user = seedUser("role-res-revoked");
    UserRole assignment = assignRole(user.getId(), TENANT_ADMIN_ROLE_ID);
    revoke(assignment);

    ResolvedPermissions resolved =
        roleResolutionService.resolve(user.getId(), BOOTSTRAP_TENANT_ID);

    assertThat(resolved.roles()).isEmpty();
    assertThat(resolved.permissions()).isEmpty();
  }

  @Test
  void should_deduplicatePermissions_when_userHasBothSeededRoles() {
    User user = seedUser("role-res-both");
    assignRole(user.getId(), TENANT_ADMIN_ROLE_ID);
    assignRole(user.getId(), MEMBER_ROLE_ID);

    ResolvedPermissions resolved =
        roleResolutionService.resolve(user.getId(), BOOTSTRAP_TENANT_ID);

    assertThat(resolved.roles()).containsExactlyInAnyOrder("TENANT_ADMIN", "MEMBER");
    // user:read is granted by both roles — must appear once, not twice.
    assertThat(resolved.permissions()).containsExactlyInAnyOrderElementsOf(ALL_SEEDED_PERMISSIONS);
  }

  /**
   * US-010 AC9 / threat-model T-S1: a user's role assignment in tenant B must be invisible when
   * resolving under tenant A, even though the {@code user_roles} row itself is entirely
   * consistent (its own {@code tenant_id} matches the role's {@code tenant_id}) — proving basic
   * tenant-scoped isolation, not just the defense-in-depth cross-check below.
   */
  @Test
  void should_returnEmpty_when_userHasRoleAssignedInADifferentTenant() {
    UUID otherTenantId = uuidGenerator.newId();
    User user = seedUser("role-res-other-tenant");
    Role otherTenantRole =
        roleRepository.save(
            new Role(uuidGenerator.newId(), otherTenantId, "OTHER_TENANT_ROLE", null, false));
    userRoleRepository.save(
        new UserRole(
            uuidGenerator.newId(), user.getId(), otherTenantRole.getId(), otherTenantId,
            user.getId()));

    ResolvedPermissions resolved =
        roleResolutionService.resolve(user.getId(), BOOTSTRAP_TENANT_ID);

    assertThat(resolved.roles())
        .as("a role assigned under a different tenant must not leak into this tenant's resolution")
        .isEmpty();
    assertThat(resolved.permissions()).isEmpty();
  }

  /**
   * US-010 AC9 / threat-model T-S1 — defense-in-depth: even if a future assignment-time bug (e.g.
   * US-012) ever wrote a {@code user_roles.tenant_id} that does NOT match the assigned role's own
   * {@code tenant_id} (a data-integrity bug the schema itself does not prevent — no FK ties the
   * two), the read path must still refuse to resolve it, rather than trusting the denormalized
   * {@code user_roles.tenant_id} alone.
   */
  @Test
  void should_excludeRole_when_userRolesTenantIdMismatchesTheRolesOwnTenant() {
    UUID otherTenantId = uuidGenerator.newId();
    User user = seedUser("role-res-mismatched-tenant");
    Role otherTenantRole =
        roleRepository.save(
            new Role(uuidGenerator.newId(), otherTenantId, "MISMATCHED_ROLE", null, false));
    // Deliberately inconsistent: user_roles claims BOOTSTRAP_TENANT_ID, but the role it points to
    // actually belongs to otherTenantId.
    userRoleRepository.save(
        new UserRole(
            uuidGenerator.newId(), user.getId(), otherTenantRole.getId(), BOOTSTRAP_TENANT_ID,
            user.getId()));

    ResolvedPermissions resolved =
        roleResolutionService.resolve(user.getId(), BOOTSTRAP_TENANT_ID);

    assertThat(resolved.roles())
        .as("a role whose own tenant_id differs from user_roles.tenant_id must never resolve")
        .isEmpty();
    assertThat(resolved.permissions()).isEmpty();
  }

  private User seedUser(String tag) {
    String email = "role-res-" + tag + "-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    User user =
        new User(
            uuidGenerator.newId(),
            BOOTSTRAP_TENANT_ID,
            new EmailCipher(email),
            hmac,
            "test-hash",
            null);
    return userRepository.save(user);
  }

  private UserRole assignRole(UUID userId, UUID roleId) {
    return userRoleRepository.save(
        new UserRole(uuidGenerator.newId(), userId, roleId, BOOTSTRAP_TENANT_ID, userId));
  }

  private void revoke(UserRole assignment) {
    assignment.revoke(Instant.now());
    userRoleRepository.save(assignment);
  }
}
