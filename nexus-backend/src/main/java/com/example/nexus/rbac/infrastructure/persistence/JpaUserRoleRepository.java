package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.domain.UserRole;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/** Spring Data JPA repository for the {@link UserRole} aggregate. */
public interface JpaUserRoleRepository extends JpaRepository<UserRole, UUID> {

  /**
   * Names of all active (non-revoked) roles assigned to a user within a tenant. JPQL (not native
   * SQL) so Hibernate's {@code UuidV7Converter} (auto-applied) handles the {@code UUID}↔{@code
   * BINARY(16)} conversion for both the join predicate and the bind parameters.
   *
   * <p>Cross-checks {@code r.tenantId} in addition to {@code ur.tenantId}: {@code
   * user_roles.tenant_id} is a denormalized copy with no DB constraint tying it to the assigned
   * role's own {@code tenant_id} (no FK exists — see {@code V5__rbac_schema.sql}). Requiring both
   * to match is defense-in-depth against a future assignment-time bug (e.g. US-012) writing a
   * mismatched {@code user_roles.tenant_id}, which would otherwise silently leak a role's
   * permissions across tenants (US-010 AC9 / threat-model T-S1 — a privilege-escalation class of
   * bug, not just a data bug).
   */
  @Query(
      """
      SELECT r.name FROM UserRole ur, Role r
      WHERE ur.roleId = r.id
        AND ur.userId = :userId
        AND ur.tenantId = :tenantId
        AND r.tenantId = :tenantId
        AND ur.revokedAt IS NULL
      """)
  List<String> findActiveRoleNames(@Param("userId") UUID userId, @Param("tenantId") UUID tenantId);

  /**
   * Deduplicated names of every permission granted (transitively, via {@code role_permissions})
   * by any active role held by a user within a tenant. Same {@code r.tenantId} cross-check as
   * {@link #findActiveRoleNames} — see that method's Javadoc.
   */
  @Query(
      """
      SELECT DISTINCT p.name FROM UserRole ur, Role r, RolePermission rp, Permission p
      WHERE ur.roleId = r.id
        AND ur.roleId = rp.id.roleId
        AND rp.id.permissionId = p.id
        AND ur.userId = :userId
        AND ur.tenantId = :tenantId
        AND r.tenantId = :tenantId
        AND ur.revokedAt IS NULL
      """)
  List<String> findActivePermissionNames(
      @Param("userId") UUID userId, @Param("tenantId") UUID tenantId);
}
