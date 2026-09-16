package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.domain.Permission;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermission;
import com.example.nexus.rbac.domain.RoleView;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/** Spring Data JPA repository for the {@link Role} aggregate. */
public interface JpaRoleRepository extends JpaRepository<Role, UUID> {

  /**
   * Q1 — US-015 AC2. All roles in a tenant, projected (never the entity — see {@link RoleView}'s
   * Javadoc), {@code ORDER BY name} for a stable unpaginated contract (D11). Served by {@code
   * uq_roles_tenant_name}'s leftmost {@code tenant_id} prefix — no new index (03-design.md §5.2).
   */
  @Query(
      """
      SELECT new com.example.nexus.rbac.domain.RoleView(
               r.id, r.tenantId, r.name, r.description, r.systemRole, r.createdAt)
      FROM Role r
      WHERE r.tenantId = :tenantId
      ORDER BY r.name
      """)
  List<RoleView> findRoleViewsByTenantId(@Param("tenantId") UUID tenantId);

  /**
   * Q2 — single-role lookup, projected (never the entity — see {@link RoleView}'s Javadoc).
   * {@code findById} must not be used here: it returns a managed {@link Role} entity, the exact
   * thing this projection exists to avoid (03-design.md §4.3, R-6).
   */
  @Query(
      """
      SELECT new com.example.nexus.rbac.domain.RoleView(
               r.id, r.tenantId, r.name, r.description, r.systemRole, r.createdAt)
      FROM Role r
      WHERE r.id = :roleId
      """)
  Optional<RoleView> findRoleViewById(@Param("roleId") UUID roleId);

  /**
   * Q3 — US-015 AC11, the method F1 identifies as the story's single most likely silent failure
   * point. Resolves the tenant's admin role id by {@code (tenantId, name)}. MUST use a plain
   * {@code r.name = :name} predicate and rely on {@code utf8mb4_0900_ai_ci} for
   * case-insensitivity, so {@code uq_roles_tenant_name} is used as an index — never wrap the
   * column in {@code UPPER()}, which would de-sargonise this write-hot-path query
   * (03-design.md §5.2). Returns the id only, never the entity.
   */
  @Query("SELECT r.id FROM Role r WHERE r.tenantId = :tenantId AND r.name = :name")
  Optional<UUID> findIdByTenantIdAndName(@Param("tenantId") UUID tenantId, @Param("name") String name);

  /**
   * M7 (US-016 D16, RC-12) — the names of every permission attached to {@code roleId}. Hosted
   * here, not on {@code JpaRolePermissionRepository}, so {@link JpaUserRoleAssignmentAdapter} can
   * read permission names without gaining any dependency on the repository that holds write
   * access over {@code role_permissions} (03-design.md §4.4/§4.5, T-T13). Two-entity comma-join JPQL —
   * {@link Role} has no mapped association to {@link RolePermission} — never native SQL, so
   * Hibernate's auto-applied {@code UuidV7Converter} handles {@code UUID} <-> {@code BINARY(16)}
   * for both the predicate and the bind parameter. No {@code @Lock} (MC-1): {@code nexus_app}
   * holds SELECT only on {@code permissions}. No {@code ORDER BY}: the caller treats the result
   * as a set.
   */
  @Query(
      "SELECT p.name FROM RolePermission rp, Permission p "
          + "WHERE rp.id.permissionId = p.id AND rp.id.roleId = :roleId")
  List<String> findPermissionNamesByRole(@Param("roleId") UUID roleId);

  /**
   * Q12 — RC-4's per-tenant role cap check. Served by {@code uq_roles_tenant_name}'s leftmost
   * prefix — same index as Q1, no new cost (03-design.md §5.2).
   */
  long countByTenantId(UUID tenantId);
}
