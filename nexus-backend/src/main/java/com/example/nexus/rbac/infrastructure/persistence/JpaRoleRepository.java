package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermissionRef;
import com.example.nexus.rbac.domain.RoleView;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
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
   * M14 (US-018, 03-design.md §4.3) — the permission ids attached to one role of one tenant,
   * served by the {@code roles} primary key and the {@code role_permissions} primary-key prefix.
   * Hosted here so the assignment adapter reads it without a dependency on the repository that
   * writes {@code role_permissions}. The {@code r.tenantId} predicate satisfies the
   * tenant-isolation ArchUnit gate (T-S1).
   *
   * <p>Fail-closed shape (07-security-review.md L-2): driven off {@code roles} with a LEFT JOIN, so
   * the two "nothing to grant" cases stay distinguishable in ONE statement. An EMPTY list means the
   * role is not in {@code tenantId} (or does not exist); a role in the tenant with no permissions
   * yields exactly one {@code null} element; otherwise one element per attached permission id. The
   * adapter maps this to {@code Optional<Set<UUID>>}. No {@code @Lock} (MC-A).
   */
  @Query(
      "SELECT rp.id.permissionId FROM Role r "
          + "LEFT JOIN RolePermission rp ON rp.id.roleId = r.id "
          + "WHERE r.id = :roleId AND r.tenantId = :tenantId")
  List<UUID> findPermissionIdsByRoleAndTenantId(
      @Param("roleId") UUID roleId, @Param("tenantId") UUID tenantId);

  /**
   * Q12 — RC-4's per-tenant role cap check. Served by {@code uq_roles_tenant_name}'s leftmost
   * prefix — same index as Q1, no new cost (03-design.md §5.2).
   */
  long countByTenantId(UUID tenantId);

  /**
   * M10' (US-018 T-016, replaces M10) — every {@code (roleId, permissionId)} pair for the roles of
   * ONE tenant. Bounded at {@code nexus.rbac.max-roles-per-tenant} (default 500) x |permissions|.
   * Ids only: the administrator definition is applied in {@code rbac.domain.RbacAdministrators},
   * never here and never by passing a list of names.
   *
   * <p>MUST be a plain, NON-LOCKING read and MUST NEVER be annotated {@code @Lock} (MC-A). It does
   * not join {@code permissions}. Comma-join JPQL, so {@code UuidV7Converter} handles {@code UUID}
   * <-> {@code BINARY(16)}. Driven by {@code uq_roles_tenant_name}'s leftmost {@code tenant_id}
   * prefix into {@code pk_role_permissions}'s leftmost {@code role_id} prefix.
   *
   * <p>Roles with zero permissions do not appear: they are never admin-defining.
   */
  @Query(
      """
      SELECT new com.example.nexus.rbac.domain.RolePermissionRef(rp.id.roleId, rp.id.permissionId)
      FROM Role r, RolePermission rp
      WHERE rp.id.roleId = r.id AND r.tenantId = :tenantId
      """)
  List<RolePermissionRef> findRolePermissionIdsByTenantRoles(@Param("tenantId") UUID tenantId);

  /**
   * C1 DELETE's write (US-018 T-025): a bulk single-column {@code UPDATE}, never {@code
   * findById->set->save} (that would flush a multi-column UPDATE; the {@code nexus_app} grant is
   * column-scoped to {@code name}, {@code description} and {@code deleted_at}). The affected-row
   * count is the concurrency guard: {@code 0} means the role is already deleted, missing or in
   * another tenant. {@code updated_at} is refreshed by the database ({@code ON UPDATE}), which needs
   * no column privilege.
   */
  @Modifying(clearAutomatically = true)
  @Query(
      "UPDATE Role r SET r.deletedAt = :deletedAt "
          + "WHERE r.id = :roleId AND r.tenantId = :tenantId AND r.deletedAt IS NULL")
  int softDelete(
      @Param("roleId") UUID roleId,
      @Param("tenantId") UUID tenantId,
      @Param("deletedAt") Instant deletedAt);
}
