package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.HolderProvenance;
import com.example.nexus.rbac.domain.PermissionViaRole;
import com.example.nexus.rbac.domain.RoleHolder;
import com.example.nexus.rbac.domain.RolePermissionRef;
import com.example.nexus.rbac.domain.RoleRef;
import com.example.nexus.rbac.domain.UserViaRole;
import com.example.nexus.rbac.domain.UserRole;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * Spring Data JPA repository for the {@link UserRole} aggregate. Additionally implements {@link
 * ZeroAdminTenantReader} (US-017 D25) so {@code RbacZeroActiveAdminsHealthIndicator} can depend on
 * a narrow read-only surface instead of this repository's full {@code save}/{@code delete}
 * capability (T-T14/RC-22.4).
 */
public interface JpaUserRoleRepository
    extends JpaRepository<UserRole, UUID>, ZeroAdminTenantReader {

  /**
   * Names of all active (non-revoked) roles assigned to a user within a tenant. JPQL (not native
   * SQL) so Hibernate's {@code UuidV7Converter} (auto-applied) handles the {@code UUID}↔{@code
   * BINARY(16)} conversion for both the join predicate and the bind parameters.
   *
   * <p>Cross-checks {@code r.tenantId} in addition to {@code ur.tenantId}: {@code
   * user_roles.tenant_id} is a denormalized copy of the assigned role's own {@code tenant_id}.
   * Since US-018 V8 the database backstops it with the composite foreign key {@code
   * fk_user_roles_role_tenant} ({@code (role_id, tenant_id)} references {@code roles (id,
   * tenant_id)}), so a mismatched row can no longer be written; requiring both to match here stays
   * as defense in depth for a leak of a role's permissions across tenants (US-010 AC9 /
   * threat-model T-S1 — a privilege-escalation class of bug, not just a data bug).
   */
  @Query(
      """
      SELECT r.name FROM UserRole ur, Role r
      WHERE ur.roleId = r.id
        AND ur.userId = :userId
        AND ur.tenantId = :tenantId
        AND r.tenantId = :tenantId
        AND r.deletedAt IS NULL
        AND ur.revokedAt IS NULL
      """)
  List<String> findActiveRoleNames(@Param("userId") UUID userId, @Param("tenantId") UUID tenantId);

  /**
   * US-019 B4 — the live roles a user actively holds within a tenant, as {@code (id, name)},
   * ordered by name then id. Same predicates as {@link #findActiveRoleNames}, including the {@code
   * r.tenantId} cross-check. Non-locking.
   */
  @Query(
      """
      SELECT new com.example.nexus.rbac.domain.RoleRef(r.id, r.name)
      FROM UserRole ur, Role r
      WHERE ur.roleId = r.id
        AND ur.userId = :userId
        AND ur.tenantId = :tenantId
        AND r.tenantId = :tenantId
        AND r.deletedAt IS NULL
        AND ur.revokedAt IS NULL
      ORDER BY r.name, r.id
      """)
  List<RoleRef> findActiveRoles(@Param("userId") UUID userId, @Param("tenantId") UUID tenantId);

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
        AND r.deletedAt IS NULL
        AND ur.revokedAt IS NULL
      """)
  List<String> findActivePermissionNames(
      @Param("userId") UUID userId, @Param("tenantId") UUID tenantId);

  /**
   * M11 (US-017 D6) — locks (PESSIMISTIC_WRITE) and returns the (assignmentId, userId) pair for
   * every ACTIVE assignment of ANY role in {@code roleIds} within {@code tenantId}. Supersedes and
   * REPLACES the removed M1 {@code lockActiveAssignmentsByRole} — a singleton {@code roleIds} is a
   * strict superset of M1's one-role lock.
   *
   * <p>Driven off {@code roleId} (the leading column of fk_user_roles_role_tenant, V8) as an IN-list range — NEVER {@code
   * tenantId} as the primary predicate — and NO join with {@code Role}: joining would widen the
   * lock beyond {@code user_roles} (lock-scope discipline inherited verbatim from M1). {@code
   * tenantId} remains a residual defense-in-depth predicate (T-S1).
   *
   * <p>{@code roleIds} MUST be sorted ASCENDING by the caller, by <b>unsigned byte-wise order of
   * the 16-byte representation</b> matching MySQL's {@code BINARY(16)} comparison — NOT {@link
   * UUID#compareTo}, which compares {@code mostSigBits} as a SIGNED long (D6's deadlock-freedom
   * argument; MC-E asserts this exact comparator).
   *
   * <p>Returns ids only, never entities — the caller must not be able to load-mutate-save a
   * {@link UserRole}.
   *
   * <p><b>Native, with an explicit {@code FORCE INDEX} (MC-C, D8):</b> the JPQL/{@code @Lock} form
   * this method originally used let MySQL's optimizer fall back to a full table scan ({@code key =
   * NULL}) at larger {@code roleIds} IN-list cardinalities (empirically confirmed reproducible,
   * deterministic, in isolation — not a cross-test statistics artifact — via {@code
   * LastAdminLockoutIT#should_pinKeyToFkUserRolesRole_acrossInListCardinalities_forM11AndM5b_MCC}
   * at size 25), which breaks D8's containment proof exactly as M5's own Javadoc describes for the
   * analogous JPQL-vs-native problem. Spring Data JPA does not support combining {@code @Lock}
   * with {@code nativeQuery = true} (same constraint as M5/M5b), so {@code FOR UPDATE} is rendered
   * directly instead of {@code PESSIMISTIC_WRITE}. Bind parameters are {@code byte[]}, not {@code
   * UUID} — native queries bypass the entity-mapped {@code UuidV7Converter} on the way in, same as
   * M5/M5b. Returns full entities at the JPA layer (like M5b) but the adapter maps them down to
   * {@link ActiveAssignmentHolder} before they escape the persistence boundary, preserving the
   * "ids only" contract above.
   */
  @Query(
      value =
          """
          SELECT * FROM user_roles FORCE INDEX (fk_user_roles_role_tenant)
          WHERE role_id IN (:roleIds) AND tenant_id = :tenantId AND revoked_at IS NULL
          FOR UPDATE
          """,
      nativeQuery = true)
  List<UserRole> lockActiveAssignmentHoldersByRoles(
      @Param("roleIds") Collection<byte[]> roleIds, @Param("tenantId") byte[] tenantId);

  /**
   * M13 (US-018, 03-design.md §4.3) — the {@code (roleId, permissionId)} pairs a user holds through
   * active assignments in one tenant. This is <b>the</b> read for grant-subset authorization
   * decisions (ADR-0021 D2); contrast M12 above, which must never be used for one.
   *
   * <p>Driven off {@code fk_user_roles_user} ({@code ur.userId}). Joins {@code Role} with {@code
   * r.tenantId = ur.tenantId} (T-S1): {@code user_roles.tenant_id} has no constraint tying it to
   * the role's own tenant until the composite FK lands, so a drifted row must not widen the
   * caller's holdings. Does not join {@code Permission}: ids only, no names.
   *
   * <p>Plain, NON-LOCKING snapshot read; MUST NEVER be annotated {@code @Lock} (MC-A).
   */
  @Query(
      """
      SELECT new com.example.nexus.rbac.domain.RolePermissionRef(rp.id.roleId, rp.id.permissionId)
      FROM UserRole ur, Role r, RolePermission rp
      WHERE ur.roleId = r.id AND r.tenantId = ur.tenantId AND rp.id.roleId = r.id
        AND r.deletedAt IS NULL
        AND ur.userId = :userId AND ur.tenantId = :tenantId AND ur.revokedAt IS NULL
      """)
  List<RolePermissionRef> findHeldRolePermissionIdsForAuthorization(
      @Param("userId") UUID userId, @Param("tenantId") UUID tenantId);

  /**
   * M2 — duplicate-active pre-check (AC1). Deliberately NO tenant predicate: must mirror the
   * {@code uq_user_role_active (user_id, role_id)} DB constraint exactly, or a row with a drifted
   * {@code tenant_id} could slip past this check and surface as an untranslated 500 instead of
   * 409.
   */
  @Query(
      "SELECT COUNT(ur) FROM UserRole ur WHERE ur.userId = :userId AND ur.roleId = :roleId AND"
          + " ur.revokedAt IS NULL")
  long countActiveByUserAndRole(@Param("userId") UUID userId, @Param("roleId") UUID roleId);

  /**
   * M3 — the active assignment to revoke, as a PROJECTION (not a managed {@link UserRole} entity —
   * a managed entity here would let a future caller invoke its documented {@code revoke(Instant)}
   * method, which Hibernate would flush as a multi-column UPDATE that a least-privilege DB grant
   * rejects in production only, invisible to every test that connects as a superuser).
   */
  @Query(
      """
      SELECT new com.example.nexus.rbac.domain.ActiveAssignmentRef(ur.id, ur.assignedAt)
      FROM UserRole ur
      WHERE ur.userId = :userId AND ur.roleId = :roleId
        AND ur.tenantId = :tenantId AND ur.revokedAt IS NULL
      """)
  Optional<com.example.nexus.rbac.domain.ActiveAssignmentRef> findActiveAssignmentRef(
      @Param("userId") UUID userId, @Param("roleId") UUID roleId, @Param("tenantId") UUID tenantId);

  /**
   * M4/M4a — one page of the active assignments projected with the role's name (AC3, and the 201
   * response body via {@link #findActiveAssignmentView}), paginated by US-018 C2. Single comma-join
   * projection, mirroring this repository's own existing {@link #findActiveRoleNames} style,
   * including its {@code r.tenantId} cross-check (defense-in-depth against a drifted {@code
   * user_roles.tenant_id} leaking a role across tenants) and the live-role filter. {@code ORDER BY
   * ur.assignedAt, ur.id}: a total order, so pages neither overlap nor skip. The sort is in the
   * query; pass an UNSORTED {@link Pageable}. The tenant predicate is on both queries.
   */
  @Query(
      value =
          """
          SELECT new com.example.nexus.rbac.domain.ActiveRoleAssignment(
                   ur.userId, ur.roleId, r.name, ur.assignedAt, ur.assignedBy)
          FROM UserRole ur, Role r
          WHERE ur.roleId = r.id
            AND ur.userId = :userId
            AND ur.tenantId = :tenantId
            AND r.tenantId = :tenantId
            AND r.deletedAt IS NULL
            AND ur.revokedAt IS NULL
          ORDER BY ur.assignedAt, ur.id
          """,
      countQuery =
          """
          SELECT COUNT(ur) FROM UserRole ur, Role r
          WHERE ur.roleId = r.id
            AND ur.userId = :userId
            AND ur.tenantId = :tenantId
            AND r.tenantId = :tenantId
            AND r.deletedAt IS NULL
            AND ur.revokedAt IS NULL
          """)
  Page<com.example.nexus.rbac.domain.ActiveRoleAssignment> findActiveAssignmentViews(
      @Param("userId") UUID userId, @Param("tenantId") UUID tenantId, Pageable pageable);

  /** See {@link #findActiveAssignmentViews} — same shape, scoped to a single role. */
  @Query(
      """
      SELECT new com.example.nexus.rbac.domain.ActiveRoleAssignment(
               ur.userId, ur.roleId, r.name, ur.assignedAt, ur.assignedBy)
      FROM UserRole ur, Role r
      WHERE ur.roleId = r.id
        AND ur.userId = :userId
        AND ur.roleId = :roleId
        AND ur.tenantId = :tenantId
        AND r.tenantId = :tenantId
        AND r.deletedAt IS NULL
        AND ur.revokedAt IS NULL
      """)
  Optional<com.example.nexus.rbac.domain.ActiveRoleAssignment> findActiveAssignmentView(
      @Param("userId") UUID userId, @Param("roleId") UUID roleId, @Param("tenantId") UUID tenantId);

  /**
   * The assign INSERT, made conditional on the role being live (US-018 C1, RC-36.1): {@code INSERT …
   * SELECT … FROM roles WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL}. Under REPEATABLE READ
   * the INSERT takes a shared lock on the source {@code roles} row as part of the statement, needs
   * only {@code SELECT} on {@code roles} (a {@code FOR SHARE} read there would need {@code UPDATE}
   * and fail in production while passing Testcontainers as superuser, the US-016 D5 trap), and
   * inserts <b>zero rows</b> when the role was deleted: the caller maps 0 to 404. {@code tenant_id}
   * of the new row is the role's own, so the composite foreign key of V8 always holds.
   *
   * <p>Native, so the bind parameters are {@code byte[]} (the entity-mapped {@code UuidV7Converter}
   * is bypassed, as in {@link #lockActiveAssignmentHoldersByRoles}). {@code assigned_at} and {@code
   * active_key} are filled by the database. {@code uq_user_role_active} still rejects a duplicate
   * active assignment, which the adapter maps to 409 {@code RBAC_004}.
   */
  @Modifying
  @Query(
      value =
          """
          INSERT INTO user_roles (id, user_id, role_id, tenant_id, assigned_by)
          SELECT :id, :userId, r.id, r.tenant_id, :assignedBy
          FROM roles r
          WHERE r.id = :roleId AND r.tenant_id = :tenantId AND r.deleted_at IS NULL
          """,
      nativeQuery = true)
  int assignIfRoleLive(
      @Param("id") byte[] id,
      @Param("userId") byte[] userId,
      @Param("roleId") byte[] roleId,
      @Param("tenantId") byte[] tenantId,
      @Param("assignedBy") byte[] assignedBy);

  /**
   * M6 — the revocation write. MUST be exactly this shape: a bulk single-column JPQL UPDATE, never
   * {@code findById->revoke()->save()} (that emits a multi-column UPDATE a least-privilege DB grant
   * rejects, in production only). Returns affected-row count: this int IS the concurrency guard
   * ({@link UserRole} has no {@code @Version}) — 1 = revoked, 0 = already revoked/vanished.
   *
   * <p>{@code revokedAt} is supplied by the caller (an app-side clamp — {@code max(now,
   * assignedAt)}, see {@link com.example.nexus.rbac.domain.ActiveAssignmentRef}) rather than
   * computed DB-side via {@code FUNCTION('now', 6)}: that construct is valid MySQL but was found,
   * empirically against this codebase's pinned Hibernate version, to fail HQL parsing at
   * repository-proxy-creation time with {@code "Function now() has 0 parameters, but 1 arguments
   * given"} — this Hibernate version's registered {@code now} function template takes no
   * arguments. Since the whole *point* of the original DB-side approach was to avoid a
   * clock-skew/precision mismatch between the app and MySQL's {@code assigned_at} default, the
   * app-side clamp achieves the same CHECK-constraint safety by construction: it can never produce
   * a {@code revokedAt} earlier than the {@code assignedAt} it was handed.
   */
  @Modifying(clearAutomatically = true)
  @Query("UPDATE UserRole ur SET ur.revokedAt = :revokedAt WHERE ur.id = :id AND ur.revokedAt IS NULL")
  int revokeById(@Param("id") UUID id, @Param("revokedAt") java.time.Instant revokedAt);

  /**
   * C3 role holders (US-018 T-029): one page of the ACTIVE holders of one live role of one tenant,
   * {@code ORDER BY assignedAt, id} (a total order). The caller resolves the role in the tenant first
   * (404 otherwise); this query still carries the tenant and live-role predicates on both the page and
   * the count query as defense in depth. Served through the {@code (role_id, tenant_id)} index
   * (V7/V8). Plain, NON-LOCKING; ids and a timestamp only.
   */
  @Query(
      value =
          """
          SELECT new com.example.nexus.rbac.domain.RoleHolder(ur.userId, ur.id, ur.assignedAt, ur.assignedBy)
          FROM UserRole ur, Role r
          WHERE ur.roleId = r.id AND ur.roleId = :roleId
            AND ur.tenantId = :tenantId AND r.tenantId = :tenantId
            AND r.deletedAt IS NULL AND ur.revokedAt IS NULL
          ORDER BY ur.assignedAt, ur.id
          """,
      countQuery =
          """
          SELECT COUNT(ur) FROM UserRole ur, Role r
          WHERE ur.roleId = r.id AND ur.roleId = :roleId
            AND ur.tenantId = :tenantId AND r.tenantId = :tenantId
            AND r.deletedAt IS NULL AND ur.revokedAt IS NULL
          """)
  Page<RoleHolder> findActiveRoleHoldersPage(
      @Param("roleId") UUID roleId, @Param("tenantId") UUID tenantId, Pageable pageable);

  /**
   * C3 permission holders, step 1 (US-018 T-029): one page of the DISTINCT users who hold {@code
   * permissionId} through an active assignment of a live role of the tenant, ordered by user id.
   * Driven by {@code role_permissions.permission_id} (its foreign-key index), then the tenant's live
   * roles, then {@code user_roles}. Paging is over distinct users, so a user who holds the permission
   * through several roles is counted and listed once. Non-locking; ids only.
   */
  @Query(
      value =
          """
          SELECT DISTINCT ur.userId FROM UserRole ur, Role r, RolePermission rp
          WHERE rp.id.permissionId = :permissionId AND rp.id.roleId = r.id
            AND r.tenantId = :tenantId AND r.deletedAt IS NULL
            AND ur.roleId = r.id AND ur.tenantId = :tenantId AND ur.revokedAt IS NULL
          ORDER BY ur.userId
          """,
      countQuery =
          """
          SELECT COUNT(DISTINCT ur.userId) FROM UserRole ur, Role r, RolePermission rp
          WHERE rp.id.permissionId = :permissionId AND rp.id.roleId = r.id
            AND r.tenantId = :tenantId AND r.deletedAt IS NULL
            AND ur.roleId = r.id AND ur.tenantId = :tenantId AND ur.revokedAt IS NULL
          """)
  Page<UUID> findPermissionHolderUserIdsPage(
      @Param("permissionId") UUID permissionId,
      @Param("tenantId") UUID tenantId,
      Pageable pageable);

  /**
   * C3 permission holders, step 2: the live roles through which each of the page's users holds the
   * permission. Same predicates as step 1, restricted to {@code userIds} (at most one page, 100).
   * Non-locking.
   */
  @Query(
      """
      SELECT new com.example.nexus.rbac.domain.UserViaRole(ur.userId, r.id)
      FROM UserRole ur, Role r, RolePermission rp
      WHERE rp.id.permissionId = :permissionId AND rp.id.roleId = r.id
        AND r.tenantId = :tenantId AND r.deletedAt IS NULL
        AND ur.roleId = r.id AND ur.tenantId = :tenantId AND ur.revokedAt IS NULL
        AND ur.userId IN :userIds
      ORDER BY ur.userId, r.id
      """)
  List<UserViaRole> findPermissionHolderRoles(
      @Param("permissionId") UUID permissionId,
      @Param("tenantId") UUID tenantId,
      @Param("userIds") Collection<UUID> userIds);

  /**
   * C3 effective permissions (US-018 T-029): every {@code (permission name, role id)} pair a user
   * holds through active assignments of live roles in one tenant, in one statement so the names and
   * the roles come from the same snapshot. Same {@code r.tenantId} cross-check and live-role filter
   * as {@link #findActivePermissionNames}. Bounded by the catalogue times the tenant's roles.
   * Non-locking; names and ids only.
   */
  @Query(
      """
      SELECT new com.example.nexus.rbac.domain.PermissionViaRole(p.name, r.id)
      FROM UserRole ur, Role r, RolePermission rp, Permission p
      WHERE ur.roleId = r.id AND rp.id.roleId = r.id AND rp.id.permissionId = p.id
        AND ur.userId = :userId AND ur.tenantId = :tenantId AND r.tenantId = :tenantId
        AND r.deletedAt IS NULL AND ur.revokedAt IS NULL
      ORDER BY p.name, r.id
      """)
  List<PermissionViaRole> findActivePermissionsViaRoles(
      @Param("userId") UUID userId, @Param("tenantId") UUID tenantId);

  /**
   * RC-6 — every user id holding an ACTIVE (non-revoked) assignment of {@code roleId}. Backs
   * {@link com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort#findActiveUserIdsForRole}
   * — see that method's Javadoc for why this is deliberately not tenant-scoped.
   */
  @Query("SELECT ur.userId FROM UserRole ur WHERE ur.roleId = :roleId AND ur.revokedAt IS NULL")
  List<UUID> findActiveUserIdsByRole(@Param("roleId") UUID roleId);

  /**
   * M16 (US-018 T-018, RC-28.1, RC-50(b)) — the ids of the roles, among the user's ACTIVE
   * assignments in one tenant, that carry every permission of the catalogue: {@code GROUP BY
   * ur.role_id HAVING COUNT(DISTINCT permission) = (catalogue count)}. It is the independent
   * runtime check behind {@code RBAC_SELF_ASSIGN_ADMIN_DISAGREEMENT}: it shares no input with M13
   * (a different statement, its own {@code r.tenantId = ur.tenantId} and active-assignment
   * predicates, and the catalogue COUNT computed in the database, not passed in).
   *
   * <p>Per role, never the union (a union-level count would match every union-holder). An empty
   * catalogue matches nothing (no group can equal a count of zero). Driven off {@code
   * fk_user_roles_user}. Plain, NON-LOCKING; MUST NEVER be annotated {@code @Lock} (MC-A), and
   * MUST NEVER be used for an authorization decision.
   */
  @Query(
      """
      SELECT ur.roleId FROM UserRole ur, Role r, RolePermission rp, Permission p
      WHERE ur.userId = :userId AND ur.tenantId = :tenantId AND ur.revokedAt IS NULL
        AND r.id = ur.roleId AND r.tenantId = ur.tenantId AND r.deletedAt IS NULL
        AND rp.id.roleId = r.id AND rp.id.permissionId = p.id
      GROUP BY ur.roleId
      HAVING COUNT(DISTINCT p.id) = (SELECT COUNT(p2) FROM Permission p2)
      """)
  List<UUID> findHeldAdminDefiningRoleIds(
      @Param("userId") UUID userId, @Param("tenantId") UUID tenantId);

  /**
   * US-018 T-017 (row 13, row 14) — every active holder of {@code roleId} in {@code tenantId} with
   * the user who assigned them. Tenant-scoped by predicate. Plain, NON-LOCKING.
   */
  @Query(
      """
      SELECT new com.example.nexus.rbac.domain.HolderProvenance(ur.userId, ur.assignedBy)
      FROM UserRole ur
      WHERE ur.roleId = :roleId AND ur.tenantId = :tenantId AND ur.revokedAt IS NULL
      """)
  List<HolderProvenance> findActiveHoldersByRole(
      @Param("roleId") UUID roleId, @Param("tenantId") UUID tenantId);

  /**
   * US-018 T-017 — the distinct users holding an ACTIVE assignment of any role in {@code roleIds}
   * within {@code tenantId}: with the admin-defining role ids, the tenant's administrator user
   * set. The caller never passes an empty collection. Plain, NON-LOCKING.
   */
  @Query(
      """
      SELECT DISTINCT ur.userId FROM UserRole ur
      WHERE ur.roleId IN :roleIds AND ur.tenantId = :tenantId AND ur.revokedAt IS NULL
      """)
  List<UUID> findActiveHolderUserIdsByRoles(
      @Param("roleIds") Collection<UUID> roleIds, @Param("tenantId") UUID tenantId);

  /**
   * Row 15 — health-check support only, {@link ZeroAdminTenantReader}'s driving set: tenants with
   * AT LEAST ONE admin-defining role, i.e. a role whose {@code COUNT(DISTINCT permission)} equals
   * the catalogue count. No names are passed. The {@code COUNT > 0} guard fails closed on an empty
   * catalogue (otherwise every role would "carry" zero of zero). Read-only, no locking: this runs
   * on a health-check cadence and must never contend with the M11 locking read. JPQL, for the
   * {@code UuidV7Converter}.
   */
  @Override
  @Query(
      """
      SELECT DISTINCT r.tenantId FROM Role r
      WHERE r.deletedAt IS NULL
        AND (SELECT COUNT(DISTINCT p.id) FROM RolePermission rp, Permission p
             WHERE rp.id.roleId = r.id AND rp.id.permissionId = p.id)
              = (SELECT COUNT(p2) FROM Permission p2)
        AND (SELECT COUNT(p3) FROM Permission p3) > 0
      """)
  List<UUID> findTenantsWithAnAdminDefiningRole();

  /**
   * Row 15 — tenants with AT LEAST ONE active holder of some admin-defining role (same definition
   * as {@link #findTenantsWithAnAdminDefiningRole}). Differenced against it in Java: the
   * tenant-level question is not a role-level {@code NOT EXISTS} once a tenant has more than one
   * admin-defining role.
   */
  @Override
  @Query(
      """
      SELECT DISTINCT r.tenantId FROM Role r, UserRole ur
      WHERE ur.roleId = r.id AND ur.tenantId = r.tenantId AND ur.revokedAt IS NULL
        AND r.deletedAt IS NULL
        AND (SELECT COUNT(DISTINCT p.id) FROM RolePermission rp, Permission p
             WHERE rp.id.roleId = r.id AND rp.id.permissionId = p.id)
              = (SELECT COUNT(p2) FROM Permission p2)
        AND (SELECT COUNT(p3) FROM Permission p3) > 0
      """)
  List<UUID> findTenantsWithActiveAdminDefiningHolders();

  /**
   * RC-36.4 invariant detector (US-018 T-026) — the number of ACTIVE {@code user_roles} rows that
   * reference a soft-deleted role. By the delete protocol it is always 0 (a role is deleted only
   * with no active holder, and assign inserts only against a live role), so any other value is an
   * invariant break that must page. A count only, never ids.
   *
   * <p>Native, and deliberately the one query that must see DELETED roles: a JPQL query on {@code
   * Role} would be filtered by {@code @SQLRestriction} and could never find one. Read-only,
   * non-locking; runs under the indicator's 30 s actuator cache.
   */
  @Override
  @Query(
      value =
          """
          SELECT COUNT(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id
          WHERE r.deleted_at IS NOT NULL AND ur.revoked_at IS NULL
          """,
      nativeQuery = true)
  long countActiveAssignmentsOnDeletedRolesInAnyTenant();
}
