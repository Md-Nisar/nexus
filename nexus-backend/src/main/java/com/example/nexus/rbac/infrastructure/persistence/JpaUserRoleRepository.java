package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.HolderProvenance;
import com.example.nexus.rbac.domain.RolePermissionRef;
import com.example.nexus.rbac.domain.UserRole;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
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

  /**
   * M11 (US-017 D6) — locks (PESSIMISTIC_WRITE) and returns the (assignmentId, userId) pair for
   * every ACTIVE assignment of ANY role in {@code roleIds} within {@code tenantId}. Supersedes and
   * REPLACES the removed M1 {@code lockActiveAssignmentsByRole} — a singleton {@code roleIds} is a
   * strict superset of M1's one-role lock.
   *
   * <p>Driven off {@code roleId} (fk_user_roles_role) as an IN-list range — NEVER {@code
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
          SELECT * FROM user_roles FORCE INDEX (fk_user_roles_role)
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
   * M4/M4a — active assignments projected with the role's name (AC3, and the 201 response body).
   * Single comma-join projection, mirroring this repository's own existing {@link
   * #findActiveRoleNames} style, including its {@code r.tenantId} cross-check (defense-in-depth
   * against a drifted {@code user_roles.tenant_id} leaking a role across tenants). {@code ORDER BY
   * r.name} for a stable contract.
   */
  @Query(
      """
      SELECT new com.example.nexus.rbac.domain.ActiveRoleAssignment(
               ur.userId, ur.roleId, r.name, ur.assignedAt, ur.assignedBy)
      FROM UserRole ur, Role r
      WHERE ur.roleId = r.id
        AND ur.userId = :userId
        AND ur.tenantId = :tenantId
        AND r.tenantId = :tenantId
        AND ur.revokedAt IS NULL
      ORDER BY r.name
      """)
  List<com.example.nexus.rbac.domain.ActiveRoleAssignment> findActiveAssignmentViews(
      @Param("userId") UUID userId, @Param("tenantId") UUID tenantId);

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
        AND ur.revokedAt IS NULL
      """)
  Optional<com.example.nexus.rbac.domain.ActiveRoleAssignment> findActiveAssignmentView(
      @Param("userId") UUID userId, @Param("roleId") UUID roleId, @Param("tenantId") UUID tenantId);

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
        AND r.id = ur.roleId AND r.tenantId = ur.tenantId
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
      WHERE (SELECT COUNT(DISTINCT p.id) FROM RolePermission rp, Permission p
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
        AND (SELECT COUNT(DISTINCT p.id) FROM RolePermission rp, Permission p
             WHERE rp.id.roleId = r.id AND rp.id.permissionId = p.id)
              = (SELECT COUNT(p2) FROM Permission p2)
        AND (SELECT COUNT(p3) FROM Permission p3) > 0
      """)
  List<UUID> findTenantsWithActiveAdminDefiningHolders();
}
