package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.RolePermissionName;
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
 * capability — zero query changes, zero behaviour change (T-T14/RC-22.4).
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
   * M5b (US-017 D8) — generalises M5 ({@link #lockActiveAdminAssignment}) from one {@code roleId}
   * to a set. Same non-negotiable contract: native, {@code FOR SHARE}, {@code FORCE INDEX
   * (fk_user_roles_role)} so every index record it requests is inside M11's X region (D8's
   * containment proof; MC-C). Bind parameters are {@code byte[]}, not {@code UUID} — same reason
   * as {@link #lockActiveAdminAssignment}.
   *
   * <p>An EMPTY {@code roleIds} means the caller has no way to qualify: the caller MUST fail
   * closed and MUST NOT call this method at all (R-10 / T-E18 precedent).
   */
  @Query(
      value =
          """
          SELECT * FROM user_roles FORCE INDEX (fk_user_roles_role)
          WHERE user_id = :userId AND role_id IN (:roleIds)
            AND tenant_id = :tenantId AND revoked_at IS NULL
          FOR SHARE
          """,
      nativeQuery = true)
  List<UserRole> lockActiveAssignmentOfAnyRole(
      @Param("userId") byte[] userId,
      @Param("roleIds") Collection<byte[]> roleIds,
      @Param("tenantId") byte[] tenantId);

  /**
   * M12 (US-017 D24) — every (roleId, permissionName) pair for the roles of the CALLER'S OWN
   * active assignments in one tenant. Sibling of M7, keyed by USER rather than by role.
   *
   * <p>Exists solely to give the self-assignment bypass canary a derivation that shares NO INPUT
   * with the gate. MUST be driven off {@code fk_user_roles_user} — a different index, a different
   * statement and a different scoping from M10 (tenant-scoped, driven off {@code r.tenantId}). An
   * over-broad M10 therefore cannot silence the canary that exists to notice it (T-E29). MUST NOT
   * reuse M10's query or delegate to it.
   *
   * <p>MUST be a plain, NON-LOCKING read, and MUST NEVER be used for an authorization decision —
   * the gate's only determination is M5b, a fresh locking read (T-E7). MC-G asserts this negative
   * on both verbs.
   */
  @Query(
      """
      SELECT new com.example.nexus.rbac.domain.RolePermissionName(rp.id.roleId, p.name)
      FROM UserRole ur, RolePermission rp, Permission p
      WHERE ur.roleId = rp.id.roleId AND rp.id.permissionId = p.id
        AND ur.userId = :userId AND ur.tenantId = :tenantId AND ur.revokedAt IS NULL
      """)
  List<RolePermissionName> findPermissionNamesForActiveAssignmentsOfUser(
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
   * M5 — AC8's live-admin check on the CALLER. MUST be a LOCKING read (renders {@code FOR SHARE}
   * directly in this native query, since Spring Data JPA does not support combining {@code @Lock}
   * with {@code nativeQuery = true}), never a plain COUNT: a non-locking read is a
   * REPEATABLE-READ snapshot that can miss a concurrent revocation of the caller's own admin
   * assignment (a real, if narrow, race). Returns entities (not a scalar) because a locking read
   * on a COUNT projection is implementation-defined under JPA — the adapter should only ever
   * inspect {@code .size()} / {@code .isEmpty()}, never mutate these.
   *
   * <p><b>Native, with an explicit {@code FORCE INDEX} (MC-5, RC-9.1, 03-design.md §7.2 step
   * 1):</b> the JPQL equivalent let MySQL's optimizer choose {@code fk_user_roles_user} over
   * {@code fk_user_roles_role} for this predicate, which breaks D8's containment proof — M11's X
   * lock (driven by {@code fk_user_roles_role}) no longer provably covers every record this read
   * requests. Forcing the same index M11 uses makes containment exact again, empirically confirmed
   * by {@code LastAdminLockoutIT#should_driveBothM11AndM5OffTheRoleIndex_when_explainingCapturedLockingReads}.
   * Bind parameters are {@code byte[]}, not {@code UUID}: native queries do not go through the
   * entity-mapped {@code UuidV7Converter} on the way IN, so the adapter converts explicitly (see
   * {@code JpaUserRoleAssignmentAdapter#hasActiveAdminAssignment}). The result set ({@code SELECT
   * *}, matching every {@link UserRole}-mapped column) is unaffected — the converter still applies
   * on the way OUT when Hibernate hydrates the returned entities.
   */
  @Query(
      value =
          """
          SELECT * FROM user_roles FORCE INDEX (fk_user_roles_role)
          WHERE user_id = :userId AND role_id = :roleId
            AND tenant_id = :tenantId AND revoked_at IS NULL
          FOR SHARE
          """,
      nativeQuery = true)
  List<UserRole> lockActiveAdminAssignment(
      @Param("userId") byte[] userId,
      @Param("roleId") byte[] roleId,
      @Param("tenantId") byte[] tenantId);

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
   * FR-2 (a) (US-017 D10, D11, D12; re-scoped by 06-code-review.md H-1, 2026-09-24) —
   * health-check support only, {@link ZeroAdminTenantReader}'s driving set: tenants with AT LEAST
   * ONE <b>caller-qualifying</b> role (literal {@code adminRoleName}, or a role carrying ALL of
   * {@code dangerousNames} — {@code dangerousNamesCount} is {@code dangerousNames.size()}, passed
   * explicitly since JPQL's {@code SIZE()} only applies to a persistent collection association,
   * not a bind parameter). {@code COUNT(DISTINCT p.name)} mirrors {@code
   * RbacDangerousPermissions#carriesAll}'s per-name, duplicate-safe semantics — never a raw row
   * count, which could over-count a role holding the same permission via more than one row. A
   * tenant with no caller-qualifying role at all is deliberately invisible here — this is the
   * DRIVING SET (D11). Names are supplied by the caller from {@code rbac.domain} (D12) — never
   * hardcoded here.
   *
   * <p>Carries the {@code ur.tenantId = r.tenantId}/{@code rp.id.roleId = r.id} cross-check
   * discipline this repository's other queries carry (T-S1). Read-only, no locking — this runs on
   * a health-check cadence, not a hot path, and must never contend with the M11/M5b locking reads
   * above. JPQL, not native SQL, for the same {@code UuidV7Converter} reason as every other query
   * here.
   */
  @Override
  @Query(
      """
      SELECT DISTINCT r.tenantId FROM Role r
      WHERE r.name = :adminRoleName
         OR (SELECT COUNT(DISTINCT p.name) FROM RolePermission rp, Permission p
             WHERE rp.id.roleId = r.id AND rp.id.permissionId = p.id
               AND p.name IN :dangerousNames) = :dangerousNamesCount
      """)
  List<UUID> findTenantsWithAFullyAdminEquivalentRole(
      @Param("adminRoleName") String adminRoleName,
      @Param("dangerousNames") Collection<String> dangerousNames,
      @Param("dangerousNamesCount") long dangerousNamesCount);

  /**
   * FR-2 (b) (US-017 D10, D11, D12; re-scoped by 06-code-review.md H-1, 2026-09-24) — tenants with
   * AT LEAST ONE active holder of some caller-qualifying role. Differenced against {@link
   * #findTenantsWithAFullyAdminEquivalentRole} in Java, not one correlated {@code
   * HAVING}/{@code GROUP BY} statement: the tenant-level question ("does *some* caller-qualifying
   * role have holders") is not equivalent to a role-level {@code NOT EXISTS} once a tenant can
   * have more than one caller-qualifying role, and two flat queries are directly unit-testable
   * with mocks.
   */
  @Override
  @Query(
      """
      SELECT DISTINCT r.tenantId FROM Role r, UserRole ur
      WHERE ur.roleId = r.id AND ur.tenantId = r.tenantId AND ur.revokedAt IS NULL
        AND (r.name = :adminRoleName
             OR (SELECT COUNT(DISTINCT p.name) FROM RolePermission rp, Permission p
                 WHERE rp.id.roleId = r.id AND rp.id.permissionId = p.id
                   AND p.name IN :dangerousNames) = :dangerousNamesCount)
      """)
  List<UUID> findTenantsWithActiveFullyAdminEquivalentHolders(
      @Param("adminRoleName") String adminRoleName,
      @Param("dangerousNames") Collection<String> dangerousNames,
      @Param("dangerousNamesCount") long dangerousNamesCount);
}
