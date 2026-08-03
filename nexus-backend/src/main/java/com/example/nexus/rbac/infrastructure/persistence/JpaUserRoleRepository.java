package com.example.nexus.rbac.infrastructure.persistence;

import com.example.nexus.rbac.domain.UserRole;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
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

  /**
   * M1 — locks (PESSIMISTIC_WRITE) the tenant's active assignments of a given role (AC5 lockout
   * guard). Single-table, driven by {@code roleId} (the FK-indexed column) — NEVER driven by
   * {@code tenantId} as the primary predicate, which is unindexed and would scan/lock the whole
   * table. {@code tenantId} stays as a residual defense-in-depth filter only. No join with {@code
   * Role} — this is what keeps the lock scope confined to one tenant's rows and avoids locking a
   * {@code Role} row at all.
   */
  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query(
      """
      SELECT ur FROM UserRole ur
      WHERE ur.roleId = :roleId
        AND ur.tenantId = :tenantId
        AND ur.revokedAt IS NULL
      """)
  List<UserRole> lockActiveAssignmentsByRole(
      @Param("tenantId") UUID tenantId, @Param("roleId") UUID roleId);

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
   * M5 — AC8's live-admin check on the CALLER. MUST be a LOCKING read (PESSIMISTIC_READ, renders
   * {@code FOR SHARE}), never a plain COUNT: a non-locking read is a REPEATABLE-READ snapshot that
   * can miss a concurrent revocation of the caller's own admin assignment (a real, if narrow,
   * race). Returns entities (not a scalar) because {@code @Lock} on a COUNT projection is
   * implementation-defined under JPA — the adapter should only ever inspect {@code .size()} /
   * {@code .isEmpty()}, never mutate these.
   */
  @Lock(LockModeType.PESSIMISTIC_READ)
  @Query(
      """
      SELECT ur FROM UserRole ur
      WHERE ur.userId = :userId AND ur.roleId = :roleId
        AND ur.tenantId = :tenantId AND ur.revokedAt IS NULL
      """)
  List<UserRole> lockActiveAdminAssignment(
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
   * Health-check support only (T-015 / {@code 03b-threat-model.md} T-D4) — the zero-active-admins
   * detection control. Returns the tenantId of every tenant that has a seeded role named {@code
   * roleName} (matched case-insensitively — {@code roles.name}'s collation makes {@code
   * uq_roles_tenant_name} case-insensitive, see {@link com.example.nexus.rbac.domain.RbacRoleNames})
   * but currently has zero active (non-revoked) assignments of it.
   *
   * <p>A non-empty result is the AC5-bypass signal this control exists to surface: unlike the
   * service-layer lockout guard (M1/{@code RoleAssignmentService}), which only prevents the
   * <em>next</em> revocation from zeroing a tenant out, this catches an already-zeroed tenant from
   * <b>any</b> cause — a bug, a future grant change, a role-name casing mismatch, or a raw-SQL
   * path that bypassed the application entirely.
   *
   * <p>Read-only, no locking — this runs on a health-check cadence, not a hot path, and must never
   * contend with the M1/M5 locking reads above. JPQL, not native SQL, for the same {@code
   * UuidV7Converter} ({@code UUID}<->{@code BINARY(16)}) reason as every other query here.
   */
  @Query(
      """
      SELECT r.tenantId FROM Role r
      WHERE UPPER(r.name) = UPPER(:roleName)
        AND NOT EXISTS (
          SELECT 1 FROM UserRole ur
          WHERE ur.roleId = r.id AND ur.tenantId = r.tenantId AND ur.revokedAt IS NULL
        )
      """)
  List<UUID> findTenantsWithZeroActiveAssignmentsForRole(@Param("roleName") String roleName);
}
