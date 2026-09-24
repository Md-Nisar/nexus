package com.example.nexus.rbac.application.port.out;

import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.ActiveAssignmentRef;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RolePermissionName;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Write-capable port over role assignment/revocation persistence (03-design.md §4.3, D3).
 *
 * <p>Deliberately a separate port from {@link UserRoleQueryPort}, not a widening of it —
 * {@code UserRoleQueryPort} is documented read-only and consumed by {@code
 * RoleResolutionService}/{@code RoleResolutionServiceTest}; widening it would leak a write
 * capability to a read-only collaborator. Implementations live in {@code
 * rbac.infrastructure.persistence} — the domain and application layers depend only on this
 * interface (hexagonal architecture, ADR-0002).
 */
public interface UserRoleAssignmentPort {

  /** Role by id, for existence + tenant + name checks. Empty when unknown. */
  Optional<Role> findRole(UUID roleId);

  /**
   * M2 — does this user currently hold an ACTIVE assignment of this role? Deliberately NOT
   * tenant-scoped: it must mirror {@code uq_user_role_active (user_id, role_id)} exactly, or a row
   * with a drifted {@code user_roles.tenant_id} could slip past this pre-check and surface as an
   * untranslated {@code DataIntegrityViolationException} (500) instead of a clean 409 ({@code
   * RBAC_004}).
   */
  boolean hasActiveAssignment(UUID userId, UUID roleId);

  /**
   * M5 — same question, tenant-scoped, used for the AC8 live-admin check on the caller. MUST be
   * implemented as a fresh, locking ({@code PESSIMISTIC_READ}) DB read in the adapter — never
   * derived from a JWT claim (a JWT's {@code roles[]} can be up to ~15 min stale), and never a
   * plain non-locking read, because a non-locking read is a REPEATABLE-READ snapshot that can miss
   * a concurrent revocation. Returns {@code true} iff the query returns at least one row.
   */
  boolean hasActiveAdminAssignment(UUID userId, UUID roleId, UUID tenantId);

  /**
   * M10 (US-017 D3) — every (roleId, permissionName) pair for the roles of ONE tenant. Bounded at
   * nexus.rbac.max-roles-per-tenant (default 500) x |permissions| = 7.
   *
   * <p>Deliberately returns NAMES paired with role ids, not a verdict and not a filtered set: the
   * ANY/ALL policy lives in rbac.domain.RbacAdminEquivalence and MUST NOT cross this port in either
   * direction — not hardcoded in the adapter and NOT passed in as a Set<String> parameter either
   * (ADR-0017 D2, upheld by ADR-0018 D3). A future "pushForFilter(Set<String> dangerousNames)"
   * variant would violate that rule and requires an ADR that argues against it explicitly.
   *
   * <p>MUST be a plain, NON-LOCKING read and MUST NEVER be annotated @Lock: it touches
   * `permissions`, on which nexus_app holds SELECT only (MC-A).
   */
  List<RolePermissionName> findPermissionNamesForTenantRoles(UUID tenantId);

  /**
   * M11 (US-017 D6) — locks (PESSIMISTIC_WRITE) and returns the (assignmentId, userId) pair for
   * every ACTIVE assignment of ANY role in {@code roleIds} within {@code tenantId}. Supersedes and
   * REPLACES M1 lockActiveAssignmentIds.
   *
   * <p>{@code roleIds} MUST be sorted ASCENDING by the caller — this is the deterministic
   * acquisition order D6's deadlock-freedom argument rests on, and it is a contract of this method,
   * not an implementation detail of one caller.
   *
   * <p>"ASCENDING" means <b>unsigned byte-wise order of the 16-byte representation</b>, matching
   * MySQL's BINARY(16) comparison — NOT {@link java.util.UUID#compareTo}, which compares
   * mostSigBits as a SIGNED long. The two coincide for every id in the system today (seeded ids
   * have a clear high bit; UUIDv7 keeps it clear until ~year 6429), so a divergence would be
   * latent, not live — which is exactly when it must be pinned. MC-E asserts THIS comparator; an
   * MC-E that merely asserted "sorted" would pass under an ordering that does not match the
   * database's and give false assurance about the one property D6 rests on.
   *
   * <p>The Java sort is belt-and-braces: the real guarantee is the PLAN. An ascending range scan on
   * fk_user_roles_role acquires in index order regardless of IN-list order, so <b>plan stability
   * across IN-list cardinalities is part of the claim</b>, not a fixture detail — MC-C asserts
   * key = fk_user_roles_role for IN-lists of size 1, 2 and >= 20. A full-scan fallback would
   * acquire in primary-key order and break the argument.
   *
   * <p>The adapter MUST drive off {@code role_id} (fk_user_roles_role) as an IN-list range, never
   * {@code tenant_id}, and MUST NOT join {@code Role} — joining would widen the lock beyond
   * user_roles. Tenant containment is therefore carried by two things together: the role-id set is
   * tenant-derived by the caller, and {@code tenant_id} remains a residual predicate (T-S1).
   *
   * <p>Returns ids only, never entities — the caller must not be able to load-mutate-save a UserRole.
   * Must be called inside an active transaction.
   */
  List<ActiveAssignmentHolder> lockActiveAssignmentHolders(UUID tenantId, List<UUID> roleIds);

  /**
   * M5b (US-017 D8) — generalises M5 from one roleId to a set. Same non-negotiable contract: a
   * FRESH, LOCKING (PESSIMISTIC_READ / FOR SHARE) read, never a JWT claim (T-E7), never a plain
   * non-locking read. MUST keep FORCE INDEX (fk_user_roles_role) so that every index record it
   * requests is inside M11's X region (ADR-0018 D4's containment proof; MC-C).
   *
   * <p>An EMPTY {@code roleIds} means the caller has no way to qualify: the caller MUST fail closed
   * and MUST NOT call this method at all (R-10 / T-E18 precedent).
   *
   * <p>Carried verbatim from M5 (US-017 editorial correction): the adapter MUST inspect only
   * {@code .isEmpty()} / {@code .size()} on the returned rows and MUST NEVER mutate them. Returning
   * managed entities from a locking read is a load-mutate-save hazard; the boolean is the contract,
   * the entities are an implementation artefact.
   */
  boolean hasActiveAssignmentOfAnyRole(UUID userId, List<UUID> roleIds, UUID tenantId);

  /**
   * M12 (US-017 D24) — every (roleId, permissionName) pair for the roles of the CALLER'S OWN active
   * assignments in one tenant. Sibling of M7, keyed by USER rather than by role.
   *
   * <p>Exists solely to give the bypass canary (D14/§9.3) a derivation that shares NO INPUT with the
   * gate. It MUST be driven off fk_user_roles_user — a different index, a different statement and a
   * different scoping from M10, which is tenant-scoped and driven off r.tenantId. An over-broad M10
   * therefore cannot silence the canary that exists to notice it (threat model T-E29).
   *
   * <p>MUST be a plain, NON-LOCKING read, and MUST NEVER be used for an authorization decision — the
   * gate's only determination is M5b, a fresh locking read (T-E7). MC-G asserts this negative on both
   * verbs.
   *
   * <p>Like M10, returns NAMES paired with role ids: the ANY/ALL policy lives in
   * rbac.domain.RbacAdminEquivalence and MUST NOT cross this port in either direction (ADR-0017 D2 /
   * ADR-0018 D3, upheld — this method is the reason D3 did not have to be reopened to satisfy RC-17).
   */
  List<RolePermissionName> findPermissionNamesForActiveAssignmentsOfUser(UUID userId, UUID tenantId);

  /**
   * M3 — the active assignment to revoke; empty covers both "never assigned" and "already revoked"
   * (never a silent 204 — always a 404).
   *
   * <p>Returns a projection, deliberately not a managed {@link
   * com.example.nexus.rbac.domain.UserRole} entity, for the same "must not be mutable-and-saveable"
   * reason as {@link #lockActiveAssignmentHolders}: a managed entity on this path could be mutated and
   * re-saved in a way the least-privilege {@code nexus_app} DB grant then rejects.
   */
  Optional<ActiveAssignmentRef> findActiveAssignmentRef(UUID userId, UUID roleId, UUID tenantId);

  /**
   * M4a — projection of one active assignment, joined to {@code roles.name}. Used for the 201
   * body: a projection reads DB values directly, whereas an entity re-read would return the
   * just-persisted session instance with a null {@code assignedAt}.
   */
  Optional<ActiveRoleAssignment> findActiveAssignmentView(UUID userId, UUID roleId, UUID tenantId);

  /** M4 — all active assignments for a user in a tenant, single projection join (no N+1). */
  List<ActiveRoleAssignment> findActiveAssignmentViews(UUID userId, UUID tenantId);

  /**
   * Inserts a new active assignment and returns its id. Implementations translate the {@code
   * uq_user_role_active} violation into {@code DuplicateRoleAssignmentException} ({@code
   * RBAC_004}) so a concurrent duplicate request yields 409, not 500.
   */
  UUID assign(UUID userId, UUID roleId, UUID tenantId, UUID assignedBy);

  /**
   * M7 — the names of every permission attached to {@code roleId}. Bounded at
   * |permissions| = 7 by the fixed catalogue (V5__rbac_schema.sql:107-114).
   *
   * <p><b>PRECONDITION (T-I13 / RC-12.4): {@code roleId} MUST already have been tenant-verified
   * by the caller. This method performs NO tenant check</b> — unlike most methods on this port it
   * takes a bare role id. {@code RoleAssignmentService} satisfies this by calling
   * {@code resolveRoleInTenant} two statements earlier; any new caller must do the same.
   *
   * <p>Deliberately returns NAMES, not a boolean and not a PermissionView projection: the
   * "which permissions are dangerous" policy lives in rbac.domain.RbacDangerousPermissions and
   * MUST NOT cross this port in either direction — not hardcoded in the adapter (R-9 discipline)
   * and not passed in as a parameter either.
   *
   * <p>MUST be a plain, NON-LOCKING read and MUST NEVER be annotated {@code @Lock}: it touches
   * {@code permissions}, on which {@code nexus_app} holds {@code SELECT} only, so a locking read
   * would be rejected in production and would pass every Testcontainers IT (03-design.md D5).
   */
  List<String> findPermissionNamesForRole(UUID roleId);

  /**
   * M8 — resolves this tenant's role id by {@code (tenantId, name)}. Same contract as
   * {@code RoleManagementPort#findRoleIdByName} and backed by the SAME repository method, so there
   * is exactly one query and one index-discipline site: a plain {@code r.name = :name} predicate
   * relying on {@code utf8mb4_0900_ai_ci}, never {@code UPPER()}, so {@code uq_roles_tenant_name}
   * is used as an index. Empty ⇒ the caller MUST fail closed (R-10 / T-E18).
   */
  Optional<UUID> findRoleIdByName(UUID tenantId, String name);

  /**
   * RC-6 — reverse lookup: the ids of every user holding an ACTIVE (non-revoked) assignment of
   * {@code roleId}. Deliberately NOT tenant-scoped: the role id alone already pins the tenant
   * ({@code roles.tenant_id}), so an additional parameter would be redundant plumbing for this
   * lookup's one caller.
   *
   * <p>Needed for the D16 remediation runbook path (03b-threat-model.md RC-6); as of US-016
   * (D13), also called at runtime by {@code RoleManagementService.attachPermission} on the
   * dangerous-permission-grant path. Read-only, no locking: not a hot path contended with the
   * M1/M5 locking reads above.
   */
  List<UUID> findActiveUserIdsForRole(UUID roleId);

  /**
   * M6 — targeted single-column soft delete. {@code revokedAt} must be the caller's app-side
   * clamped instant (never earlier than the assignment's {@code assignedAt} — see {@link
   * ActiveAssignmentRef}), since this codebase's pinned Hibernate version rejects a DB-side {@code
   * FUNCTION('now', 6)} at HQL-parse time. Returns affected-row count: {@code 1} = revoked, {@code
   * 0} = already revoked or vanished (maps to 404). There is no {@code @Version} on {@code
   * UserRole}, so this int count IS the concurrency guard.
   */
  int revoke(UUID userRoleId, Instant revokedAt);
}
