package com.example.nexus.rbac.application.port.out;

import com.example.nexus.rbac.domain.ActiveAssignmentHolder;
import com.example.nexus.rbac.domain.ActiveAssignmentRef;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.HolderProvenance;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.PermissionHolder;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleHolder;
import com.example.nexus.rbac.domain.RolePermissionRef;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
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
   * Locks the live role row (X-lock) in roles. Follows universal locking order
   * (roles -> user_roles -> role_permissions) to eliminate gap-lock next-key deadlocks on
   * first admin assignment.
   */
  boolean lockRoleRow(UUID roleId, UUID tenantId);

  /**
   * M2 — does this user currently hold an ACTIVE assignment of this role? Deliberately NOT
   * tenant-scoped: it must mirror {@code uq_user_role_active (user_id, role_id)} exactly, or a row
   * with a drifted {@code user_roles.tenant_id} could slip past this pre-check and surface as an
   * untranslated {@code DataIntegrityViolationException} (500) instead of a clean 409 ({@code
   * RBAC_004}).
   */
  boolean hasActiveAssignment(UUID userId, UUID roleId);

  /**
   * M10' (US-018 T-016, replaces M10) — every {@code (roleId, permissionId)} pair for the roles of
   * ONE tenant. Bounded at nexus.rbac.max-roles-per-tenant (default 500) x |permissions|.
   *
   * <p>Ids only, never names and never a verdict: "which roles are admin-defining" is decided in
   * {@code rbac.domain.RbacAdministrators} over this result and {@link #findCatalogueIds()}, and no
   * policy list crosses this port in either direction (ADR-0017 D2, ADR-0018 D3).
   *
   * <p>MUST be a plain, NON-LOCKING read and MUST NEVER be annotated @Lock (MC-A). The tenant's
   * set lock ({@link #lockActiveAssignmentHolders}) is built from it.
   */
  List<RolePermissionRef> findRolePermissionIdsForTenantRoles(UUID tenantId);

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
   * fk_user_roles_role_tenant (role_id, tenant_id) acquires in index order regardless of IN-list order, so <b>plan stability
   * across IN-list cardinalities is part of the claim</b>, not a fixture detail — MC-C asserts
   * key = fk_user_roles_role_tenant for IN-lists of size 1, 2 and >= 20. A full-scan fallback would
   * acquire in primary-key order and break the argument.
   *
   * <p>The adapter MUST drive off {@code role_id} (fk_user_roles_role_tenant) as an IN-list range, never
   * {@code tenant_id}, and MUST NOT join {@code Role} — joining would widen the lock beyond
   * user_roles. Tenant containment is therefore carried by two things together: the role-id set is
   * tenant-derived by the caller, and {@code tenant_id} remains a residual predicate (T-S1).
   *
   * <p>Returns ids only, never entities — the caller must not be able to load-mutate-save a UserRole.
   * Must be called inside an active transaction.
   *
   * <p>US-018 (ADR-0021 D2): on a request that takes this lock, the caller's administrator status
   * is computed from THESE rows (current and X-locked: the caller is an active holder of an
   * admin-defining role in the result), never from the snapshot read {@link
   * #findHeldRolePermissionIdsForAuthorization}.
   */
  List<ActiveAssignmentHolder> lockActiveAssignmentHolders(UUID tenantId, List<UUID> roleIds);

  /**
   * US-019 RC-57.1 (design §10.3 step 10, §10.4) — the CURRENT {@code (roleId, permissionId)}
   * pairs of {@code roleIds}, a locking {@code FOR SHARE} read on {@code pk_role_permissions}, so
   * a set-lock verb classifies which locked roles are admin-defining <b>now</b>, never from the
   * pre-lock M10' snapshot. An uncommitted detach on one of them is waited for, then seen.
   *
   * <p>Called while holding the set lock ({@link #lockActiveAssignmentHolders}) and, on a replace,
   * the role row: B8 never requests a {@code user_roles} or {@code roles} lock after this one
   * (RC-46). {@code roleIds} are the lock set's role ids, tenant-derived by the caller. Also called
   * by assign on its non-admin-defining path (US-019 RC-56.2) with the target role alone, after the
   * conditional insert has taken that role's row S lock and its {@code user_roles} row, and as the
   * last lock that assign takes. An empty collection returns an empty list without a read. Ids
   * only. MC-A is untouched: this is a new, explicitly locking method; M10', M13, M14 and M15 stay
   * non-locking.
   */
  List<RolePermissionRef> lockRolePermissionsForRoles(UUID tenantId, Collection<UUID> roleIds);

  /**
   * M13 (US-018, 03-design.md §4.3) — every {@code (roleId, permissionId)} pair the user holds
   * through an ACTIVE assignment in {@code tenantId}. This is <b>the</b> read for grant-subset
   * authorization decisions (ADR-0021 D2): the caller derives the union of held permission ids
   * from it. Never substitute a JWT claim or any other read for it.
   *
   * <p>Joins {@code roles} with {@code r.tenantId = ur.tenantId} (T-S1), so a {@code user_roles}
   * row that points at another tenant's role never widens the result. Driven off {@code
   * fk_user_roles_user}. Ids only; it does not join {@code permissions}.
   *
   * <p>MUST be a plain, NON-LOCKING snapshot read and MUST NEVER be annotated {@code @Lock}: a
   * locking read here would be a new acquisition outside the set-lock region (ADR-0018 D6), and
   * {@code nexus_app} holds {@code SELECT} only on {@code permissions} (MC-A). A read failure
   * propagates; the caller must never treat it as "allow".
   */
  List<RolePermissionRef> findHeldRolePermissionIdsForAuthorization(UUID userId, UUID tenantId);

  /**
   * M14 (US-018, 03-design.md §4.3) — the ids of every permission attached to {@code roleId},
   * provided the role belongs to {@code tenantId}.
   *
   * <p>Fails closed (07-security-review.md L-2): {@link Optional#empty()} means the role is NOT in
   * {@code tenantId} (or does not exist), and a caller MUST deny on it, never read it as "grants
   * nothing". A present, empty set means the role is in the tenant and has no permissions. The two
   * cases are distinguished by one statement, so no caller depends on having run {@code
   * resolveRoleInTenant} first for safety (it still does, for the 404/403 contract).
   *
   * <p>MUST be a plain, NON-LOCKING read and MUST NEVER be annotated {@code @Lock} (MC-A).
   */
  Optional<Set<UUID>> findPermissionIdsForRole(UUID roleId, UUID tenantId);

  /**
   * M15 (US-018, 03-design.md §2.1, §4.3) — the ids of the whole, global permission catalogue,
   * against which a role is admin-defining. Read only when needed: on {@code assign()}, only for a
   * self-target (A4). Backed by a read-only repository that cannot write {@code permissions} (L-5).
   *
   * <p>MUST be a plain, NON-LOCKING read and MUST NEVER be annotated {@code @Lock} (MC-A). A read
   * failure propagates; the caller must never treat it as "allow".
   */
  Set<UUID> findCatalogueIds();

  /**
   * M16 (US-018 T-018, RC-28.1, RC-50(b)) — the ids of the roles, among the user's ACTIVE
   * assignments in {@code tenantId}, that carry every permission of the catalogue.
   *
   * <p>The independent runtime check behind {@code RBAC_SELF_ASSIGN_ADMIN_DISAGREEMENT}: one
   * statement, per role ({@code GROUP BY role HAVING COUNT(DISTINCT permission) = catalogue
   * count}, never a union count), with its own tenant and active-assignment predicates and the
   * catalogue count computed in the database. It shares no input with {@link
   * #findHeldRolePermissionIdsForAuthorization} (M13).
   *
   * <p>MUST be a plain, NON-LOCKING read, MUST NEVER be annotated @Lock (MC-A), and MUST NEVER be
   * used for an authorization decision: it is read before the INSERT of a successful self-target
   * assignment, only to be compared with A4's verdict.
   */
  List<UUID> findHeldAdminDefiningRoleIds(UUID userId, UUID tenantId);

  /**
   * US-018 T-017 (rows 13 and 14) — every ACTIVE holder of {@code roleId} in {@code tenantId}
   * together with the user who assigned them. Plain, NON-LOCKING.
   */
  List<HolderProvenance> findActiveHoldersForRole(UUID roleId, UUID tenantId);

  /**
   * US-018 T-017 (rows 13 and 14) — the distinct users holding an ACTIVE assignment of any role in
   * {@code roleIds} within {@code tenantId}; with the admin-defining role ids, the tenant's
   * administrator user set. An empty {@code roleIds} returns an empty set without a read. Plain,
   * NON-LOCKING.
   */
  Set<UUID> findActiveHolderUserIdsForRoles(UUID tenantId, Collection<UUID> roleIds);

  /**
   * C3 (US-018 T-029) — one page of the ACTIVE holders of {@code roleId} in {@code tenantId}, {@code
   * ORDER BY assignedAt, id}: a tenant-scoped, paged variant of {@link #findActiveUserIdsForRole}
   * that also carries the assignment id, timestamp and assigner. The role must already have been
   * resolved in the tenant by the caller. Excludes revoked rows and deleted roles. Plain,
   * NON-LOCKING; ids only.
   */
  PageResult<RoleHolder> findActiveRoleHolders(UUID roleId, UUID tenantId, int page, int size);

  /**
   * C3 (US-018 T-029) — one page, ordered by user id, of the DISTINCT users of {@code tenantId} who
   * hold {@code permissionId} through an active assignment of a live role, each with the roles that
   * grant it. A user holding it through several roles appears once. Plain, NON-LOCKING; ids only.
   */
  PageResult<PermissionHolder> findPermissionHolders(
      UUID permissionId, UUID tenantId, int page, int size);

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

  /**
   * M4 — one page of the active assignments for a user in a tenant, single projection join (no N+1),
   * {@code ORDER BY assignedAt, id} (a total order; US-018 C2). Excludes assignments of deleted
   * roles. Non-locking.
   */
  PageResult<ActiveRoleAssignment> findActiveAssignmentViews(
      UUID userId, UUID tenantId, int page, int size);

  /**
   * Inserts a new active assignment and returns its id. The insert is conditional on the role being
   * live and in {@code tenantId} (US-018 C1, RC-36.1): when it inserts nothing, implementations
   * throw a {@code ResourceNotFoundException} with code {@code ROLE_NOT_FOUND}, so an assign that
   * races a delete of the role can never attach a holder to a deleted role. Implementations also
   * translate the {@code uq_user_role_active} violation into {@code DuplicateRoleAssignmentException}
   * ({@code RBAC_004}) so a concurrent duplicate request yields 409, not 500.
   */
  UUID assign(UUID userId, UUID roleId, UUID tenantId, UUID assignedBy);

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
   * <p>Needed for the D16 remediation runbook path (03b-threat-model.md RC-6), and called after
   * commit by {@code RoleManagementService.detachPermission} and the role-level replay of a failed
   * detach holder read. Read-only, no locking: not a hot path contended with the M11 locking
   * read above.
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
