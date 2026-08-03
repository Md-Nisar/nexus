package com.example.nexus.rbac.application.port.out;

import com.example.nexus.rbac.domain.ActiveAssignmentRef;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.Role;
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
   * M1 — locks ({@code PESSIMISTIC_WRITE}) and returns the ids of every active assignment of
   * {@code roleId} within {@code tenantId}. Returns ids only, never entities — the caller must not
   * be able to load-mutate-save a {@link com.example.nexus.rbac.domain.UserRole}. Must be called
   * inside an active transaction. The adapter must scope the lock by {@code role_id} as the driving
   * predicate, never by {@code tenant_id} — driving on {@code tenant_id} would scan/lock the whole
   * table instead of just this tenant's rows for this role.
   */
  List<UUID> lockActiveAssignmentIds(UUID tenantId, UUID roleId);

  /**
   * M3 — the active assignment to revoke; empty covers both "never assigned" and "already revoked"
   * (never a silent 204 — always a 404).
   *
   * <p>Returns a projection, deliberately not a managed {@link
   * com.example.nexus.rbac.domain.UserRole} entity, for the same "must not be mutable-and-saveable"
   * reason as {@link #lockActiveAssignmentIds}: a managed entity on this path could be mutated and
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
   * M6 — targeted single-column soft delete. {@code revokedAt} must be the caller's app-side
   * clamped instant (never earlier than the assignment's {@code assignedAt} — see {@link
   * ActiveAssignmentRef}), since this codebase's pinned Hibernate version rejects a DB-side {@code
   * FUNCTION('now', 6)} at HQL-parse time. Returns affected-row count: {@code 1} = revoked, {@code
   * 0} = already revoked or vanished (maps to 404). There is no {@code @Version} on {@code
   * UserRole}, so this int count IS the concurrency guard.
   */
  int revoke(UUID userRoleId, Instant revokedAt);
}
