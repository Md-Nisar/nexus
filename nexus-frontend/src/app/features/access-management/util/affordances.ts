import type { RoleResponse } from '../../../shared/types/api/rbac';
import { isAdminDefiningHint } from './admin-defining-hint';

/**
 * Why a permission row of the editor is disabled (US-020 design §8.3). Each has visible copy.
 */
export type AffordanceReason =
  'profile-unavailable' | 'not-held' | 'admin-only-directory' | 'role-exceeds-caller';

/** A row that stays enabled but carries a hint for the Review (Q17: never a block). */
export type AffordanceHint = 'hint-admin-demotion';

/**
 * What the editor may offer for one permission:
 * - `enabled`, possibly with a hint;
 * - `disabled` with the reason shown beside it;
 * - `not-editable`: a system role, which renders no edit control at all (FR-B7).
 */
export type Affordance =
  | { readonly kind: 'enabled'; readonly hint?: AffordanceHint }
  | { readonly kind: 'disabled'; readonly reason: AffordanceReason }
  | { readonly kind: 'not-editable' };

/** Everything the rules read. Ids only; the profile's names are mapped through the catalogue. */
export interface AffordanceContext {
  /** Ids of the permissions the caller holds, from the live profile. */
  readonly held: ReadonlySet<string>;
  readonly isAdministrator: boolean;
  /** Ids of the role's current (base) set. */
  readonly roleSet: ReadonlySet<string>;
  readonly isSystemRole: boolean;
  /** The live profile is ready (Q8); every row is disabled otherwise. */
  readonly mutationsEnabled: boolean;
  /** Id of `user:directory:read` in the catalogue, or `null` when the catalogue lacks it. */
  readonly directoryReadId: string | null;
  /** The role looks administrator-defining (`isAdminDefiningHint`). */
  readonly adminDefiningHint: boolean;
}

const ENABLED: Affordance = { kind: 'enabled' };
const DEMOTION_HINT: Affordance = { kind: 'enabled', hint: 'hint-admin-demotion' };
const NOT_EDITABLE: Affordance = { kind: 'not-editable' };

function disabled(reason: AffordanceReason): Affordance {
  return { kind: 'disabled', reason };
}

/**
 * The affordance of one permission row (design §8.3, Q18). It mirrors, in order, the server's
 * `RoleManagementService.authorizeReplace`:
 *
 * 1. A system role is immutable (`requireMutableRole`): no control at all.
 * 2. The live profile is unavailable: every row disabled (Q8, fail closed).
 * 3. **Add** (the id is not in the role):
 *    - grant-subset: the caller must hold it (`not-held`);
 *    - then the PII rule: only an administrator may add `user:directory:read`
 *      (`admin-only-directory`). Evaluated after grant-subset, as on the server, so a caller who
 *      does not hold it is told `not-held`.
 * 4. **Remove** (the id is in the role):
 *    - role-subset: the caller must hold every permission of the role, otherwise every removal is
 *      disabled (`role-exceeds-caller`);
 *    - a role that looks administrator-defining needs the caller to be an administrator through
 *      **another** role. The client cannot know that, so it is a hint only (Q17), never a block.
 *      A non-administrator can hold every permission through several roles; the server decides.
 *
 * Over-blocking is the safe direction; the server is final for every request.
 */
export function permissionAffordance(id: string, ctx: AffordanceContext): Affordance {
  if (ctx.isSystemRole) return NOT_EDITABLE;
  if (!ctx.mutationsEnabled) return disabled('profile-unavailable');

  if (!ctx.roleSet.has(id)) {
    if (!ctx.held.has(id)) return disabled('not-held');
    if (id === ctx.directoryReadId && !ctx.isAdministrator) {
      return disabled('admin-only-directory');
    }
    return ENABLED;
  }

  for (const member of ctx.roleSet) {
    if (!ctx.held.has(member)) return disabled('role-exceeds-caller');
  }
  return ctx.adminDefiningHint ? DEMOTION_HINT : ENABLED;
}

/**
 * The H-2 block (design §8.3, §23; threat model §12.2, D-4): a role that looks
 * administrator-defining is not offered to a PENDING target until F-4 lands. A **code constant**:
 * nothing at run time (configuration, environment, URL, storage) can turn it off. Its only other
 * value is the `blockAdminRolesForPending` parameter of {@link roleAssignAffordance}, which specs
 * set to pin the post-F-4 typed confirm. When F-4 lands, this constant and the one rule it guards
 * are removed.
 */
export const PENDING_ADMIN_ROLE_BLOCK = true;

/** The permission only an administrator may grant (`PiiPermissionGrantRule`). */
const DIRECTORY_READ = 'user:directory:read';

/** Why a candidate role cannot be assigned (design §8.3 assign table, §14.2). */
export type AssignReason =
  'already-assigned' | 'role-needs-more-access' | 'admin-only-directory' | 'pending-admin-role';

/** Everything the assign rules read. Codes and ids only, never an address. */
export interface AssignContext {
  /** Codes the caller holds, from the live profile. */
  readonly held: ReadonlySet<string>;
  readonly isAdministrator: boolean;
  /** Ids of the roles the target already holds (the loaded assignments). */
  readonly assignedRoleIds: ReadonlySet<string>;
  /** The catalogue's size, or `null` while it is not known. */
  readonly catalogueTotal: number | null;
  /** The target has not verified their address (RC-69). */
  readonly targetIsPending: boolean;
}

/**
 * What the Assign dialog may offer for one candidate role:
 * - `enabled`: `adminHint` shows the "looks like an administrator role" hint (never a block);
 *   `checked` is true once the role's permissions are loaded and passed the rules, so the
 *   confirm may be used;
 * - `disabled`, with the reason shown beside it and, for a role that needs more access than the
 *   caller holds, the codes that are missing (empty when known only from the count).
 */
export type AssignAffordance =
  | { readonly kind: 'enabled'; readonly adminHint: boolean; readonly checked: boolean }
  | {
      readonly kind: 'disabled';
      readonly reason: AssignReason;
      readonly missing: readonly string[];
    };

/** How the Assign dialog confirms (design §12.9, RC-69). */
export type AssignConfirmKind = 'assign' | 'assign-unverified' | 'typed-unverified';

function knownTotal(total: number | null): number | null {
  return total !== null && total > 0 ? total : null;
}

/** The role looks administrator-defining against a known catalogue total (Q17: a hint). */
function hinted(role: RoleResponse, total: number | null): boolean {
  const known = knownTotal(total);
  return known !== null && isAdminDefiningHint(role, known);
}

/**
 * Whether a role counts as administrator-defining for a PENDING target (H-2): the hint, or
 * **any** role while the catalogue total is unknown (D-4: fail closed).
 */
function treatedAsAdminForPending(role: RoleResponse, ctx: AssignContext): boolean {
  return (
    ctx.targetIsPending &&
    (knownTotal(ctx.catalogueTotal) === null || hinted(role, ctx.catalogueTotal))
  );
}

function blocked(reason: AssignReason, missing: readonly string[] = []): AssignAffordance {
  return { kind: 'disabled', reason, missing };
}

/**
 * The affordance of one candidate role in the Assign dialog (US-020 design §8.3 assign table, Q18;
 * RC-69, H-2, D-4). In order:
 *
 * 1. **(a)** the target already holds it: `already-assigned` (a racing `RBAC_004` still converges);
 * 2. **(b) pigeonhole:** the role carries more permissions than the caller holds, so it must carry
 *    one the caller lacks: `role-needs-more-access`, decided **without a request**;
 * 3. **H-2:** a PENDING target and a role treated as administrator-defining (the hint, or every
 *    role while the catalogue total is unknown, D-4): `pending-admin-role`, unless
 *    `blockAdminRolesForPending` is off (specs only; after F-4);
 * 4. once `permissions` (the role's codes) are loaded: **(b)** any code the caller does not hold
 *    (`role-needs-more-access` with the codes), then the **PII rule**: `user:directory:read` for a
 *    non-administrator (`admin-only-directory`), in the server's order;
 * 5. otherwise enabled. **(c)** a hinted role for a non-administrator carries the hint only: a
 *    non-administrator can hold every permission through several roles, and the server's
 *    `ADMINISTRATOR_REQUIRED` decides (administrator is per role, never the union).
 *
 * A PENDING target alone never disables anything (RC-69); it changes the confirm
 * ({@link assignConfirmKind}). The self-target rule (FR-C4) applies to the whole dialog
 * ({@link assignButtonAffordance}). Over-blocking is the safe direction; the server is final.
 */
export function roleAssignAffordance(
  role: RoleResponse,
  ctx: AssignContext,
  permissions: readonly string[] | null,
  blockAdminRolesForPending: boolean = PENDING_ADMIN_ROLE_BLOCK,
): AssignAffordance {
  if (ctx.assignedRoleIds.has(role.id)) return blocked('already-assigned');
  if (role.permissionCount > ctx.held.size) return blocked('role-needs-more-access');
  if (blockAdminRolesForPending && treatedAsAdminForPending(role, ctx)) {
    return blocked('pending-admin-role');
  }
  if (permissions !== null) {
    const missing = permissions.filter((code) => !ctx.held.has(code));
    if (missing.length > 0) return blocked('role-needs-more-access', missing);
    if (permissions.includes(DIRECTORY_READ) && !ctx.isAdministrator) {
      return blocked('admin-only-directory');
    }
  }
  return {
    kind: 'enabled',
    adminHint: !ctx.isAdministrator && hinted(role, ctx.catalogueTotal),
    checked: permissions !== null,
  };
}

/**
 * The confirm the dialog uses for a role (design §12.9, RC-69): the standard "Assign role" for a
 * verified target; "Assign to unverified account" (`danger`) for a PENDING one; and for a PENDING
 * target with a role treated as administrator-defining, the typed confirm with the role name.
 * While the H-2 block is on, that last combination is disabled before it can be confirmed.
 */
export function assignConfirmKind(role: RoleResponse, ctx: AssignContext): AssignConfirmKind {
  if (!ctx.targetIsPending) return 'assign';
  return treatedAsAdminForPending(role, ctx) ? 'typed-unverified' : 'assign-unverified';
}

/** Why the "Assign role" button is off (design §12.8, §14.2). */
export type AssignButtonReason =
  'profile-loading' | 'profile-unavailable' | 'self-assign' | 'no-role-read';

/** Everything the "Assign role" button reads, from the live profile (ADR-0028). */
export interface AssignButtonContext {
  readonly profileStatus: 'idle' | 'loading' | 'ready' | 'error';
  /** The caller may assign roles (`user:role:assign`). */
  readonly canAssign: boolean;
  /** The caller may read roles, which the picker needs (FR-C3, Q19). */
  readonly canReadRoles: boolean;
  /** The page is the caller's own, by user id (never by address). */
  readonly isSelf: boolean;
  readonly isAdministrator: boolean;
}

export type AssignButtonAffordance =
  | { readonly kind: 'hidden' }
  | { readonly kind: 'enabled' }
  | { readonly kind: 'disabled'; readonly reason: AssignButtonReason };

/**
 * The "Assign role" button (design §12.8; FR-C3, FR-C4, FR-G6; Q8, Q19):
 * - hidden without `user:role:assign`;
 * - off while the live profile loads, and with the "couldn't confirm your access" reason when it
 *   cannot be read (Q8, fail closed);
 * - on the caller's own page, off for a non-administrator (FR-C4); an administrator may assign to
 *   themself (the server's A4 decides);
 * - off without `role:read`: the picker cannot list roles or read what they grant.
 */
export function assignButtonAffordance(ctx: AssignButtonContext): AssignButtonAffordance {
  if (!ctx.canAssign) return { kind: 'hidden' };
  if (ctx.profileStatus === 'error') return { kind: 'disabled', reason: 'profile-unavailable' };
  if (ctx.profileStatus !== 'ready') return { kind: 'disabled', reason: 'profile-loading' };
  if (ctx.isSelf && !ctx.isAdministrator) return { kind: 'disabled', reason: 'self-assign' };
  if (!ctx.canReadRoles) return { kind: 'disabled', reason: 'no-role-read' };
  return { kind: 'enabled' };
}
