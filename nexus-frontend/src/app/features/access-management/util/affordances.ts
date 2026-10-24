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
