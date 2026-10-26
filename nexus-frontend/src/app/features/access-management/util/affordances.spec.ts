import { ESLint, Linter } from 'eslint';
import { describe, expect, it } from 'vitest';
import type { RoleResponse } from '../../../shared/types/api/rbac';
import {
  AffordanceContext,
  AssignButtonContext,
  AssignContext,
  PENDING_ADMIN_ROLE_BLOCK,
  assignButtonAffordance,
  assignConfirmKind,
  permissionAffordance,
  roleAssignAffordance,
  targetNeedsVerification,
} from './affordances';

const DIRECTORY = 'id-user:directory:read';
const ALL = ['id-role:read', 'id-role:write', 'id-user:read', 'id-audit:read', DIRECTORY];

function ctx(overrides: Partial<AffordanceContext> = {}): AffordanceContext {
  return {
    held: new Set(['id-role:read', 'id-role:write', 'id-user:read']),
    isAdministrator: false,
    roleSet: new Set(['id-role:read']),
    isSystemRole: false,
    mutationsEnabled: true,
    directoryReadId: DIRECTORY,
    adminDefiningHint: false,
    ...overrides,
  };
}

describe('permissionAffordance (design §8.3, Q18: mirror the server)', () => {
  it('renders no control at all on a system role (FR-B7)', () => {
    for (const id of ['id-role:read', 'id-audit:read']) {
      expect(permissionAffordance(id, ctx({ isSystemRole: true }))).toEqual({
        kind: 'not-editable',
      });
    }
  });

  it('disables every row while the live profile is unavailable (Q8)', () => {
    for (const id of ['id-role:read', 'id-user:read', 'id-audit:read']) {
      expect(permissionAffordance(id, ctx({ mutationsEnabled: false }))).toEqual({
        kind: 'disabled',
        reason: 'profile-unavailable',
      });
    }
  });

  it('disables every row while a restore offer is pending, with its own reason (MJ-1)', () => {
    for (const id of ['id-role:read', 'id-user:read']) {
      expect(permissionAffordance(id, ctx({ offerPending: true }))).toEqual({
        kind: 'disabled',
        reason: 'draft-offer-pending',
      });
    }
    // The profile being unavailable is still the reason when both apply.
    expect(
      permissionAffordance('id-user:read', ctx({ offerPending: true, mutationsEnabled: false })),
    ).toMatchObject({ reason: 'profile-unavailable' });
  });

  it('enables adding a permission the caller holds', () => {
    expect(permissionAffordance('id-user:read', ctx())).toEqual({ kind: 'enabled' });
  });

  it('disables adding a permission the caller does not hold (grant-subset)', () => {
    expect(permissionAffordance('id-audit:read', ctx())).toEqual({
      kind: 'disabled',
      reason: 'not-held',
    });
  });

  it('disables adding user:directory:read for a non-administrator who holds it (PII rule)', () => {
    const held = new Set(['id-role:read', DIRECTORY]);
    expect(permissionAffordance(DIRECTORY, ctx({ held }))).toEqual({
      kind: 'disabled',
      reason: 'admin-only-directory',
    });
  });

  it('gives a non-administrator who does not hold it the grant-subset reason, as the server does', () => {
    expect(permissionAffordance(DIRECTORY, ctx())).toEqual({
      kind: 'disabled',
      reason: 'not-held',
    });
  });

  it('lets an administrator add user:directory:read', () => {
    const admin = ctx({ held: new Set(ALL), isAdministrator: true });
    expect(permissionAffordance(DIRECTORY, admin)).toEqual({ kind: 'enabled' });
  });

  it('enables removal when the caller holds every permission of the role', () => {
    const role = ctx({ roleSet: new Set(['id-role:read', 'id-user:read']) });
    expect(permissionAffordance('id-user:read', role)).toEqual({ kind: 'enabled' });
  });

  it('disables every removal when the role carries a permission the caller lacks (role-subset)', () => {
    const role = ctx({ roleSet: new Set(['id-role:read', 'id-audit:read']) });
    for (const id of ['id-role:read', 'id-audit:read']) {
      expect(permissionAffordance(id, role)).toEqual({
        kind: 'disabled',
        reason: 'role-exceeds-caller',
      });
    }
    // Adds are judged by the grant-subset rule only.
    expect(permissionAffordance('id-user:read', role)).toEqual({ kind: 'enabled' });
  });

  it('only hints when removing from an admin-defining role, never disables', () => {
    const role = ctx({
      held: new Set(ALL),
      isAdministrator: true,
      roleSet: new Set(ALL),
      adminDefiningHint: true,
    });
    expect(permissionAffordance('id-audit:read', role)).toEqual({
      kind: 'enabled',
      hint: 'hint-admin-demotion',
    });
  });

  it('hints, not blocks, a non-administrator holding every permission through several roles', () => {
    const union = ctx({
      held: new Set(ALL),
      isAdministrator: false,
      roleSet: new Set(ALL),
      adminDefiningHint: true,
    });
    for (const id of ALL) {
      expect(permissionAffordance(id, union)).toEqual({
        kind: 'enabled',
        hint: 'hint-admin-demotion',
      });
    }
  });

  it('works without a known directory permission id', () => {
    expect(permissionAffordance('id-user:read', ctx({ directoryReadId: null }))).toEqual({
      kind: 'enabled',
    });
  });
});

/** The caller of the assign specs: a role-reader user manager (four codes, not an administrator). */
const MANAGER = ['role:read', 'user:read', 'user:role:assign', 'user:directory:read'] as const;
const CATALOGUE_TOTAL = 9;

function candidate(permissionCount: number, id = 'role-1'): RoleResponse {
  return {
    id,
    name: 'Support',
    description: '',
    isSystemRole: false,
    createdAt: '2026-01-01T00:00:00Z',
    memberCount: 0,
    permissionCount,
  };
}

function assignCtx(overrides: Partial<AssignContext> = {}): AssignContext {
  return {
    held: new Set<string>(MANAGER),
    isAdministrator: false,
    assignedRoleIds: new Set<string>(),
    catalogueTotal: CATALOGUE_TOTAL,
    targetIsPending: false,
    ...overrides,
  };
}

/** The file the D-4 "no runtime input" spec reads, relative to the workspace root. */
const AFFORDANCES = 'src/app/features/access-management/util/affordances.ts';

/** Rules that fail on any runtime input path into the H-2 block (D-4). */
const NO_RUNTIME_INPUT: Linter.RulesRecord = {
  'no-restricted-imports': [
    'error',
    {
      patterns: [
        { group: ['**/app-config', '**/environments/**', '**/environment*'], message: 'config' },
        { group: ['@angular/*'], message: 'runtime (DI, Router, HTTP)' },
        { group: ['**/drafts/**', '**/*storage*'], message: 'storage' },
      ],
    },
  ],
  'no-restricted-globals': [
    'error',
    'window',
    'document',
    'location',
    'localStorage',
    'sessionStorage',
    'indexedDB',
    'navigator',
  ],
};

/** Every code of a nine-entry catalogue. */
const EVERY = [
  ...MANAGER,
  'role:write',
  'audit:read',
  'tenant:read',
  'tenant:write',
  'user:write',
] as const;

const ADMINISTRATOR = assignCtx({ held: new Set<string>(EVERY), isAdministrator: true });

describe('roleAssignAffordance (design §8.3 assign table, Q18: mirror the server)', () => {
  it('(a) disables a role the target already holds', () => {
    expect(
      roleAssignAffordance(candidate(1), assignCtx({ assignedRoleIds: new Set(['role-1']) }), null),
    ).toEqual({ kind: 'disabled', reason: 'already-assigned', missing: [] });
  });

  it('(b) pigeonhole: more permissions than the caller holds is disabled before any load', () => {
    expect(roleAssignAffordance(candidate(5), assignCtx(), null)).toEqual({
      kind: 'disabled',
      reason: 'role-needs-more-access',
      missing: [],
    });
  });

  it('(b) after the load, a permission the caller does not hold disables with the missing codes', () => {
    expect(roleAssignAffordance(candidate(2), assignCtx(), ['role:read', 'audit:read'])).toEqual({
      kind: 'disabled',
      reason: 'role-needs-more-access',
      missing: ['audit:read'],
    });
  });

  it('PII rule: a role carrying user:directory:read is administrator-only', () => {
    expect(roleAssignAffordance(candidate(1), assignCtx(), ['user:directory:read'])).toEqual({
      kind: 'disabled',
      reason: 'admin-only-directory',
      missing: [],
    });
  });

  it('PII rule: grant-subset is evaluated first, as on the server', () => {
    const notHolding = assignCtx({ held: new Set(['role:read']) });
    expect(roleAssignAffordance(candidate(1), notHolding, ['user:directory:read'])).toMatchObject({
      reason: 'role-needs-more-access',
      missing: ['user:directory:read'],
    });
  });

  it('an administrator may assign a role carrying user:directory:read', () => {
    expect(roleAssignAffordance(candidate(1), ADMINISTRATOR, ['user:directory:read'])).toEqual({
      kind: 'enabled',
      adminHint: false,
      checked: true,
    });
  });

  it("is enabled but not checked until the role's permissions are loaded", () => {
    expect(roleAssignAffordance(candidate(2), assignCtx(), null)).toEqual({
      kind: 'enabled',
      adminHint: false,
      checked: false,
    });
    expect(roleAssignAffordance(candidate(2), assignCtx(), ['role:read', 'user:read'])).toEqual({
      kind: 'enabled',
      adminHint: false,
      checked: true,
    });
  });

  it('(c) a hinted admin-defining role for a non-administrator is a hint, never a block', () => {
    const union = assignCtx({
      held: new Set(Array.from({ length: CATALOGUE_TOTAL }, (_, i) => `code-${i}`)),
    });
    const codes = [...union.held];
    expect(roleAssignAffordance(candidate(CATALOGUE_TOTAL), union, null)).toEqual({
      kind: 'enabled',
      adminHint: true,
      checked: false,
    });
    // Union of roles: holding every permission through several roles is not an administrator;
    // the server's ADMINISTRATOR_REQUIRED decides (administrator is per role, never the union).
    expect(roleAssignAffordance(candidate(CATALOGUE_TOTAL), union, codes)).toEqual({
      kind: 'enabled',
      adminHint: true,
      checked: true,
    });
  });

  it('(c) gives no hint to an administrator', () => {
    expect(roleAssignAffordance(candidate(CATALOGUE_TOTAL), ADMINISTRATOR, null)).toMatchObject({
      kind: 'enabled',
      adminHint: false,
    });
  });

  describe('PENDING targets (RC-69, H-2, D-4)', () => {
    const pending = (overrides: Partial<AssignContext> = {}): AssignContext =>
      assignCtx({ targetIsPending: true, ...overrides });

    it('RC-69: is never disabled because the target is PENDING alone', () => {
      expect(roleAssignAffordance(candidate(1), pending(), ['role:read'])).toEqual({
        kind: 'enabled',
        adminHint: false,
        checked: true,
      });
    });

    it('H-2: a hinted admin-defining role to a PENDING target is disabled pending-admin-role', () => {
      expect(
        roleAssignAffordance(
          candidate(CATALOGUE_TOTAL),
          { ...ADMINISTRATOR, targetIsPending: true },
          null,
        ),
      ).toEqual({
        kind: 'disabled',
        reason: 'pending-admin-role',
        missing: [],
      });
    });

    it('RC-69: a non-hinted role to a PENDING target is allowed (the server stays authoritative)', () => {
      expect(
        roleAssignAffordance(
          candidate(CATALOGUE_TOTAL - 1),
          { ...ADMINISTRATOR, targetIsPending: true },
          null,
        ),
      ).toMatchObject({ kind: 'enabled' });
    });

    it('D-4: with an unknown catalogue total every role is treated as hinted (fail closed)', () => {
      for (const total of [null, 0]) {
        for (const count of [0, 1, 2]) {
          expect(
            roleAssignAffordance(candidate(count), pending({ catalogueTotal: total }), null),
          ).toEqual({ kind: 'disabled', reason: 'pending-catalogue-unknown', missing: [] });
        }
      }
    });

    it('D-4: an unknown total has its own reason, never the administrator-role one (MJ-3)', () => {
      expect(
        roleAssignAffordance(candidate(1), pending({ catalogueTotal: null }), null),
      ).toMatchObject({ reason: 'pending-catalogue-unknown' });
      expect(
        roleAssignAffordance(candidate(1), pending({ catalogueTotal: null }), null, false),
      ).toMatchObject({ kind: 'enabled' });
    });

    it('D-4: an unknown total gives an ACTIVE target no hint and no block', () => {
      expect(roleAssignAffordance(candidate(1), assignCtx({ catalogueTotal: null }), null)).toEqual(
        { kind: 'enabled', adminHint: false, checked: false },
      );
    });

    it('D-4: the block defaults to on, and only a parameter turns it off', () => {
      expect(PENDING_ADMIN_ROLE_BLOCK).toBe(true);
      const ctx = { ...ADMINISTRATOR, targetIsPending: true };
      expect(roleAssignAffordance(candidate(CATALOGUE_TOTAL), ctx, null)).toMatchObject({
        reason: 'pending-admin-role',
      });
      expect(roleAssignAffordance(candidate(CATALOGUE_TOTAL), ctx, null, false)).toMatchObject({
        kind: 'enabled',
      });
    });

    it('D-4: the module has no runtime input path (no AppConfig, environment, Router, URL or storage)', async () => {
      const eslint = new ESLint({ overrideConfig: { rules: NO_RUNTIME_INPUT } });
      const offences = (messages: readonly Linter.LintMessage[]) =>
        messages.filter((message) => message.ruleId !== null && message.ruleId in NO_RUNTIME_INPUT);

      // Control: the rules do catch a config import and a storage read.
      const [control] = await eslint.lintText(
        `import { APP_CONFIG } from '../../../core/config/app-config';
export const block = APP_CONFIG !== null && sessionStorage.getItem('block') === null;
`,
        { filePath: AFFORDANCES },
      );
      expect(offences(control.messages).length).toBeGreaterThanOrEqual(2);

      const [result] = await eslint.lintFiles([AFFORDANCES]);
      expect(offences(result.messages)).toEqual([]);
    });
  });
});

describe('targetNeedsVerification (RC-69, H-2: fail closed, Low 1)', () => {
  it('treats an unknown target as unverified', () => {
    expect(targetNeedsVerification(null)).toBe(true);
  });

  it('treats PENDING, or any account without a verified address, as unverified', () => {
    expect(targetNeedsVerification({ status: 'PENDING', emailVerified: false })).toBe(true);
    expect(targetNeedsVerification({ status: 'PENDING', emailVerified: true })).toBe(true);
    expect(targetNeedsVerification({ status: 'ACTIVE', emailVerified: false })).toBe(true);
  });

  it('treats an ACTIVE, verified account as verified', () => {
    expect(targetNeedsVerification({ status: 'ACTIVE', emailVerified: true })).toBe(false);
  });
});

describe('assignConfirmKind (design §12.9, RC-69)', () => {
  it('is the standard confirm for an ACTIVE target', () => {
    expect(assignConfirmKind(candidate(CATALOGUE_TOTAL), assignCtx())).toBe('assign');
  });

  it('is "Assign to unverified account" for a PENDING target and a non-hinted role', () => {
    expect(assignConfirmKind(candidate(1), assignCtx({ targetIsPending: true }))).toBe(
      'assign-unverified',
    );
  });

  it('is the typed confirm for a PENDING target and a hinted role (reachable once F-4 lifts H-2)', () => {
    const pending = assignCtx({ targetIsPending: true });
    expect(assignConfirmKind(candidate(CATALOGUE_TOTAL), pending)).toBe('typed-unverified');
    // D-4: with an unknown total every role counts as hinted for a PENDING target.
    expect(assignConfirmKind(candidate(1), { ...pending, catalogueTotal: null })).toBe(
      'typed-unverified',
    );
  });
});

describe('assignButtonAffordance (design §12.8, FR-C4)', () => {
  function button(overrides: Partial<AssignButtonContext> = {}): AssignButtonContext {
    return {
      profileStatus: 'ready',
      canAssign: true,
      canReadRoles: true,
      isSelf: false,
      isAdministrator: false,
      ...overrides,
    };
  }

  it('is hidden without user:role:assign', () => {
    expect(assignButtonAffordance(button({ canAssign: false }))).toEqual({ kind: 'hidden' });
  });

  it('is enabled for a role-reading assigner on someone else', () => {
    expect(assignButtonAffordance(button())).toEqual({ kind: 'enabled' });
  });

  it("FR-C4: is disabled on the caller's own page for a non-administrator", () => {
    expect(assignButtonAffordance(button({ isSelf: true }))).toEqual({
      kind: 'disabled',
      reason: 'self-assign',
    });
  });

  it('FR-G6: lets an administrator assign to themself', () => {
    expect(assignButtonAffordance(button({ isSelf: true, isAdministrator: true }))).toEqual({
      kind: 'enabled',
    });
  });

  it('is disabled while the live profile loads, and with a reason when it is unavailable (Q8)', () => {
    expect(assignButtonAffordance(button({ profileStatus: 'loading' }))).toEqual({
      kind: 'disabled',
      reason: 'profile-loading',
    });
    expect(assignButtonAffordance(button({ profileStatus: 'error' }))).toEqual({
      kind: 'disabled',
      reason: 'profile-unavailable',
    });
  });

  it('is disabled with a reason without role:read, which the picker needs (FR-C3, Q19)', () => {
    expect(assignButtonAffordance(button({ canReadRoles: false }))).toEqual({
      kind: 'disabled',
      reason: 'no-role-read',
    });
  });
});
