import { describe, expect, it } from 'vitest';
import { AffordanceContext, permissionAffordance } from './affordances';

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
