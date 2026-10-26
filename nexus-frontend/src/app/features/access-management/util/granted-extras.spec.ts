import { describe, expect, it } from 'vitest';
import type { PermissionResponse } from '../../../shared/types/api/rbac';
import type { PermissionGroup } from '../data/catalogue.store';
import { withGrantedExtras } from './granted-extras';

function permission(name: string): PermissionResponse {
  return { id: `id-${name}`, name, description: '', isSensitive: false };
}

const ROLE_READ = permission('role:read');
const GROUPS: readonly PermissionGroup[] = [
  { resource: 'role', label: 'Roles', permissions: [ROLE_READ] },
];
const KNOWN = new Map([[ROLE_READ.id, ROLE_READ]]);

describe('withGrantedExtras', () => {
  it('returns the groups unchanged when every granted permission is known', () => {
    expect(withGrantedExtras(GROUPS, KNOWN, [ROLE_READ])).toBe(GROUPS);
  });

  it('adds an unknown granted permission to an Other group at the end', () => {
    const extra = permission('report:export');
    const groups = withGrantedExtras(GROUPS, KNOWN, [ROLE_READ, extra]);
    expect(groups.map((group) => group.resource)).toEqual(['role', 'other']);
    expect(groups[1].label).toBe('Other');
    expect(groups[1].permissions).toEqual([extra]);
  });

  it('appends to an existing Other group, keeping its label', () => {
    const known = permission('misc:thing');
    const withOther = [...GROUPS, { resource: 'other', label: 'Misc', permissions: [known] }];
    const extra = permission('report:export');
    const groups = withGrantedExtras(withOther, KNOWN, [extra]);
    expect(groups[1]).toEqual({ resource: 'other', label: 'Misc', permissions: [known, extra] });
  });
});
