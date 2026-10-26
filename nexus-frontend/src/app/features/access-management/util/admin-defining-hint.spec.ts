import { describe, expect, it } from 'vitest';
import type { RoleResponse } from '../../../shared/types/api/rbac';
import { isAdminDefiningHint } from './admin-defining-hint';

function role(permissionCount: number, memberCount = 4): RoleResponse {
  return {
    id: 'role-1',
    name: 'Support',
    description: '',
    isSystemRole: false,
    createdAt: '2026-01-01T00:00:00Z',
    memberCount,
    permissionCount,
  };
}

/** The role, wrapped so every property read is recorded. */
function spied(target: RoleResponse): { role: RoleResponse; reads: string[] } {
  const reads: string[] = [];
  const proxy = new Proxy(target, {
    get(object, key, receiver) {
      reads.push(String(key));
      return Reflect.get(object, key, receiver);
    },
  });
  return { role: proxy, reads };
}

describe('isAdminDefiningHint (design §8.3, Q16, Q17)', () => {
  it('is true when the role carries as many permissions as the catalogue holds', () => {
    expect(isAdminDefiningHint(role(9), 9)).toBe(true);
  });

  it('is false for fewer permissions', () => {
    expect(isAdminDefiningHint(role(8), 9)).toBe(false);
  });

  it('is false when the catalogue total is not known', () => {
    expect(isAdminDefiningHint(role(0), 0)).toBe(false);
  });

  it('never reads memberCount (Q16: members are not a predictor)', () => {
    for (const count of [0, 8, 9]) {
      const { role: watched, reads } = spied(role(count, 9));
      isAdminDefiningHint(watched, 9);
      expect(reads).not.toContain('memberCount');
      expect(reads).toContain('permissionCount');
    }
  });
});
