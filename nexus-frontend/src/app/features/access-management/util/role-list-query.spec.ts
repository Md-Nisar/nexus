import { describe, expect, it } from 'vitest';
import type { RoleResponse } from '../../../shared/types/api/rbac';
import { ROLE_PAGE_SIZE, parseRoleFilter, queryRoles } from './role-list-query';

function role(name: string, isSystemRole = false, id = `id-${name}`): RoleResponse {
  return {
    id,
    name,
    description: '',
    isSystemRole,
    createdAt: '2026-01-01T00:00:00Z',
    memberCount: 0,
    permissionCount: 0,
  };
}

const ALL = { q: '', filter: 'all', page: 0, size: ROLE_PAGE_SIZE } as const;

function names(rows: readonly RoleResponse[]): string[] {
  return rows.map((row) => row.name);
}

describe('queryRoles (US-020 design §6.4)', () => {
  it('keeps system roles first and the server order inside each group (stable partition)', () => {
    // The server orders by (name, id): Alpha, Bravo, MEMBER, Zulu, TENANT_ADMIN.
    const roles = [
      role('Alpha'),
      role('Bravo'),
      role('MEMBER', true),
      role('Zulu'),
      role('TENANT_ADMIN', true),
    ];

    expect(names(queryRoles(roles, ALL).rows)).toEqual([
      'MEMBER',
      'TENANT_ADMIN',
      'Alpha',
      'Bravo',
      'Zulu',
    ]);
  });

  it('keeps equal names in server (id) order', () => {
    const roles = [role('Same', false, 'a'), role('Same', false, 'b'), role('Same', false, 'c')];
    expect(queryRoles(roles, ALL).rows.map((row) => row.id)).toEqual(['a', 'b', 'c']);
  });

  it('does not mutate its input', () => {
    const roles = [role('Alpha'), role('MEMBER', true)];
    const copy = [...roles];
    queryRoles(roles, ALL);
    expect(roles).toEqual(copy);
  });

  describe('search', () => {
    const roles = [
      role('Support Agent'),
      role('support.lead'),
      role('A+B (test)'),
      role('a.b'),
      role('Billing'),
    ];

    it('is a case-folded substring match on the name', () => {
      expect(names(queryRoles(roles, { ...ALL, q: 'SUPPORT' }).rows)).toEqual([
        'Support Agent',
        'support.lead',
      ]);
    });

    it('trims the search text', () => {
      expect(names(queryRoles(roles, { ...ALL, q: '  bill  ' }).rows)).toEqual(['Billing']);
    });

    it('treats regex characters literally, never as a pattern', () => {
      expect(names(queryRoles(roles, { ...ALL, q: 'a.b' }).rows)).toEqual(['a.b']);
      expect(names(queryRoles(roles, { ...ALL, q: 'a+b' }).rows)).toEqual(['A+B (test)']);
      expect(queryRoles(roles, { ...ALL, q: '.*' }).rows).toEqual([]);
      expect(queryRoles(roles, { ...ALL, q: '(' }).rows).toHaveLength(1);
      expect(queryRoles(roles, { ...ALL, q: '[' }).rows).toEqual([]);
      expect(queryRoles(roles, { ...ALL, q: '\\' }).rows).toEqual([]);
    });

    it('does not search the description', () => {
      const withDescription = [{ ...role('Alpha'), description: 'findme' }];
      expect(queryRoles(withDescription, { ...ALL, q: 'findme' }).rows).toEqual([]);
    });

    it('treats blank text as no search', () => {
      expect(queryRoles(roles, { ...ALL, q: '   ' }).total).toBe(roles.length);
    });
  });

  describe('filter', () => {
    const roles = [role('Alpha'), role('MEMBER', true), role('Zulu')];

    it.each([
      ['all', ['MEMBER', 'Alpha', 'Zulu']],
      ['system', ['MEMBER']],
      ['custom', ['Alpha', 'Zulu']],
    ] as const)('filter %s', (filter, expected) => {
      expect(names(queryRoles(roles, { ...ALL, filter }).rows)).toEqual(expected);
    });

    it('combines with the search', () => {
      expect(names(queryRoles(roles, { ...ALL, filter: 'custom', q: 'z' }).rows)).toEqual(['Zulu']);
      expect(queryRoles(roles, { ...ALL, filter: 'system', q: 'z' }).rows).toEqual([]);
    });
  });

  describe('pagination', () => {
    const roles = Array.from({ length: 45 }, (_, i) => role(`Role ${String(i).padStart(2, '0')}`));

    it('returns 20 rows per page and the total of the filtered list', () => {
      const first = queryRoles(roles, ALL);
      expect(first.rows).toHaveLength(20);
      expect(first.total).toBe(45);
      expect(first.pageCount).toBe(3);
      expect(first.page).toBe(0);
      expect(first.rows[0].name).toBe('Role 00');
    });

    it('returns the remainder on the last page', () => {
      const last = queryRoles(roles, { ...ALL, page: 2 });
      expect(names(last.rows)).toEqual(
        Array.from({ length: 5 }, (_, i) => `Role ${String(40 + i).padStart(2, '0')}`),
      );
    });

    it('clamps a page past the end to the last page, and a negative page to the first', () => {
      expect(queryRoles(roles, { ...ALL, page: 99 }).page).toBe(2);
      expect(queryRoles(roles, { ...ALL, page: -3 }).page).toBe(0);
    });

    it('reports one empty page for no matches', () => {
      const none = queryRoles(roles, { ...ALL, q: 'zzz' });
      expect(none).toEqual({ rows: [], total: 0, page: 0, pageCount: 1 });
    });

    it('pages the filtered list, not the whole list', () => {
      const result = queryRoles(roles, { ...ALL, q: 'role 4' });
      expect(result.total).toBe(5);
      expect(result.pageCount).toBe(1);
    });
  });
});

describe('parseRoleFilter', () => {
  it.each([
    ['all', 'all'],
    ['system', 'system'],
    ['custom', 'custom'],
    [null, 'all'],
    ['', 'all'],
    ['unused', 'all'],
    ['SYSTEM', 'all'],
    ['<script>', 'all'],
  ])('%s gives %s', (raw, expected) => {
    expect(parseRoleFilter(raw)).toBe(expected);
  });
});
