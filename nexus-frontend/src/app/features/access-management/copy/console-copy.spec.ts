import { describe, expect, it } from 'vitest';
import { RBAC_DENIAL_REASONS } from '../../../shared/types/api/rbac';
import {
  CONSOLE_COPY,
  ConsoleErrorCode,
  ErrorCopy,
  NotEnabledCopy,
  Rbac001ReasonCopy,
  RbacErrorMessages,
  format,
} from './console-copy';

/** Every string leaf of the copy object. */
function strings(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (value !== null && typeof value === 'object') return Object.values(value).flatMap(strings);
  return [];
}

describe('CONSOLE_COPY (layout strings, US-020 design §14; provisional D3)', () => {
  it('has no empty string', () => {
    for (const text of strings(CONSOLE_COPY)) expect(text.trim()).not.toBe('');
  });

  it('never contains the literal 500 (Q28, N5)', () => {
    for (const text of strings(CONSOLE_COPY)) expect(text).not.toContain('500');
  });

  it('gives each area a one-line explainer with no "Learn more" link (FR-G11, Q25)', () => {
    for (const area of Object.values(CONSOLE_COPY.areas)) {
      expect(area.explainer).not.toMatch(/\n/);
      expect(area.explainer.toLowerCase()).not.toContain('learn more');
    }
  });

  it('uses the D3 profile-unavailable strings (design §14.1, §14.2)', () => {
    expect(CONSOLE_COPY.readOnly.title).toBe('You can view, but not change, access');
    expect(CONSOLE_COPY.readOnly.body).toBe(
      "We couldn't load your access details, so changes are turned off.",
    );
    expect(CONSOLE_COPY.disabledReason.profileUnavailable).toBe(
      "Changes are off because we couldn't confirm your access.",
    );
    expect(CONSOLE_COPY.unavailable).toEqual({
      title: 'Nexus is temporarily unavailable',
      body: "We can't confirm your access right now.",
    });
  });
});

/**
 * Every code the console handles: requirements §3.2 and design §2.3, written out here so a code
 * added to the union without copy (or copy without a code) fails this spec.
 */
const EVERY_CODE: readonly ConsoleErrorCode[] = [
  'RBAC_001',
  'RBAC_002',
  'RBAC_003',
  'RBAC_004',
  'RBAC_005',
  'RBAC_006',
  'RBAC_007',
  'RBAC_008',
  'RBAC_009',
  'RBAC_010',
  'RBAC_011',
  'RBAC_012',
  'USER_DIR_001',
  'USER_DIR_002',
  'VALIDATION_FAILED',
  'PRECONDITION_FAILED',
  'PRECONDITION_REQUIRED',
  'RESOURCE_NOT_FOUND',
  'ROLE_NOT_FOUND',
  'USER_NOT_FOUND',
  'PERMISSION_NOT_FOUND',
  'ROLE_ASSIGNMENT_NOT_FOUND',
  'ACCESS_DENIED',
  'AUTH_005',
  'NETWORK_ERROR',
  'HTTP_ERROR',
  'INTERNAL_ERROR',
  'UNEXPECTED_ERROR',
];

const COPY_PRESENTATIONS = ['inline', 'banner', 'page', 'field'];

function allCopies(): { name: string; copy: ErrorCopy }[] {
  return [
    ...Object.entries(RbacErrorMessages).map(([name, copy]) => ({ name, copy })),
    ...Object.entries(Rbac001ReasonCopy).map(([name, copy]) => ({
      name: `RBAC_001/${name}`,
      copy,
    })),
    ...Object.entries(NotEnabledCopy).map(([name, copy]) => ({
      name: `not-enabled/${name}`,
      copy,
    })),
  ];
}

describe('RbacErrorMessages (design §9.1, §14.1; provisional D3)', () => {
  it('has copy for exactly the codes of requirements §3.2 and design §2.3', () => {
    expect(Object.keys(RbacErrorMessages).sort()).toEqual([...EVERY_CODE].sort());
  });

  it.each(EVERY_CODE)('%s has a title, a body and a valid presentation', (code) => {
    const copy = RbacErrorMessages[code];
    expect(copy.title.trim()).not.toBe('');
    expect(copy.body.trim()).not.toBe('');
    expect(COPY_PRESENTATIONS).toContain(copy.presentation);
  });

  it('has copy for every RBAC_001 denial reason, and no copy shows the raw reason', () => {
    expect(Object.keys(Rbac001ReasonCopy).sort()).toEqual([...RBAC_DENIAL_REASONS].sort());
    for (const reason of RBAC_DENIAL_REASONS) {
      const copy = Rbac001ReasonCopy[reason];
      expect(copy.title.trim()).not.toBe('');
      expect(copy.body.trim()).not.toBe('');
      expect(copy.showsReference).toBe(true);
    }
  });

  it('uses the UNSPECIFIED reason copy for the bare RBAC_001 code', () => {
    expect(RbacErrorMessages.RBAC_001).toEqual(Rbac001ReasonCopy.UNSPECIFIED);
  });

  it('has not-enabled copy for every area, with no retry and no reference', () => {
    expect(Object.keys(NotEnabledCopy).sort()).toEqual(
      ['assignments', 'permissions', 'profile', 'roles', 'users'].sort(),
    );
    for (const copy of Object.values(NotEnabledCopy)) {
      expect(copy.title.trim()).not.toBe('');
      expect(copy.retryable).toBe(false);
    }
  });

  it('never shows a raw code in a title or body', () => {
    for (const { name, copy } of allCopies()) {
      for (const text of [copy.title, copy.body]) {
        expect(text, name).not.toMatch(/\b(RBAC|USER_DIR|AUTH)_\d{3}\b/);
        expect(text, name).not.toMatch(/\b[A-Z]{3,}(_[A-Z]+)+\b/);
      }
    }
  });

  it('never contains the literal 500 (Q28, N5)', () => {
    for (const { name, copy } of allCopies()) {
      expect(copy.title, name).not.toContain('500');
      expect(copy.body, name).not.toContain('500');
    }
  });

  it('is plain text: no markup in any string', () => {
    for (const { name, copy } of allCopies()) {
      expect(copy.title + copy.body, name).not.toMatch(/[<>]/);
    }
  });

  it('marks the rate-limit codes as waits and the convergent codes as convergent', () => {
    for (const code of ['RBAC_011', 'USER_DIR_001', 'USER_DIR_002', 'AUTH_005'] as const) {
      expect(RbacErrorMessages[code].showsWait, code).toBe(true);
    }
    for (const code of ['RBAC_004', 'RBAC_005', 'ROLE_ASSIGNMENT_NOT_FOUND'] as const) {
      expect(RbacErrorMessages[code].convergent, code).toBe(true);
    }
  });

  it('shows the reference for exactly the codes of the §14.1 "Ref" column', () => {
    const withReference = EVERY_CODE.filter((code) => RbacErrorMessages[code].showsReference);
    expect(withReference.sort()).toEqual(
      [
        'RBAC_001',
        'RBAC_010',
        'RBAC_012',
        'PRECONDITION_REQUIRED',
        'PERMISSION_NOT_FOUND',
        'ACCESS_DENIED',
        'AUTH_005',
        'HTTP_ERROR',
        'INTERNAL_ERROR',
        'UNEXPECTED_ERROR',
      ].sort(),
    );
  });

  it('uses the D3 strings for the codes users meet most', () => {
    expect(Rbac001ReasonCopy.GRANT_EXCEEDS_CALLER.title).toBe("You can't grant this");
    expect(Rbac001ReasonCopy.SELF_ASSIGNMENT.title).toBe("You can't change your own roles");
    expect(Rbac001ReasonCopy.ADMINISTRATOR_REQUIRED.title).toBe('Administrator needed');
    expect(RbacErrorMessages.RBAC_002.title).toBe('This would leave no administrator');
    expect(RbacErrorMessages.NETWORK_ERROR.title).toBe("We couldn't reach Nexus");
    expect(RbacErrorMessages.INTERNAL_ERROR.title).toBe('Something went wrong');
    expect(NotEnabledCopy.roles.title).toBe("Roles aren't enabled");
    expect(NotEnabledCopy.users.title).toBe("Users aren't enabled");
  });
});

describe('format (design §9.1)', () => {
  it('substitutes {placeholders} with text', () => {
    expect(format('Try again in {n} seconds.', { n: 30 })).toBe('Try again in 30 seconds.');
    expect(format('{a} and {a}', { a: 'x' })).toBe('x and x');
  });

  it('inserts values as text, never interpreting them', () => {
    expect(format('Role {role}', { role: '<img src=x onerror=alert(1)>' })).toBe(
      'Role <img src=x onerror=alert(1)>',
    );
    expect(format('{a}', { a: '$& {b}', b: 'no' })).toBe('$& {b}');
  });

  it('leaves a placeholder without a value as written and ignores unused values', () => {
    expect(format('Remove {n} members', {})).toBe('Remove {n} members');
    expect(format('Plain', { n: 1 })).toBe('Plain');
  });

  it('does not read inherited object properties', () => {
    expect(format('{constructor} {toString}', {})).toBe('{constructor} {toString}');
  });
});

describe('CONSOLE_COPY (roles page strings, design §14.2)', () => {
  it('has the D3 roles list strings', () => {
    expect(CONSOLE_COPY.roles.loadingCount).toBe('Loading roles: {loaded} of {total}');
    expect(CONSOLE_COPY.roles.truncated).toBe(
      'Only the first {n} roles are loaded; search covers those only.',
    );
    expect(CONSOLE_COPY.roles.emptyCustom).toBe('No custom roles yet');
    expect(CONSOLE_COPY.roles.emptySearch).toBe('No roles match your search');
    expect(CONSOLE_COPY.roles.noDescription).toBe('No description');
    expect(CONSOLE_COPY.badges.system).toBe('System');
    expect(CONSOLE_COPY.badges.custom).toBe('Custom');
    expect(CONSOLE_COPY.badges.hiddenCharacters).toBe('Contains hidden characters');
  });
});
