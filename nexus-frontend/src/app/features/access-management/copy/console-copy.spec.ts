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

describe('CONSOLE_COPY (role detail strings, design §7.2, §12.3, §14)', () => {
  it('has the D3 role detail strings', () => {
    expect(CONSOLE_COPY.roleDetail.systemBanner).toBe(
      "This is a system role. Its permissions can't be changed. You can clone it to make a custom role.",
    );
    expect(CONSOLE_COPY.roleDetail.emptyPermissions).toBe('This role grants no access yet');
    expect(CONSOLE_COPY.roleDetail.updated).toBe('Updated {time}');
    expect(CONSOLE_COPY.roleDetail.edit).toBe('Edit permissions');
    expect(CONSOLE_COPY.roleDetail.clone).toBe('Clone');
    expect(CONSOLE_COPY.matrix.caption).toBe('Permissions granted by {role}');
    expect(CONSOLE_COPY.matrix.granted).toBe('Granted');
    expect(CONSOLE_COPY.matrix.notGranted).toBe('Not granted');
  });

  it('has the ETag-unusable banner (§14.1) and the Edit reason (§7.2)', () => {
    expect(CONSOLE_COPY.roleDetail.etagUnusable.title).toBe('Saving is unavailable');
    expect(CONSOLE_COPY.roleDetail.etagUnusable.body).toBe(
      'A network component changed the version information Nexus needs to save safely. You can still view this role.',
    );
    expect(CONSOLE_COPY.disabledReason.etagUnusable).toBe(
      'Saving is unavailable because a network component changed the version information Nexus needs.',
    );
  });

  it('puts the role name in the caption only through the {role} placeholder', () => {
    expect(CONSOLE_COPY.matrix.caption.split('{role}')).toHaveLength(2);
  });
});

describe('CONSOLE_COPY (editor and Review strings, design §4.8, §12.4, §14.2)', () => {
  it('has the D3 disabled reasons and hints of the editor rules (§8.3)', () => {
    expect(CONSOLE_COPY.disabledReason.notHeld).toBe(
      "You don't hold this permission, so you can't grant it.",
    );
    expect(CONSOLE_COPY.disabledReason.adminOnlyDirectory).toBe(
      'Only an administrator can grant access to email addresses.',
    );
    expect(CONSOLE_COPY.disabledReason.roleExceedsCaller).toBe(
      "You can't remove permissions from this role because it includes access you don't hold.",
    );
    expect(CONSOLE_COPY.hints.adminDemotion).toBe(
      'This role currently grants every permission. Removing any requires you to be an administrator through another role.',
    );
    expect(CONSOLE_COPY.hints.wholeCatalogue).toBe(
      'This role will grant every permission, which makes its members administrators.',
    );
  });

  it('has the D3 editor, Review and leave strings', () => {
    expect(CONSOLE_COPY.editor.footerCounts).toBe('{n} to add, {m} to remove');
    expect(CONSOLE_COPY.editor.discard).toBe('Discard');
    expect(CONSOLE_COPY.editor.review).toBe('Review changes');
    expect(CONSOLE_COPY.editor.rowLabel).toBe('{label} ({code})');
    expect(CONSOLE_COPY.editor.groupLabel).toBe('All {group} permissions');
    expect(CONSOLE_COPY.review.title).toBe('Review changes to {role}');
    expect(CONSOLE_COPY.review.adding).toBe('Adding ({n})');
    expect(CONSOLE_COPY.review.removing).toBe('Removing ({n})');
    expect(CONSOLE_COPY.review.affected).toBe('Who is affected');
    expect(CONSOLE_COPY.review.members).toBe('{n} people hold this role.');
    expect(CONSOLE_COPY.review.membersNone).toBe('No one holds this role yet.');
    expect(CONSOLE_COPY.review.emptyResult).toBe('This role will grant no access.');
    expect(CONSOLE_COPY.review.save).toBe('Save changes');
    expect(CONSOLE_COPY.review.grantSensitive).toBe('Grant sensitive access');
    expect(CONSOLE_COPY.leave).toEqual({
      title: 'Leave without saving?',
      message: 'Your changes stay as a draft in this tab.',
      confirm: 'Leave',
      cancel: 'Stay',
    });
  });

  it('puts the role name in the Review title only through the {role} placeholder', () => {
    expect(CONSOLE_COPY.review.title.split('{role}')).toHaveLength(2);
  });
});

describe('CONSOLE_COPY (save strings, design §12.4, §14.2)', () => {
  it('has the D3 success, own-access and conflict strings', () => {
    expect(CONSOLE_COPY.save.success).toBe('Role updated: {n} added, {m} removed.');
    expect(CONSOLE_COPY.save.noop).toBe('No changes to save.');
    expect(CONSOLE_COPY.save.ownAccess).toBe('Your own access has changed.');
    expect(CONSOLE_COPY.save.alreadyInPlace).toBe('Your changes are already in place.');
    // §14.2 "Conflict lists", rebuilt from its parts when both sides changed.
    const changed = format(CONSOLE_COPY.save.conflictChanged, {
      changes: [
        format(CONSOLE_COPY.save.conflictAdded, { labels: 'A' }),
        format(CONSOLE_COPY.save.conflictRemoved, { labels: 'B' }),
      ].join(CONSOLE_COPY.save.conflictPartSeparator),
    });
    expect(changed).toBe('Changed by someone else: added A; removed B.');
    expect(format(CONSOLE_COPY.save.conflictInPlace, { labels: 'C' })).toBe('Already in place: C.');
  });

  it('has the wait countdown', () => {
    expect(format(CONSOLE_COPY.save.wait, { n: 30 })).toBe('Try again in 30 seconds.');
  });
});

describe('CONSOLE_COPY (draft strings, design §10, §14.2; D-6)', () => {
  it('has the D3 restore offer, outdated and not-restored strings', () => {
    const { draft } = CONSOLE_COPY;
    expect(format(draft.offer, { time: '5 minutes ago' })).toBe(
      'You have unsaved changes to this role from 5 minutes ago.',
    );
    expect(draft.offerQuestion).toBe('Restore or discard?');
    expect(draft.restore).toBe('Restore');
    expect(draft.discard).toBe('Discard');
    expect(draft.outdated).toBe(
      'This role has changed since you saved these changes. Check them before saving.',
    );
    expect(format(draft.notRestored, { labels: 'A, B' })).toBe(
      "Not restored because you can't grant them: A, B.",
    );
    expect(draft.restoredTitle.length).toBeGreaterThan(0);
  });
});

describe('CONSOLE_COPY (users list strings, design §12.7, §14.2; RC-68)', () => {
  it('has the D3 users list, lookup and badge strings', () => {
    const { users, badges } = CONSOLE_COPY;
    expect(users.title).toBe('Users');
    expect(users.lookupLabel).toBe('Find by email');
    expect(users.lookupHint).toBe('Enter a full email address');
    expect(users.lookupCaption).toBe('Lookup result');
    expect(users.lookupMiss).toBe('No one in your organisation has this email address.');
    expect(users.emptyFilter).toBe('No users match this filter');
    expect(format(users.lookupWait, { n: 4 })).toBe('Try again in 4 seconds.');
    expect(badges.status).toEqual({
      ACTIVE: 'Active',
      PENDING: 'Pending',
      LOCKED: 'Locked',
      DISABLED: 'Disabled',
    });
    expect([badges.verified, badges.unverified, badges.you]).toEqual([
      'Verified',
      'Unverified email',
      '(you)',
    ]);
  });

  it('has the RC-68 address explanation, token text and token accessible name', () => {
    const { badges } = CONSOLE_COPY;
    expect(badges.hiddenCharactersEmailExplanation).toBe(
      'This address contains characters that are invisible or change text direction. Check it carefully before giving access.',
    );
    expect(format(badges.hiddenCharacterToken, { hex: '202E' })).toBe('⟨U+202E⟩');
    expect(format(badges.hiddenCharacterName, { hex: '202E' })).toBe('hidden character U+202E');
  });
});

describe('CONSOLE_COPY (user page strings, design §12.8, §14.2; Q19)', () => {
  it('has the D3 status notes, keyed by the statuses that get one', () => {
    expect(CONSOLE_COPY.userDetail.statusNotes).toEqual({
      LOCKED: "This person is locked out and can't sign in until the lock ends.",
      DISABLED: 'This account is disabled.',
      PENDING: "This person hasn't verified their email address yet.",
    });
    expect(format(CONSOLE_COPY.userDetail.joined, { date: 'Jan 2, 2026' })).toBe(
      'Joined Jan 2, 2026',
    );
  });

  it('has the D3 Roles tab strings, including both degraded notes', () => {
    const { userRoles } = CONSOLE_COPY;
    expect(userRoles.empty).toBe('No roles assigned');
    expect(userRoles.noUserRead).toBe("You need permission to read users' roles to see this.");
    expect(userRoles.noRoleRead).toBe("Role details are hidden because you can't read roles.");
    expect(userRoles.columns).toEqual({
      role: 'Role',
      type: 'Type',
      assigned: 'Assigned',
      assignedBy: 'Assigned by',
      actions: 'Actions',
    });
  });

  it('has the D3 Revoke strings (§12.10, §14.2)', () => {
    const { revoke } = CONSOLE_COPY;
    expect(revoke.title).toBe('Remove {role} from {person}?');
    expect(revoke.loses).toBe('They will lose: {labels}.');
    expect(revoke.losesGeneric).toBe('They will lose the access this role grants.');
    expect(revoke.adminWarning).toBe(
      'This role grants every permission. If no other administrator would remain, Nexus will refuse this change.',
    );
    expect(revoke.confirm).toBe('Remove role');
    expect(revoke.success).toBe('Role removed.');
    expect(revoke.selfTitle).toBe('Remove your own {role} role?');
    expect(revoke.selfMessage).toBe('You will lose access to this page.');
    expect(revoke.selfConfirm).toBe('Remove my role');
  });

  it('never puts an address placeholder in the breadcrumb or the title copy', () => {
    for (const value of strings(CONSOLE_COPY.userDetail)) expect(value).not.toContain('{email');
  });
});
