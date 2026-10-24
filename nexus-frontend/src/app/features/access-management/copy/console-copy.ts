import type { RbacDenialReason, RbacErrorCode } from '../../../shared/types/api/rbac';
import type { DirectoryErrorCode } from '../../../shared/types/api/user-directory';

/**
 * Every string of the access console (US-020 design §9, §14). **PROVISIONAL: not UX/PM approved**
 * (Gate 1 Q2); approved D3 text replaces these values without code changes elsewhere.
 *
 * T-006 added the layout strings; T-007 adds the whole error map (`RbacErrorMessages`,
 * `Rbac001ReasonCopy`, `NotEnabledCopy`, `format`; A-10) and the roles list strings. Later tasks add
 * only the §14.2 page strings of their own pages. Permission labels live in `permission-labels.ts` (T-008)
 * and the propagation lines in `propagation.ts` (T-011).
 *
 * All values are plain text rendered by interpolation; none is ever HTML. The console renders this
 * text and never `AppError.message` (design §9.2).
 */
export const CONSOLE_COPY = {
  /** Accessible name of the area sub-nav (design §6.1). */
  areasLabel: 'Access management areas',

  /** Area tab labels and the one-line explainer each area page shows under its header (FR-G11). */
  areas: {
    roles: {
      label: 'Roles',
      explainer: 'Roles bundle permissions. Assign roles to people to give them access.',
    },
    permissions: {
      label: 'Permissions',
      explainer: 'Every permission Nexus can grant, grouped by what it controls.',
    },
    users: {
      label: 'Users',
      explainer: 'People in your organisation and the roles they hold.',
    },
  },

  /** The read-only banner when the live profile cannot be read (§14.1 `RESOURCE_NOT_FOUND` profile). */
  readOnly: {
    title: 'You can view, but not change, access',
    body: "We couldn't load your access details, so changes are turned off.",
    reference: 'Reference:',
    retry: 'Retry',
  },

  /** Visible reasons next to disabled controls (§14.2). */
  disabledReason: {
    profileUnavailable: "Changes are off because we couldn't confirm your access.",
    etagUnusable:
      'Saving is unavailable because a network component changed the version information Nexus needs.',
    /** Editor rows (§8.3). */
    notHeld: "You don't hold this permission, so you can't grant it.",
    adminOnlyDirectory: 'Only an administrator can grant access to email addresses.',
    roleExceedsCaller:
      "You can't remove permissions from this role because it includes access you don't hold.",
  },

  /** Hints that never disable anything (§8.3, Q17). */
  hints: {
    adminDemotion:
      'This role currently grants every permission. Removing any requires you to be an administrator through another role.',
    wholeCatalogue:
      'This role will grant every permission, which makes its members administrators.',
  },

  /** 503 `AUTH_005` on a page load (§14.1). */
  unavailable: {
    title: 'Nexus is temporarily unavailable',
    body: "We can't confirm your access right now.",
  },

  /** Label of the failure reference line ("Reference: {id}"). */
  reference: 'Reference:',

  /** Badges shared by the pages (§14.2). */
  badges: {
    system: 'System',
    custom: 'Custom',
    sensitive: 'Sensitive',
    unlabelled: 'Unlabelled',
    hiddenCharacters: 'Contains hidden characters',
    hiddenCharactersExplanation:
      'This text contains characters that are invisible or change text direction. Check it carefully.',
  },

  /** The roles list (§12.2, §14.2). */
  roles: {
    title: 'Roles',
    create: 'Create role',
    searchLabel: 'Search roles',
    filterLabel: 'Filter by type',
    filterAll: 'All',
    filterSystem: 'System',
    filterCustom: 'Custom',
    caption: 'Roles',
    resultCount: '{n} roles',
    resultCountOne: '1 role',
    loadingCount: 'Loading roles: {loaded} of {total}',
    loadingUnknown: 'Loading roles',
    truncated: 'Only the first {n} roles are loaded; search covers those only.',
    emptyCustom: 'No custom roles yet',
    emptySearch: 'No roles match your search',
    noDescription: 'No description',
    columns: {
      name: 'Name',
      type: 'Type',
      description: 'Description',
      permissions: 'Permissions',
      members: 'Members',
      created: 'Created',
    },
  },

  /** The permission catalogue (§12.6, §14.2). */
  catalogue: {
    title: 'Permissions',
    searchLabel: 'Search permissions',
    resultCount: '{n} permissions',
    resultCountOne: '1 permission',
    loading: 'Loading permissions',
    otherGroup: 'Other',
    emptyAll: 'No permissions to show',
    emptySearch: 'No permissions match your search',
    sensitiveSummary: 'What does Sensitive mean?',
    sensitiveDefinition:
      'Sensitive permissions control users, roles, role assignment or tenant settings, or let someone read personal data or the audit trail.',
  },

  /** The role detail page (§12.3, §14.1, §14.2). `{time}` is a relative time, `{n}` a count. */
  roleDetail: {
    breadcrumbRoot: 'Access management',
    breadcrumbRoles: 'Roles',
    /** The `h1` while the role is on its way; the name replaces it. */
    loadingTitle: 'Loading role',
    /** The `h1` when the role could not be read for a reason other than "not found". */
    fallbackTitle: 'Role',
    loading: 'Loading role',
    permissionCount: '{n} permissions',
    permissionCountOne: '1 permission',
    memberCount: '{n} members',
    memberCountOne: '1 member',
    countSeparator: ' · ',
    updated: 'Updated {time}',
    refresh: 'Refresh',
    edit: 'Edit permissions',
    clone: 'Clone',
    systemBanner:
      "This is a system role. Its permissions can't be changed. You can clone it to make a custom role.",
    etagUnusable: {
      title: 'Saving is unavailable',
      body: 'A network component changed the version information Nexus needs to save safely. You can still view this role.',
    },
    backToRoles: 'Back to Roles',
    tabsLabel: 'Role sections',
    tabPermissions: 'Permissions',
    emptyPermissions: 'This role grants no access yet',
    loadingPermissions: 'Loading permissions',
  },

  /** The permission matrix (§12.3, §13). `{role}` is the role name, rendered isolated. */
  matrix: {
    caption: 'Permissions granted by {role}',
    columns: {
      permission: 'Permission',
      code: 'Code',
      description: 'Description',
      status: 'Status',
    },
    granted: 'Granted',
    notGranted: 'Not granted',
  },

  /** The role editor (§12.4, §14.2). `{label}`, `{code}`, `{group}` are catalogue text. */
  editor: {
    rowLabel: '{label} ({code})',
    groupLabel: 'All {group} permissions',
    footerLabel: 'Staged changes',
    footerCounts: '{n} to add, {m} to remove',
    discard: 'Discard',
    review: 'Review changes',
    loading: 'Loading the editor',
    noWrite: "You can't change this role's permissions.",
    backToPermissions: 'Back to permissions',
  },

  /** The Review dialog (§12.4, §14.2). `{role}` is the role name, rendered isolated. */
  review: {
    title: 'Review changes to {role}',
    adding: 'Adding ({n})',
    removing: 'Removing ({n})',
    affected: 'Who is affected',
    members: '{n} people hold this role.',
    membersOne: '1 person holds this role.',
    membersNone: 'No one holds this role yet.',
    emptyResult: 'This role will grant no access.',
    cancel: 'Cancel',
    save: 'Save changes',
    grantSensitive: 'Grant sensitive access',
  },

  /**
   * Saving the editor's changes (§12.4, §14.2). `{n}`, `{m}` are counts, `{labels}` permission
   * labels joined by `listSeparator`, `{changes}` the conflict parts joined by
   * `conflictPartSeparator`.
   */
  save: {
    success: 'Role updated: {n} added, {m} removed.',
    noop: 'No changes to save.',
    ownAccess: 'Your own access has changed.',
    alreadyInPlace: 'Your changes are already in place.',
    conflictChanged: 'Changed by someone else: {changes}.',
    conflictAdded: 'added {labels}',
    conflictRemoved: 'removed {labels}',
    conflictPartSeparator: '; ',
    conflictInPlace: 'Already in place: {labels}.',
    listSeparator: ', ',
    wait: 'Try again in {n} seconds.',
  },

  /**
   * Drafts of staged work (§10, §12.4, §14.2; D-6). `{time}` is a relative time, `{labels}`
   * permission labels joined by `save.listSeparator`.
   */
  draft: {
    offer: 'You have unsaved changes to this role from {time}.',
    offerQuestion: 'Restore or discard?',
    restore: 'Restore',
    discard: 'Discard',
    restoredTitle: 'Your unsaved changes are back',
    outdated: 'This role has changed since you saved these changes. Check them before saving.',
    notRestored: "Not restored because you can't grant them: {labels}.",
  },

  /**
   * Create and Clone (§12.5, §14.1 `VALIDATION_FAILED`, §14.2). `{name}` is the source role's name,
   * `{labels}` permission labels joined by `save.listSeparator`, `{n}` and `{max}` counts.
   */
  createRole: {
    title: 'Create role',
    nameLabel: 'Name',
    nameHint: 'Letters, numbers, spaces, dots, hyphens and underscores',
    descriptionLabel: 'Description',
    counter: '{n} of {max}',
    permissionsTitle: 'Permissions',
    permissionsHint: 'Optional. You can only grant permissions you hold yourself.',
    /** The matrix caption's role while the name is still empty. */
    unnamedRole: 'the new role',
    submit: 'Create role',
    cancel: 'Cancel',
    loading: 'Loading the form',
    loadingSource: 'Loading the role to copy',
    noWrite: "You can't create roles.",
    success: 'Role created.',
    partial: "Role created, but its permissions weren't saved.",
    retry: 'Retry',
    openRole: 'Open role',
    cloneName: 'Copy of {name}',
    notCopied: "Not copied, because you can't grant them: {labels}",
    notCopiedItem: '{label}: {reason}',
    summaryTitle: 'Some details need fixing',
    leaveMessage: "The role hasn't been created yet, so nothing is kept.",
    errors: {
      nameRequired: 'Enter a role name',
      nameTooLong: 'Use 64 characters or fewer',
      namePattern:
        'Start with a letter or number, then use letters, numbers, spaces, dots, hyphens or underscores',
      nameReserved: 'This name is reserved',
      descriptionTooLong: 'Use 255 characters or fewer',
      descriptionControl: 'Remove line breaks and control characters',
    },
  },

  /** The unsaved-changes prompt (§4.8, §14.2). */
  leave: {
    title: 'Leave without saving?',
    message: 'Your changes stay as a draft in this tab.',
    confirm: 'Leave',
    cancel: 'Stay',
  },
} as const;

/**
 * Every error code the console has copy for (design §2.3): the RBAC codes, the directory codes and
 * the generic codes. Any other code gets the generic copy plus a reference.
 */
export type ConsoleErrorCode =
  | RbacErrorCode
  | DirectoryErrorCode
  | 'VALIDATION_FAILED'
  | 'PRECONDITION_FAILED'
  | 'PRECONDITION_REQUIRED'
  | 'RESOURCE_NOT_FOUND'
  | 'ROLE_NOT_FOUND'
  | 'USER_NOT_FOUND'
  | 'PERMISSION_NOT_FOUND'
  | 'ROLE_ASSIGNMENT_NOT_FOUND'
  | 'ACCESS_DENIED'
  | 'AUTH_005'
  | 'NETWORK_ERROR'
  | 'HTTP_ERROR'
  | 'INTERNAL_ERROR'
  | 'UNEXPECTED_ERROR';

/** Where an error shows: beside the control, in a banner, in place of the page, or at a field. */
export type ErrorPresentation = 'inline' | 'banner' | 'page' | 'field';

/** Title and body of one error (design §9.1). Both are plain text; `{n}` style placeholders only. */
export interface ErrorCopy {
  readonly title: string;
  readonly body: string;
  readonly presentation: ErrorPresentation;
  /** The server already agrees with what the user wanted (already assigned, already removed). */
  readonly convergent?: true;
  /** Show "Reference: {traceId or correlationId}". */
  readonly showsReference?: true;
  /** The body carries `{n}` seconds to wait; the control stays off for that long. */
  readonly showsWait?: true;
  /** A retry cannot help (the thing is gone, or the area is switched off). */
  readonly retryable?: false;
}

/** The area an error occurred in; chooses the "not enabled" copy of a `RESOURCE_NOT_FOUND`. */
export type ConsoleErrorArea = 'roles' | 'permissions' | 'users' | 'assignments' | 'profile';

/** Replaces `{name}` with the matching value as text; a placeholder with no value stays as written. */
export function format(
  template: string,
  values: Readonly<Record<string, string | number>>,
): string {
  return template.replace(/\{(\w+)\}/g, (placeholder, key: string) =>
    Object.hasOwn(values, key) ? String(values[key]) : placeholder,
  );
}

/** Why a 403 `RBAC_001` was refused (design §14.1). */
export const Rbac001ReasonCopy: Readonly<Record<RbacDenialReason, ErrorCopy>> = {
  GRANT_EXCEEDS_CALLER: {
    title: "You can't grant this",
    body: "This includes access you don't hold yourself. Ask someone who holds it, or an administrator.",
    presentation: 'inline',
    showsReference: true,
  },
  SELF_ASSIGNMENT: {
    title: "You can't change your own roles",
    body: 'Ask an administrator to make this change.',
    presentation: 'inline',
    showsReference: true,
  },
  ADMINISTRATOR_REQUIRED: {
    title: 'Administrator needed',
    body: 'Only an administrator can make this change.',
    presentation: 'inline',
    showsReference: true,
  },
  UNSPECIFIED: {
    title: "You don't have permission to do this",
    body: 'If you think you should, contact your administrator and quote the reference.',
    presentation: 'inline',
    showsReference: true,
  },
};

/** "Not enabled" copy of a `RESOURCE_NOT_FOUND`, by area: the feature flag is off (design §12.0). */
export const NotEnabledCopy: Readonly<Record<ConsoleErrorArea, ErrorCopy>> = {
  roles: {
    title: "Roles aren't enabled",
    body: "Role management isn't turned on for your organisation yet.",
    presentation: 'page',
    retryable: false,
  },
  permissions: {
    title: "Roles aren't enabled",
    body: "Role management isn't turned on for your organisation yet.",
    presentation: 'page',
    retryable: false,
  },
  users: {
    title: "Users aren't enabled",
    body: "The user directory isn't turned on for your organisation yet.",
    presentation: 'page',
    retryable: false,
  },
  assignments: {
    title: "Role assignment isn't enabled",
    body: "Assigning roles isn't turned on for your organisation yet.",
    presentation: 'page',
    retryable: false,
  },
  profile: {
    title: 'You can view, but not change, access',
    body: "We couldn't load your access details, so changes are turned off.",
    presentation: 'banner',
    retryable: false,
  },
};

/** A `VALIDATION_FAILED` on a list load: the page parameter is out of range (design §14.1). */
export const ListPageErrorCopy: Readonly<Record<'default' | 'users', ErrorCopy>> = {
  default: {
    title: "This page doesn't exist",
    body: 'Go back to the first page.',
    presentation: 'page',
  },
  users: {
    title: "This page doesn't exist",
    body: 'This page is past the end of the list. Use the status filter to narrow it.',
    presentation: 'page',
  },
};

/** A 503 `AUTH_005` on an action rather than a page load (design §14.1). */
export const ActionUnavailableCopy: ErrorCopy = {
  title: 'Nothing was changed',
  body: 'Nexus is temporarily unavailable. Try again in {n} seconds.',
  presentation: 'inline',
  showsReference: true,
  showsWait: true,
};

const GENERIC: ErrorCopy = {
  title: 'Something went wrong',
  body: 'Try again. If it keeps happening, contact support and quote the reference.',
  presentation: 'page',
  showsReference: true,
};

/**
 * The copy of every {@link ConsoleErrorCode} (design §9.1, §14.1; provisional D3). Exhaustive by
 * type. `RBAC_001` here is the reason-less copy; use {@link Rbac001ReasonCopy} when the error
 * carries a reason. `RESOURCE_NOT_FOUND` here is the roles copy; see {@link NotEnabledCopy}.
 *
 * `RBAC_006` and `RBAC_007` show at the name field; their titles are the fallback for assistive
 * technology and summaries.
 */
export const RbacErrorMessages: Readonly<Record<ConsoleErrorCode, ErrorCopy>> = {
  RBAC_001: Rbac001ReasonCopy.UNSPECIFIED,
  RBAC_002: {
    title: 'This would leave no administrator',
    body: "Nexus didn't remove this role because your organisation would have no administrator. Give someone else an administrator role first.",
    presentation: 'inline',
  },
  RBAC_003: {
    title: "System roles can't be changed",
    body: 'You can clone this role to make a custom one.',
    presentation: 'banner',
  },
  RBAC_004: {
    title: 'Already assigned',
    body: 'This person already had this role.',
    presentation: 'inline',
    convergent: true,
  },
  RBAC_005: {
    title: 'Already granted',
    body: 'This permission is already on the role.',
    presentation: 'inline',
    convergent: true,
  },
  RBAC_006: {
    title: 'Role name already in use',
    body: 'A role with this name already exists. Choose another name.',
    presentation: 'field',
  },
  RBAC_007: {
    title: 'Role name is reserved',
    body: 'This name is reserved. Choose another name.',
    presentation: 'field',
  },
  RBAC_008: {
    title: 'Role limit reached',
    body: 'Your organisation has reached its limit for roles. Delete a role you no longer need, then try again.',
    presentation: 'banner',
  },
  RBAC_009: {
    title: 'Role still has members',
    body: 'Remove all {n} members before deleting this role.',
    presentation: 'inline',
  },
  RBAC_010: {
    title: 'An administrator needs to review this role',
    body: "This change would give the role every permission while one of its members was assigned by someone who isn't an administrator. Ask an administrator to review its members first.",
    presentation: 'inline',
    showsReference: true,
  },
  RBAC_011: {
    title: 'Too many refused attempts',
    body: 'Try again in {n} seconds.',
    presentation: 'inline',
    showsWait: true,
  },
  RBAC_012: {
    title: 'The role changed while saving',
    body: "This role changed while your change was being saved. We tried again and it still didn't go through. Reload the role and try again.",
    presentation: 'inline',
    showsReference: true,
  },
  USER_DIR_001: {
    title: 'Too many lookups',
    body: 'Try again in {n} seconds.',
    presentation: 'inline',
    showsWait: true,
  },
  USER_DIR_002: {
    title: 'Too many requests',
    body: "You've made a lot of directory requests in a short time. Try again in {n} seconds.",
    presentation: 'inline',
    showsWait: true,
  },
  VALIDATION_FAILED: {
    title: 'Some details need fixing',
    body: 'Fix the highlighted details and try again.',
    presentation: 'field',
  },
  PRECONDITION_FAILED: {
    title: 'Someone else changed this role',
    body: 'Their changes are now shown, and your changes are still staged. Review them and save again.',
    presentation: 'banner',
  },
  PRECONDITION_REQUIRED: {
    title: "We couldn't save this",
    body: 'A technical problem stopped the save. Your changes are kept.',
    presentation: 'inline',
    showsReference: true,
  },
  RESOURCE_NOT_FOUND: NotEnabledCopy.roles,
  ROLE_NOT_FOUND: {
    title: 'This role no longer exists',
    body: 'It may have been deleted. Go back to Roles.',
    presentation: 'page',
    retryable: false,
  },
  USER_NOT_FOUND: {
    title: "We couldn't find this person",
    body: "They aren't in your organisation, or the link is wrong.",
    presentation: 'page',
    retryable: false,
  },
  PERMISSION_NOT_FOUND: {
    title: 'A permission no longer exists',
    body: 'Reload the page and try again.',
    presentation: 'inline',
    showsReference: true,
  },
  ROLE_ASSIGNMENT_NOT_FOUND: {
    title: 'Already removed',
    body: 'This role had already been removed.',
    presentation: 'inline',
    convergent: true,
  },
  ACCESS_DENIED: {
    title: "You don't have access to this",
    body: 'Contact your administrator and quote the reference.',
    presentation: 'inline',
    showsReference: true,
  },
  AUTH_005: {
    title: CONSOLE_COPY.unavailable.title,
    body: CONSOLE_COPY.unavailable.body,
    presentation: 'page',
    showsReference: true,
    showsWait: true,
  },
  NETWORK_ERROR: {
    title: "We couldn't reach Nexus",
    body: 'Check your connection and try again.',
    presentation: 'page',
  },
  HTTP_ERROR: GENERIC,
  INTERNAL_ERROR: GENERIC,
  UNEXPECTED_ERROR: GENERIC,
};
