/**
 * Every string of the access console (US-020 design §9, §14). **PROVISIONAL: not UX/PM approved**
 * (Gate 1 Q2); approved D3 text replaces these values without code changes elsewhere.
 *
 * T-006 adds the layout strings only. The error map (`RbacErrorMessages`, `resolveConsoleError`,
 * `format`) arrives with the first page that maps errors (A-10).
 *
 * All values are plain text rendered by interpolation; none is ever HTML.
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
  },

  /** 503 `AUTH_005` on a page load (§14.1). */
  unavailable: {
    title: 'Nexus is temporarily unavailable',
    body: "We can't confirm your access right now.",
  },
} as const;
