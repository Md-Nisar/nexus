/**
 * When an access change takes effect (US-020 design §9.3, Gate 1 Q3, FR-F3). **PROVISIONAL: not
 * UX/PM approved** (Gate 1 Q2).
 *
 * The minutes are derived from the two server TTLs below, never written by hand. If either TTL
 * changes in `application.yml` or in an environment, update these constants (PR template review
 * line; threat model §4.3 and release item §20.2 item 8 compare them per environment).
 */

/** Mirrors `nexus.jwt.access-token-ttl-seconds` (`application.yml:269`). */
export const ACCESS_TOKEN_TTL_SECONDS = 900;

/**
 * Mirrors `nexus.rbac.permission-cache-ttl-seconds` (`application.yml:157`); overridable per
 * environment, so check each environment's value.
 */
export const PERMISSION_CACHE_TTL_SECONDS = 900;

/** Whether access is being given or taken away. */
export type PropagationAction = 'grant' | 'revoke';

function minutes(seconds: number): number {
  return Math.ceil(seconds / 60);
}

/**
 * A grant does not bump the holder's epoch: it shows once the cached permissions expire and the
 * access token is renewed, so its ceiling is the longer of the two TTLs.
 */
const GRANT_MINUTES = minutes(Math.max(ACCESS_TOKEN_TTL_SECONDS, PERMISSION_CACHE_TTL_SECONDS));

/** A revoke applies on the next request, and in every case within both TTLs back to back. */
const REVOKE_CEILING_MINUTES = minutes(ACCESS_TOKEN_TTL_SECONDS + PERMISSION_CACHE_TTL_SECONDS);

/** The propagation lines (design §14.2). Plain text, rendered by interpolation. */
export const PROPAGATION_COPY: Readonly<Record<PropagationAction, string>> = {
  grant: `This takes effect within about ${GRANT_MINUTES} minutes, or when the person signs in again.`,
  revoke: `This takes effect on the person's next request, and in every case within about ${REVOKE_CEILING_MINUTES} minutes.`,
};

/** A permission replace (counts of what it adds and removes), an assign or a revoke. */
export type PropagationChange =
  { readonly added: number; readonly removed: number } | 'assign' | 'revoke';

/**
 * The lines to show for a change: the grant line for an assign or a replace that adds, the revoke
 * line for a revoke or a replace that removes; both for a replace that does both.
 */
export function propagationFor(change: PropagationChange): readonly string[] {
  if (change === 'assign') return [PROPAGATION_COPY.grant];
  if (change === 'revoke') return [PROPAGATION_COPY.revoke];
  return [
    ...(change.added > 0 ? [PROPAGATION_COPY.grant] : []),
    ...(change.removed > 0 ? [PROPAGATION_COPY.revoke] : []),
  ];
}
