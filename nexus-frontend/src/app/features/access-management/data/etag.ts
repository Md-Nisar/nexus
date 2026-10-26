/**
 * The version tag of a role's permission set as the console holds it (US-020 design §7.1, §7.2;
 * threat model SD-8; ADR-0027).
 *
 * - `strong`: the only kind a save may use. `value` is the header **verbatim, quotes included**,
 *   and is sent back unchanged as `If-Match`.
 * - `weak`: a `W/` tag, typically produced by an intermediary that compressed the response. The
 *   server refuses it (428), so it carries no value: nothing can send it back, and the `W/` prefix
 *   is never stripped to make it look strong (DQ-5).
 * - `missing`: no header, or anything that is not exactly one strong tag.
 */
export type EtagState =
  | { readonly kind: 'strong'; readonly value: string }
  | { readonly kind: 'weak' }
  | { readonly kind: 'missing' };

export type EtagKind = EtagState['kind'];

/**
 * One quoted, non-empty opaque tag of visible ASCII other than the double quote: the grammar the
 * server's `IfMatchHeader.STRONG_TAG` accepts, so a tag classified strong here is one the PUT
 * accepts. No surrounding whitespace is allowed; the value is not trimmed.
 */
const STRONG_TAG = /^"[\x21\x23-\x7E]+"$/;

/** The weak-tag prefix; case-sensitive (RFC 9110 §8.8.3). */
const WEAK_PREFIX = 'W/';

/**
 * Classifies the `ETag` header of `GET /roles/{id}/permissions` (design §7.2). Pure.
 *
 * Strong only for exactly one strong entity-tag. A `W/` prefix is weak. Null, empty, unquoted, a
 * list, `*` or anything else is missing.
 */
export function classifyEtag(raw: string | null): EtagState {
  if (raw === null) return { kind: 'missing' };
  if (STRONG_TAG.test(raw)) return { kind: 'strong', value: raw };
  if (raw.startsWith(WEAK_PREFIX)) return { kind: 'weak' };
  return { kind: 'missing' };
}
