import { DefaultUrlSerializer, PRIMARY_OUTLET, UrlSegmentGroup } from '@angular/router';

const FALLBACK = '/dashboard';

/**
 * The app registers no custom `UrlSerializer`, so this parses exactly as the router will. If one is
 * ever registered, inject it at the call sites and pass it here instead (US-020 D-2).
 */
const SERIALIZER = new DefaultUrlSerializer();

/** First path segments that must never be a post-login or post-retry destination (RC-70). */
const REJECTED_FIRST_SEGMENTS: ReadonlySet<string> = new Set(['auth', 'unavailable']);

/** C0 and C1 control characters, DEL, and the Unicode line separators. */
// eslint-disable-next-line no-control-regex
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;

/** Percent-encoded slash, backslash or C0 control in the path part (inspected, never decoded). */
const ENCODED_PATH_HAZARD = /%(?:2f|5c|0[0-9a-f]|1[0-9a-f]|7f)/i;

/**
 * Returns `raw` when it is a safe in-app destination for a post-login redirect, else `/dashboard`.
 *
 * `raw` comes from `queryParamMap`, which has already decoded the value once. This function
 * deliberately does **no decoding of its own**: decoding again would validate one string and
 * navigate another. The value returned is exactly the value validated.
 *
 * Accepted: starts with `/`; second character is not `/` or `\`; contains no `\` or control
 * character; has no `:` before the first `?` or `#`; carries no percent-encoded slash, backslash
 * or control character in its path; parses with the router's serializer; has a first primary
 * segment, **as the router decodes it**, other than `auth` or `unavailable`; has no `.` or `..`
 * segment; and resolves to the current origin.
 *
 * The segment rule reads the parse tree (so `/%61uth/login`, `/unavailable;x=1` and
 * `/(unavailable)` are rejected), but the string returned is still the string validated: the tree
 * is never serialised back, so there is no second decode (`/%2575navailable` is returned as is).
 *
 * @security Open-redirect defence (US-019 RC-63(i)); segment rule US-020 RC-70 as D-2. Reject on
 * doubt: the fallback is harmless.
 */
export function safeReturnUrl(raw: string | null): string {
  if (raw === null || raw.length === 0) return FALLBACK;
  if (!raw.startsWith('/') || raw[1] === '/' || raw[1] === '\\') return FALLBACK;
  if (raw.includes('\\') || CONTROL_CHARACTERS.test(raw)) return FALLBACK;

  const pathEnd = raw.search(/[?#]/);
  const path = pathEnd === -1 ? raw : raw.slice(0, pathEnd);
  if (path.includes(':') || ENCODED_PATH_HAZARD.test(path)) return FALLBACK;
  if (!hasSafeSegments(raw)) return FALLBACK;

  const origin = globalThis.location.origin;
  try {
    return new URL(raw, origin).origin === origin ? raw : FALLBACK;
  } catch {
    return FALLBACK;
  }
}

/**
 * True when `raw` parses and its primary outlet does not start with a rejected segment, and no
 * segment anywhere in the tree is `.` or `..` (the router matches those literally, but the address
 * bar normalises them away, so router and address bar would disagree). A parse failure is false.
 */
function hasSafeSegments(raw: string): boolean {
  let root: UrlSegmentGroup;
  try {
    root = SERIALIZER.parse(raw).root;
  } catch {
    return false;
  }
  const first = root.children[PRIMARY_OUTLET]?.segments[0]?.path;
  if (first !== undefined && REJECTED_FIRST_SEGMENTS.has(first)) return false;
  return !hasDotSegment(root);
}

function hasDotSegment(group: UrlSegmentGroup): boolean {
  if (group.segments.some((s) => s.path === '.' || s.path === '..')) return true;
  return Object.values(group.children).some(hasDotSegment);
}
