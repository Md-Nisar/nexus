const FALLBACK = '/dashboard';

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
 * character; has no `:` before the first `?` or `#`; is not under `/auth`; carries no
 * percent-encoded slash, backslash or control character in its path; and resolves to the
 * current origin.
 *
 * @security Open-redirect defence (US-019 RC-63(i)). Reject on doubt: the fallback is harmless.
 */
export function safeReturnUrl(raw: string | null): string {
  if (raw === null || raw.length === 0) return FALLBACK;
  if (!raw.startsWith('/') || raw[1] === '/' || raw[1] === '\\') return FALLBACK;
  if (raw.includes('\\') || CONTROL_CHARACTERS.test(raw)) return FALLBACK;

  const pathEnd = raw.search(/[?#]/);
  const path = pathEnd === -1 ? raw : raw.slice(0, pathEnd);
  if (path.includes(':') || ENCODED_PATH_HAZARD.test(path)) return FALLBACK;
  if (path === '/auth' || path.startsWith('/auth/')) return FALLBACK;

  const origin = globalThis.location.origin;
  try {
    return new URL(raw, origin).origin === origin ? raw : FALLBACK;
  } catch {
    return FALLBACK;
  }
}
