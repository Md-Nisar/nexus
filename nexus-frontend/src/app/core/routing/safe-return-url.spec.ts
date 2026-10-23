import { describe, expect, it } from 'vitest';
import { safeReturnUrl } from './safe-return-url';

const FALLBACK = '/dashboard';

describe('safeReturnUrl', () => {
  it.each([
    ['protocol-relative', '//evil.example'],
    ['slash then backslash', '/\\evil.example'],
    ['double backslash', '\\\\evil'],
    ['absolute https', 'https://evil.example'],
    ['javascript scheme', 'javascript:alert(1)'],
    ['encoded protocol-relative', '%2F%2Fevil.example'],
    ['encoded backslash after slash', '/%5Cevil'],
    ['encoded backslash, lower case', '/%5cevil'],
    ['encoded slash in path', '/%2Fevil.example'],
    ['double-encoded protocol-relative', '%252F%252Fevil.example'],
    ['login loop', '/auth/login?returnUrl=%2Fdashboard'],
    ['auth root', '/auth'],
    ['auth subtree', '/auth/register'],
    ['NUL control character', '/dashboard\u0000'],
    ['encoded NUL', '/dashboard%00'],
    ['tab inside', '/da\tshboard'],
    ['newline inside', '/dashboard\n'],
    ['colon in path', '/a:b'],
    ['scheme-like path', '/javascript:alert(1)'],
    ['no leading slash', 'dashboard'],
    ['whitespace before slashes', ' //evil.example'],
    ['empty string', ''],
    ['null', null],
  ])('falls back to /dashboard for %s', (_name, raw) => {
    expect(safeReturnUrl(raw)).toBe(FALLBACK);
  });

  it('accepts an in-app path with query and fragment unchanged', () => {
    expect(safeReturnUrl('/dashboard?tab=x#y')).toBe('/dashboard?tab=x#y');
  });

  it('accepts a colon that appears only after the query starts', () => {
    expect(safeReturnUrl('/users?next=a:b')).toBe('/users?next=a:b');
  });

  it('does not decode: an encoded query value is returned exactly as given', () => {
    expect(safeReturnUrl('/users?q=a%2Fb')).toBe('/users?q=a%2Fb');
  });

  it('accepts the root path', () => {
    expect(safeReturnUrl('/')).toBe('/');
  });

  /**
   * RC-70 as D-2 (US-020): the first segment of the primary outlet, as the router's serializer
   * parses it, must not be `unavailable` or `auth`, and no segment may be `.` or `..`.
   */
  describe('segment rule (US-020 RC-70, D-2)', () => {
    it.each([
      ['the unavailable view', '/unavailable'],
      ['the unavailable view with its own returnUrl', '/unavailable?returnUrl=%2Fadmin'],
      ['an encoded first segment that decodes to unavailable', '/%75navailable'],
      ['an encoded first segment that decodes to auth', '/%61uth/login'],
      ['matrix parameters on unavailable', '/unavailable;x=1'],
      ['matrix parameters on auth', '/auth;x=1/login'],
      ['a parenthesised primary group', '/(unavailable)'],
      ['a dot-dot segment before unavailable', '/x/../unavailable'],
      ['an encoded dot-dot segment', '/%2e%2e/unavailable'],
      ['a dot segment', '/./unavailable'],
      ['a dot-dot segment in a nested primary group', '/admin/(..)'],
      ['a parse failure (unbalanced group)', '/(admin'],
      ['a parse failure (malformed percent sequence)', '/%E0%A4%A'],
    ])('falls back to /dashboard for %s', (_name, raw) => {
      expect(safeReturnUrl(raw)).toBe(FALLBACK);
    });

    it('does not decode twice: a double-encoded first segment is returned unchanged', () => {
      expect(safeReturnUrl('/%2575navailable')).toBe('/%2575navailable');
    });

    it('returns an allowed console path unchanged', () => {
      expect(safeReturnUrl('/admin/access/roles')).toBe('/admin/access/roles');
    });

    it('allows a path that only starts with the letters of a rejected segment', () => {
      expect(safeReturnUrl('/authors')).toBe('/authors');
      expect(safeReturnUrl('/unavailable-reports')).toBe('/unavailable-reports');
    });
  });
});
