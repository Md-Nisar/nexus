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
});
