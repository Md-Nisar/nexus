import { describe, expect, it } from 'vitest';
import { environment as development } from '../../../environments/environment.development';
import { SupportContact, parseSupportContact } from './app-config';

describe('accessConsoleEnabled (US-020 design §18)', () => {
  // environment.ts (false) is not asserted here: the unit-test build applies the development
  // `fileReplacements`, so any import of `environments/environment` yields the development file.
  it('ships true in environment.development.ts', () => {
    expect(development.accessConsoleEnabled).toBe(true);
  });
});

describe('parseSupportContact', () => {
  it('accepts mailto and https contacts', () => {
    const mail = { label: 'Help', href: 'mailto:help@example.com' };
    const web = { label: 'Help', href: 'https://example.com/help' };
    expect(parseSupportContact(mail)).toBe(mail);
    expect(parseSupportContact(web)).toBe(web);
  });

  it.each([
    ['javascript:', { label: 'Help', href: 'javascript:alert(1)' }],
    ['scheme-relative', { label: 'Help', href: '//evil.example' }],
    ['whitespace in the href', { label: 'Help', href: 'https://example.com/a b' }],
    ['a blank label', { label: '   ', href: 'https://example.com' }],
    ['a null contact', null],
    ['an undefined contact', undefined],
  ])('rejects %s', (_name, raw) => {
    expect(parseSupportContact(raw as SupportContact | null | undefined)).toBeNull();
  });

  it.each([
    ['label', { label: 42, href: 'https://example.com' }],
    ['label (null)', { label: null, href: 'https://example.com' }],
    ['href', { label: 'Help', href: 42 }],
    ['missing label', { href: 'https://example.com' }],
  ])('returns null instead of throwing on a non-string %s', (_name, raw) => {
    expect(() => parseSupportContact(raw as unknown as SupportContact)).not.toThrow();
    expect(parseSupportContact(raw as unknown as SupportContact)).toBeNull();
  });
});
