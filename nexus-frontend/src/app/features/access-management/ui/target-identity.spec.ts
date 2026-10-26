import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../../shared/testing/axe';
import type { UserDirectoryEntry } from '../../../shared/types/api/user-directory';
import { CONSOLE_COPY } from '../copy/console-copy';
import { TargetIdentity } from './target-identity';

/** Synthetic addresses only; `.invalid` never resolves. */
const CLEAN = 'person.clean@identity.invalid';
/** U+202E RIGHT-TO-LEFT OVERRIDE inside the local part (T-S15). */
const RLO = `person${String.fromCodePoint(0x202e)}gnp.@identity.invalid`;
/** U+3164 HANGUL FILLER: renders as blank space (D-1). */
const HANGUL_FILLER = `person${String.fromCodePoint(0x3164)}@identity.invalid`;

function entry(overrides: Partial<UserDirectoryEntry> = {}): UserDirectoryEntry {
  return {
    userId: '0190a000-0000-7000-8000-000000000042',
    email: CLEAN,
    status: 'ACTIVE',
    emailVerified: true,
    createdAt: '2026-01-02T03:04:05Z',
    ...overrides,
  };
}

@Component({
  imports: [TargetIdentity],
  template: `<app-target-identity [target]="target" />`,
})
class Host {
  target: UserDirectoryEntry | null = null;
}

function render(target: UserDirectoryEntry | null) {
  const fixture = TestBed.createComponent(Host);
  fixture.componentInstance.target = target;
  fixture.detectChanges();
  const root: HTMLElement = fixture.nativeElement;
  const q = (id: string) => root.querySelector<HTMLElement>(`[data-testid="${id}"]`);
  const all = (id: string) => root.querySelectorAll<HTMLElement>(`[data-testid="${id}"]`);
  return { root, q, all };
}

function text(node: Element | null): string {
  return node?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
}

describe('TargetIdentity (US-020 design §12.9, §12.10; RC-68 item 2)', () => {
  it('shows the address, the status and the Verified badge of an active, verified person', () => {
    const { q, all } = render(entry());

    expect(q('target-identity')).not.toBeNull();
    expect(text(q('user-text'))).toBe(CLEAN);
    expect(q('user-status-badge')?.getAttribute('data-status')).toBe('ACTIVE');
    expect(text(q('target-identity-verified'))).toContain(CONSOLE_COPY.badges.verified);
    expect(q('target-identity-verified')?.getAttribute('data-verified')).toBe('true');
    expect(all('user-text-hidden-badge')).toHaveLength(0);
  });

  it('shows Pending and "Unverified email" for an unverified account', () => {
    const { q } = render(entry({ status: 'PENDING', emailVerified: false }));

    expect(q('user-status-badge')?.getAttribute('data-status')).toBe('PENDING');
    expect(text(q('user-status-badge'))).toContain(CONSOLE_COPY.badges.status.PENDING);
    expect(text(q('target-identity-verified'))).toContain(CONSOLE_COPY.badges.unverified);
    expect(q('target-identity-verified')?.getAttribute('data-verified')).toBe('false');
  });

  it.each([
    ['an RLO override', RLO, '202E'],
    ['a Hangul filler', HANGUL_FILLER, '3164'],
  ])(
    'with %s, renders the token, the hidden-character badge and its explanation',
    (_name, address, hex) => {
      const { root, q, all } = render(entry({ email: address }));

      const tokens = all('user-text-hidden-token');
      expect(tokens).toHaveLength(1);
      expect(tokens[0].textContent).toBe(`⟨U+${hex}⟩`);
      expect(tokens[0].getAttribute('aria-label')).toBe(`hidden character U+${hex}`);
      expect(text(q('user-text-hidden-badge'))).toContain(CONSOLE_COPY.badges.hiddenCharacters);
      expect(text(root)).toContain(CONSOLE_COPY.badges.hiddenCharactersEmailExplanation);
      // The hidden code point itself never reaches the DOM.
      expect(root.textContent).not.toContain(String.fromCodePoint(Number.parseInt(hex, 16)));
    },
  );

  it('falls back to "this person" without a directory entry (FR-X5), with no badges', () => {
    const { q, all } = render(null);

    expect(text(q('target-identity'))).toBe(CONSOLE_COPY.assign.person);
    expect(all('user-status-badge')).toHaveLength(0);
    expect(all('target-identity-verified')).toHaveLength(0);
  });

  it('has no axe violations, including the hidden-character badge', async () => {
    const { root } = render(entry({ email: RLO, status: 'PENDING', emailVerified: false }));
    await expect(expectNoAxeViolations(root)).resolves.toBeUndefined();
  });
});
