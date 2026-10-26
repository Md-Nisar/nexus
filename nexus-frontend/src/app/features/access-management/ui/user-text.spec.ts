import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../../shared/testing/axe';
import { hasHiddenCharacters } from '../util/hidden-characters';
import { UserText, UserTextMode } from './user-text';

@Component({
  imports: [UserText],
  template: `<app-user-text [text]="text" [maxLines]="maxLines" [mode]="mode" />`,
})
class Host {
  text = '';
  maxLines: number | null = null;
  mode: UserTextMode = 'text';
}

function render(text: string, maxLines: number | null = null, mode: UserTextMode = 'text') {
  const fixture = TestBed.createComponent(Host);
  fixture.componentInstance.text = text;
  fixture.componentInstance.maxLines = maxLines;
  fixture.componentInstance.mode = mode;
  fixture.detectChanges();
  const root: HTMLElement = fixture.nativeElement;
  return { fixture, root, bdi: root.querySelector('bdi') as HTMLElement };
}

describe('UserText (text mode; US-020 design §6.1, §15.3)', () => {
  it('renders the text inside a <bdi>, by interpolation', () => {
    const { bdi } = render('Support Agent');
    expect(bdi.tagName).toBe('BDI');
    expect(bdi.textContent).toBe('Support Agent');
  });

  it('scenario 24: markup and an override character stay text, with no element created', () => {
    const hostile = '<img src=x onerror=alert(1)>‮';
    const { root, bdi } = render(hostile);

    expect(bdi.textContent).toBe(hostile);
    expect(root.querySelector('img')).toBeNull();
    expect(root.querySelectorAll('bdi')).toHaveLength(1);
    expect(bdi.children).toHaveLength(0);
  });

  it.each([
    '<script>alert(1)</script>',
    '"><svg onload=alert(1)>',
    '<a href="javascript:alert(1)">x</a>',
    '&lt;b&gt;',
  ])('renders %j as literal text', (hostile) => {
    const { root, bdi } = render(hostile);
    expect(bdi.textContent).toBe(hostile);
    expect(bdi.children).toHaveLength(0);
    expect(root.querySelector('script, svg, a, b')).toBeNull();
  });

  describe('truncation (G8)', () => {
    it('does not truncate by default and sets no title', () => {
      const { bdi } = render('A long name');
      expect(bdi.classList.contains('user-text--clamped')).toBe(false);
      expect(bdi.hasAttribute('title')).toBe(false);
    });

    it('clamps to the given number of lines and keeps the full text as content and as title', () => {
      const text = 'A very long description '.repeat(30);
      const { bdi } = render(text, 2);

      expect(bdi.classList.contains('user-text--clamped')).toBe(true);
      expect(bdi.style.getPropertyValue('--user-text-lines')).toBe('2');
      expect(bdi.textContent).toBe(text);
      expect(bdi.getAttribute('title')).toBe(text);
    });
  });

  describe('hidden characters (RC-68, D-1)', () => {
    it('shows no badge for clean text', () => {
      const { root } = render('Support Agent');
      expect(root.querySelector('[data-testid="user-text-hidden-badge"]')).toBeNull();
    });

    it.each([
      ['an override', 'abc‮def'],
      ['a zero-width space', 'a​b'],
      ['a Hangul filler', 'aㅤb'],
      ['a variation selector', 'a️b'],
      ['a no-break space', 'a b'],
    ])('shows the badge, outside the text, for %s', (_name, text) => {
      const { root, bdi } = render(text, 1);

      const badge = root.querySelector('[data-testid="user-text-hidden-badge"]') as HTMLElement;
      expect(badge).not.toBeNull();
      expect(badge.textContent).toContain('Contains hidden characters');
      expect(bdi.contains(badge)).toBe(false);
      // The text itself is unchanged: text mode only adds the badge.
      expect(bdi.textContent).toBe(text);
    });

    it('describes the badge with the explanation', () => {
      const { root } = render('a​b');
      const badge = root.querySelector('[data-testid="user-text-hidden-badge"]') as HTMLElement;
      const described = root.querySelector(`#${badge.getAttribute('aria-describedby')}`);
      expect(described?.textContent).toContain('invisible or change text direction');
    });
  });

  it('has no axe violations', async () => {
    const { root } = render('abc‮def', 1);
    await expectNoAxeViolations(root);
  });

  describe('email mode (RC-68, D-1)', () => {
    const DOMAIN = '@directory.invalid';
    const TOKEN = /⟨U\+([0-9A-F]{4,6})⟩/g;

    function tokens(root: HTMLElement): HTMLElement[] {
      return Array.from(root.querySelectorAll('[data-testid="user-text-hidden-token"]'));
    }

    /** The text as rendered, with each token turned back into the code point it names. */
    function decoded(bdi: HTMLElement): string {
      return (bdi.textContent ?? '').replace(TOKEN, (_token, hex: string) =>
        String.fromCodePoint(Number.parseInt(hex, 16)),
      );
    }

    it('renders a clean address as plain text, with no token and no badge', () => {
      const text = `clean.person${DOMAIN}`;
      const { root, bdi } = render(text, null, 'email');

      expect(bdi.textContent).toBe(text);
      expect(tokens(root)).toHaveLength(0);
      expect(root.querySelector('[data-testid="user-text-hidden-badge"]')).toBeNull();
    });

    it.each([
      ['a right-to-left override', `adm\u202Enimda${DOMAIN}`, ['202E']],
      ['a zero-width joiner', `ad\u200Dmin${DOMAIN}`, ['200D']],
      ['a Hangul filler', `ad\u3164min${DOMAIN}`, ['3164']],
      ['a no-break space and a byte-order mark', `a\u00A0b\uFEFF${DOMAIN}`, ['00A0', 'FEFF']],
    ])('shows %s as a visible token with an accessible name', (_name, text, hexes) => {
      const { root, bdi } = render(text, null, 'email');

      const spans = tokens(root);
      expect(spans.map((span) => span.textContent)).toEqual(hexes.map((hex) => `⟨U+${hex}⟩`));
      expect(spans.map((span) => span.getAttribute('aria-label'))).toEqual(
        hexes.map((hex) => `hidden character U+${hex}`),
      );
      expect(spans.every((span) => span.getAttribute('role') === 'img')).toBe(true);
      expect(spans.every((span) => bdi.contains(span))).toBe(true);
      // The hidden code points themselves never reach the DOM, so an override cannot act.
      expect(hasHiddenCharacters(root.textContent ?? '')).toBe(false);
      // Lossless: every token maps back to its code point and gives the input.
      expect(decoded(bdi)).toBe(text);
    });

    it('shows the badge outside the clamped text, described by the address explanation', () => {
      const { root, bdi } = render(`a\u202Eb${DOMAIN}`, 1, 'email');

      const badge = root.querySelector('[data-testid="user-text-hidden-badge"]') as HTMLElement;
      expect(badge.textContent).toContain('Contains hidden characters');
      expect(bdi.contains(badge)).toBe(false);
      const described = root.querySelector(`#${badge.getAttribute('aria-describedby')}`);
      expect(described?.textContent).toContain(
        'This address contains characters that are invisible or change text direction.',
      );
    });

    it('puts the tokenised text, not the raw value, in the title of a truncated address', () => {
      const { bdi } = render(`a\u202Eb${DOMAIN}`, 1, 'email');
      expect(bdi.getAttribute('title')).toBe(`a⟨U+202E⟩b${DOMAIN}`);
    });

    it('keeps markup and an override as text: no element other than the segment spans', () => {
      const hostile = `<img src=x onerror=alert(1)>\u202E${DOMAIN}`;
      const { root, bdi } = render(hostile, null, 'email');

      expect(root.querySelector('img')).toBeNull();
      // Only the segment spans, each holding text alone.
      const children = Array.from(bdi.children);
      expect(children.every((c) => c.tagName === 'SPAN' && c.children.length === 0)).toBe(true);
      expect(tokens(root)).toHaveLength(1);
      expect(decoded(bdi)).toBe(hostile);
    });

    it('text mode adds the badge only, never tokens', () => {
      const text = `a\u202Eb${DOMAIN}`;
      const { root, bdi } = render(text, null, 'text');
      expect(tokens(root)).toHaveLength(0);
      expect(bdi.textContent).toBe(text);
      expect(root.querySelector('[data-testid="user-text-hidden-badge"]')).not.toBeNull();
    });

    it('has no axe violations with tokens', async () => {
      const { root } = render(`a\u202Eb\u200D${DOMAIN}`, 1, 'email');
      await expectNoAxeViolations(root);
    });
  });
});
