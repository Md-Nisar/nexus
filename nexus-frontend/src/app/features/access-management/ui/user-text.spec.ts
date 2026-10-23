import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../../shared/testing/axe';
import { UserText } from './user-text';

@Component({
  imports: [UserText],
  template: `<app-user-text [text]="text" [maxLines]="maxLines" />`,
})
class Host {
  text = '';
  maxLines: number | null = null;
}

function render(text: string, maxLines: number | null = null) {
  const fixture = TestBed.createComponent(Host);
  fixture.componentInstance.text = text;
  fixture.componentInstance.maxLines = maxLines;
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
});
