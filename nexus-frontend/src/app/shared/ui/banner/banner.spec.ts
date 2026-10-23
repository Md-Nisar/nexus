import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../testing/axe';
import { BannerLive, BannerVariant, NxBanner } from './banner';

@Component({
  imports: [NxBanner],
  template: `
    <nx-banner
      [variant]="variant()"
      [title]="title()"
      [live]="live()"
      [dismissible]="dismissible()"
      (dismissed)="dismissals = dismissals + 1"
    >
      <p data-testid="banner-body">You can still read everything.</p>
      <button type="button" slot="actions" data-testid="banner-action">Retry</button>
    </nx-banner>
  `,
})
class Host {
  readonly variant = signal<BannerVariant>('info');
  readonly title = signal('Changes are off');
  readonly live = signal<BannerLive | undefined>(undefined);
  readonly dismissible = signal(false);
  dismissals = 0;
}

describe('NxBanner', () => {
  let fixture: ComponentFixture<Host>;

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function root(): HTMLElement {
    return el().querySelector('[data-testid="nx-banner"]') as HTMLElement;
  }

  function render(changes: Partial<Record<keyof Host, unknown>> = {}): void {
    fixture = TestBed.createComponent(Host);
    const host = fixture.componentInstance;
    if (changes.variant !== undefined) host.variant.set(changes.variant as BannerVariant);
    if (changes.title !== undefined) host.title.set(changes.title as string);
    if ('live' in changes) host.live.set(changes.live as BannerLive | undefined);
    if (changes.dismissible !== undefined) host.dismissible.set(changes.dismissible as boolean);
    fixture.detectChanges();
  }

  it('renders the title as text, the projected body and the actions slot', () => {
    render();

    expect(el().querySelector('[data-testid="nx-banner-title"]')?.textContent?.trim()).toBe(
      'Changes are off',
    );
    expect(root().querySelector('[data-testid="banner-body"]')).not.toBeNull();
    const actions = root().querySelector('.nx-banner__actions');
    expect(actions?.querySelector('[data-testid="banner-action"]')).not.toBeNull();
  });

  it.each<[BannerVariant, string]>([
    ['info', 'info'],
    ['success', 'check_circle'],
    ['warning', 'warning'],
    ['error', 'error'],
  ])('%s variant: class and a decorative %s icon next to the text', (variant, icon) => {
    render({ variant });

    expect(root().classList).toContain(`nx-banner--${variant}`);
    const glyph = root().querySelector('.nx-banner__icon mat-icon');
    expect(glyph?.textContent?.trim()).toBe(icon);
    expect(glyph?.getAttribute('aria-hidden')).toBe('true');
  });

  it.each<[BannerVariant, string]>([
    ['info', 'status'],
    ['success', 'status'],
    ['warning', 'status'],
    ['error', 'alert'],
  ])('defaults the live region by variant: %s is role=%s', (variant, role) => {
    render({ variant });

    expect(root().getAttribute('role')).toBe(role);
  });

  it.each<[BannerLive, string | null]>([
    ['polite', 'status'],
    ['assertive', 'alert'],
    ['off', null],
  ])('live=%s overrides the default: role %s', (live, role) => {
    render({ variant: 'warning', live });

    expect(root().getAttribute('role')).toBe(role);
  });

  it('shows no dismiss control unless dismissible', () => {
    render();

    expect(root().querySelector('[data-testid="nx-banner-dismiss"]')).toBeNull();
  });

  it('a dismissible banner emits dismissed from a named button and leaves removal to the host', () => {
    render({ dismissible: true, title: 'Saved' });

    const dismiss = root().querySelector(
      '[data-testid="nx-banner-dismiss"] button',
    ) as HTMLButtonElement;
    expect(dismiss.getAttribute('aria-label')).toBe('Dismiss: Saved');
    dismiss.click();
    fixture.detectChanges();

    expect(fixture.componentInstance.dismissals).toBe(1);
    expect(root()).not.toBeNull();
  });

  it('renders a title containing markup as text only', () => {
    render({ title: '<img src=x onerror=alert(1)>' });

    expect(root().querySelector('img')).toBeNull();
    expect(el().querySelector('[data-testid="nx-banner-title"]')?.textContent?.trim()).toBe(
      '<img src=x onerror=alert(1)>',
    );
  });

  it.each<BannerVariant>(['info', 'success', 'warning', 'error'])(
    'has no axe violations (%s, dismissible)',
    async (variant) => {
      render({ variant, dismissible: true });

      await expectNoAxeViolations(el());
    },
  );
});
