import { ComponentFixture, TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { expectNoAxeViolations } from '../../testing/axe';
import { NxSkeleton } from './skeleton';

function stubReducedMotion(reduced: boolean): void {
  vi.stubGlobal(
    'matchMedia',
    (query: string) =>
      ({
        matches: reduced && query.includes('prefers-reduced-motion'),
        media: query,
        addListener: () => undefined,
        removeListener: () => undefined,
      }) as unknown as MediaQueryList,
  );
}

describe('NxSkeleton', () => {
  let fixture: ComponentFixture<NxSkeleton>;
  const el = () => fixture.nativeElement as HTMLElement;
  const bars = () => Array.from(el().querySelectorAll<HTMLElement>('.nx-skeleton__bar'));

  async function setup(reduced = false) {
    stubReducedMotion(reduced);
    fixture = TestBed.createComponent(NxSkeleton);
    await fixture.whenStable();
  }

  afterEach(() => vi.unstubAllGlobals());

  it('is hidden from assistive technology', async () => {
    await setup();
    expect(el().getAttribute('aria-hidden')).toBe('true');
  });

  it('renders a single text bar by default', async () => {
    await setup();
    expect(bars().length).toBe(1);
    expect(bars()[0].classList).toContain('nx-skeleton__bar--text');
  });

  it('renders one bar per line for text, the last one shorter', async () => {
    await setup();
    fixture.componentRef.setInput('lines', 3);
    await fixture.whenStable();
    expect(bars().length).toBe(3);
    expect(bars()[2].style.width).toBe('60%');
    expect(bars()[0].style.width).toBe('');
  });

  it.each(['rect', 'circle'] as const)(
    'renders one %s bar regardless of lines',
    async (variant) => {
      await setup();
      fixture.componentRef.setInput('variant', variant);
      fixture.componentRef.setInput('lines', 4);
      await fixture.whenStable();
      expect(bars().length).toBe(1);
      expect(bars()[0].classList).toContain(`nx-skeleton__bar--${variant}`);
    },
  );

  it('applies width to the bars', async () => {
    await setup();
    fixture.componentRef.setInput('width', '120px');
    await fixture.whenStable();
    expect(bars()[0].style.width).toBe('120px');
  });

  it('shimmers by default', async () => {
    await setup();
    expect(el().classList).not.toContain('nx-skeleton--static');
  });

  it('does not shimmer under prefers-reduced-motion', async () => {
    await setup(true);
    expect(el().classList).toContain('nx-skeleton--static');
  });

  it('has no axe violations', async () => {
    await setup();
    await expect(expectNoAxeViolations(el())).resolves.toBeUndefined();
  });
});
