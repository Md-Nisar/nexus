import { BreakpointObserver } from '@angular/cdk/layout';
import { Component, computed, inject, input } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { map } from 'rxjs';

export type SkeletonVariant = 'text' | 'rect' | 'circle';

/**
 * Loading placeholder. Decorative: hidden from assistive technology, so the consumer sets
 * `aria-busy` on the region being loaded. The shimmer is off under `prefers-reduced-motion`.
 */
@Component({
  selector: 'nx-skeleton',
  host: {
    'aria-hidden': 'true',
    class: 'nx-skeleton',
    '[class.nx-skeleton--static]': 'reducedMotion()',
  },
  template: `
    @for (bar of bars(); track $index) {
      <span
        [class]="'nx-skeleton__bar nx-skeleton__bar--' + variant()"
        [style.width]="bar.width"
        [style.height]="variant() === 'circle' ? bar.width : null"
      ></span>
    }
  `,
  styleUrl: './skeleton.scss',
})
export class NxSkeleton {
  readonly variant = input<SkeletonVariant>('text');
  /** Number of text lines; ignored for `rect` and `circle`. */
  readonly lines = input(1);
  /** Any CSS width, for example `120px` or `50%`. Circles use it as the diameter. */
  readonly width = input('');

  protected readonly reducedMotion = toSignal(
    inject(BreakpointObserver)
      .observe('(prefers-reduced-motion: reduce)')
      .pipe(map((state) => state.matches)),
    { requireSync: true },
  );

  protected readonly bars = computed(() => {
    const width = this.width() || null;
    if (this.variant() !== 'text') return [{ width }];
    const count = Math.max(1, Math.floor(this.lines()));
    return Array.from({ length: count }, (_, i) => ({
      width: count > 1 && i === count - 1 ? '60%' : width,
    }));
  });
}
