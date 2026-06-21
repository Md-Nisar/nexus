import { ChangeDetectionStrategy, Component, input } from '@angular/core';

export type BadgeVariant = 'success' | 'error' | 'warning' | 'neutral' | 'primary';

@Component({
  selector: 'nx-badge',
  standalone: true,
  host: {
    '[class]': '"nx-badge nx-badge--" + variant()',
    role: 'status',
    'aria-live': 'polite',
  },
  template: `<ng-content />`,
  styleUrl: './badge.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NxBadge {
  readonly variant = input<BadgeVariant>('neutral');
}
