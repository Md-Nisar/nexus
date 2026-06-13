import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';

@Component({
  selector: 'nx-empty-state',
  standalone: true,
  imports: [MatIconModule],
  template: `
    <div class="nx-empty-state" role="status" data-testid="nx-empty-state">
      @if (icon()) {
        <mat-icon class="nx-empty-state__icon" aria-hidden="true">{{ icon() }}</mat-icon>
      }
      <p class="nx-empty-state__title">{{ title() }}</p>
      @if (description()) {
        <p class="nx-empty-state__description">{{ description() }}</p>
      }
      <div class="nx-empty-state__action">
        <ng-content />
      </div>
    </div>
  `,
  styleUrl: './empty-state.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NxEmptyState {
  readonly icon = input<string>('inbox');
  readonly title = input.required<string>();
  readonly description = input<string>('');
}
