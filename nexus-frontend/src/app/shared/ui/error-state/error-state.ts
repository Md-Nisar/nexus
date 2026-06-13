import { ChangeDetectionStrategy, Component, input, output } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';

@Component({
  selector: 'nx-error-state',
  standalone: true,
  imports: [MatIconModule, MatButtonModule],
  template: `
    <div class="nx-error-state" role="alert" data-testid="nx-error-state">
      <mat-icon class="nx-error-state__icon" aria-hidden="true">error_outline</mat-icon>
      <p class="nx-error-state__title">{{ title() }}</p>
      @if (message()) {
        <p class="nx-error-state__message">{{ message() }}</p>
      }
      @if (showRetry()) {
        <button
          mat-flat-button
          class="nx-error-state__retry"
          (click)="retry.emit()"
          data-testid="nx-error-state-retry"
        >
          Try again
        </button>
      }
      <ng-content />
    </div>
  `,
  styleUrl: './error-state.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NxErrorState {
  readonly title = input('Something went wrong');
  readonly message = input<string>('');
  readonly showRetry = input(true);
  readonly retry = output<void>();
}
