import { ChangeDetectionStrategy, Component, input, output } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';

// nx-button is a token-native button (not a MatButton wrapper): the full visual
// contract lives in button.scss against --nx-* tokens. MatIconModule is the only
// Material dependency, used for leading/trailing/loading glyphs.

export type ButtonVariant = 'primary' | 'secondary' | 'tertiary' | 'danger' | 'ghost' | 'inverse';
export type ButtonSize = 'sm' | 'md' | 'lg';

@Component({
  selector: 'nx-button',
  standalone: true,
  imports: [MatIconModule],
  host: {
    '[class.nx-btn-host--full-width]': 'fullWidth()',
  },
  template: `
    <button
      [class]="buttonClass()"
      [type]="type()"
      [disabled]="disabled()"
      [attr.aria-busy]="loading() ? true : null"
      [attr.aria-label]="ariaLabel() || null"
      (click)="clicked.emit()"
      data-testid="nx-button"
    >
      @if (loading()) {
        <mat-icon class="nx-btn__spinner" aria-hidden="true">sync</mat-icon>
      }
      @if (leadingIcon() && !loading()) {
        <mat-icon aria-hidden="true">{{ leadingIcon() }}</mat-icon>
      }
      <span class="nx-btn__label"><ng-content /></span>
      @if (trailingIcon()) {
        <mat-icon aria-hidden="true">{{ trailingIcon() }}</mat-icon>
      }
    </button>
  `,
  styleUrl: './button.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NxButton {
  readonly variant = input<ButtonVariant>('primary');
  readonly size = input<ButtonSize>('md');
  readonly type = input<'button' | 'submit' | 'reset'>('button');
  readonly disabled = input(false);
  readonly loading = input(false);
  readonly fullWidth = input(false);
  readonly leadingIcon = input<string>('');
  readonly trailingIcon = input<string>('');
  readonly ariaLabel = input<string>('');
  readonly clicked = output<void>();

  protected buttonClass(): string {
    return [
      'nx-btn',
      `nx-btn--${this.variant()}`,
      `nx-btn--${this.size()}`,
      this.loading() ? 'nx-btn--loading' : '',
    ]
      .filter(Boolean)
      .join(' ');
  }
}
