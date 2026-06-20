import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

const LABELS = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'] as const;
const SCORE_COLORS = [
  'var(--nx-color-error)',
  'var(--nx-color-error)',
  'var(--nx-color-warning)',
  'var(--nx-color-success)',
  'var(--nx-color-success)',
] as const;
const BARS = [0, 1, 2, 3] as const;

function computeScore(pw: string): number {
  if (!pw) return 0;
  let score = 0;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return score;
}

@Component({
  selector: 'app-password-strength-meter',
  standalone: true,
  imports: [],
  template: `
    <div class="strength-meter" role="status" [attr.aria-label]="'Password strength: ' + label()">
      <div class="strength-meter__bars" aria-hidden="true">
        @for (bar of bars; track bar) {
          <div
            class="strength-meter__bar"
            [style.background]="score() > bar ? barColor() : null"
            [class.strength-meter__bar--filled]="score() > bar"
          ></div>
        }
      </div>
      <span class="strength-meter__label" [style.color]="password() ? barColor() : null">
        {{ label() }}
      </span>
    </div>
  `,
  styles: `
    .strength-meter {
      display: flex;
      flex-direction: column;
      gap: 6px;
      margin-top: 4px;
    }
    .strength-meter__bars {
      display: flex;
      gap: 4px;
    }
    .strength-meter__bar {
      flex: 1;
      height: 3px;
      border-radius: 2px;
      background: var(--nx-color-outline-variant);
      transition: background var(--nx-duration-base) var(--nx-easing-standard);
    }
    .strength-meter__label {
      font-size: var(--nx-text-xs);
      font-weight: var(--nx-weight-medium);
      color: var(--nx-color-on-surface-faint);
      transition: color var(--nx-duration-base) var(--nx-easing-standard);
    }
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PasswordStrengthMeterComponent {
  readonly password = input('');

  protected readonly bars = BARS;
  protected readonly score = computed(() => computeScore(this.password()));
  protected readonly label = computed(() => LABELS[this.score()]);
  protected readonly barColor = computed(() => SCORE_COLORS[this.score()]);
}
