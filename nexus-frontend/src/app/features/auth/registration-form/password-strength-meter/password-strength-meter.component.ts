import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

/**
 * Strength labels corresponding to score tiers.
 * - Score 0: Very Weak
 * - Score 1: Weak
 * - Score 2: Fair
 * - Score 3: Strong
 * - Score 4: Very Strong
 */
const LABELS = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'] as const;

/**
 * Color values for strength bars, indexed by score.
 * Scores 0–1: error (red), Score 2: warning (yellow), Scores 3–4: success (green).
 */
const SCORE_COLORS = [
  'var(--nx-color-error)',
  'var(--nx-color-error)',
  'var(--nx-color-warning)',
  'var(--nx-color-success)',
  'var(--nx-color-success)',
] as const;

/** Bar indices used for visual strength representation. */
const BARS = [0, 1, 2, 3] as const;

/**
 * Computes a password strength score (0–4) based on four criteria.
 * Scoring:
 *   - Length ≥ 12 characters: +1 point
 *   - Contains uppercase letter [A-Z]: +1 point
 *   - Contains digit [0-9]: +1 point
 *   - Contains special character (not alphanumeric): +1 point
 *
 * @param pw The password string to evaluate
 * @returns A score from 0 to 4 where 4 is the strongest
 */
function computeScore(pw: string): number {
  if (!pw) return 0;
  let score = 0;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return score;
}

/**
 * Displays a 4-bar strength meter with color-coded feedback.
 *
 * @componentName Password Strength Meter
 * @selector app-password-strength-meter
 * @standalone true
 *
 * @signals
 *   - `password` (input): The password string to evaluate (default: '')
 *   - `score` (computed): Strength score 0–4 derived from password criteria
 *   - `label` (computed): Human-readable strength label ('Very Weak'–'Very Strong')
 *   - `barColor` (computed): CSS color value matching the current score tier
 *
 * @a11y
 *   - role="status" on strength-meter container for dynamic content updates
 *   - aria-label="${label()}" includes the strength label for screen readers
 *   - aria-hidden="true" on visual bar elements (not needed by AT)
 *   - Label only renders when password is non-empty to reduce clutter
 */
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
      @if (password()) {
        <span class="strength-meter__label" [style.color]="barColor()">
          {{ label() }}
        </span>
      }
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
  /**
   * Input: the password string to evaluate.
   * When empty, the strength label is hidden from view.
   */
  readonly password = input('');

  /** Array of bar indices used to render 4 visual bars. */
  protected readonly bars = BARS;

  /**
   * Computed signal: derives strength score (0–4) from the current password.
   * Reactively updates whenever password input changes.
   */
  protected readonly score = computed(() => computeScore(this.password()));

  /**
   * Computed signal: derives the strength label from the current score.
   * Maps score [0–4] to labels: 'Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'.
   */
  protected readonly label = computed(() => LABELS[this.score()]);

  /**
   * Computed signal: derives the bar color (error/warning/success) from the current score.
   * Used to color-code the visual bars and label text.
   */
  protected readonly barColor = computed(() => SCORE_COLORS[this.score()]);
}
