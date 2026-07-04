import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  OnInit,
  signal,
} from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AuthService } from '../auth.service';
import { AppError } from '../../../shared/types/app-error';
import { NxInput, NxButton } from '../../../shared/ui';
import { PasswordStrengthMeterComponent } from '../registration-form/password-strength-meter/password-strength-meter.component';

/**
 * Reset Password flow component.
 *
 * Completes password reset initiated by the forgot-password flow.
 * Extracts a reset token from the URL, validates the new password, and submits the reset request.
 *
 * Security:
 * - Token is immediately stripped from URL to prevent Referer leakage and browser history exposure.
 * - Never displays the token in the UI.
 * - Validates password meets policy (length, complexity).
 * - Detects and rejects attempts to reuse the current password.
 * - Detects expired/already-used tokens and offers a retry path.
 *
 * @componentName Reset Password
 * @selector nx-reset-password
 * @standalone true
 *
 * @signals
 *   - `loading` (signal): Set to true while API request is in-flight
 *   - `errorMessage` (signal): Set to error message on API failure (null on success/initial)
 *   - `showPassword` (signal): Toggles password input type between password and text
 *   - `showForgotLink` (signal): Shows "request new link" when token is expired
 *
 * @form
 *   - `resetForm` (FormGroup): New password input form
 *     - `newPassword` (FormControl): New password, validators: required, min 12 chars, max 256 chars
 *
 * @computed
 *   - `passwordError` (computed): Human-readable error message for password field validation
 *
 * @lifecycle
 *   - ngOnInit: Reads token from query param, strips it from URL (history/Referer protection)
 *
 * @a11y
 *   - role="alert" on error banner for screen reader notification
 *   - Password input includes aria-describedby="reset-strength-meter" for strength meter context
 *   - Password visibility toggle icon button with aria-label
 *   - Strength meter announces password strength via aria-label on role="status"
 *   - Error messages clearly state requirements and validation failures
 */
@Component({
  selector: 'nx-reset-password',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, RouterLink, NxInput, NxButton, PasswordStrengthMeterComponent],
  template: `
    <div class="reset-password-container">
      <div class="reset-password-card">
        <h2 class="reset-password-card__heading">Set a new password</h2>

        @if (errorMessage()) {
          <div class="reset-password-card__error-banner" role="alert" data-testid="reset-error">
            {{ errorMessage() }}
            @if (showForgotLink()) {
              <br />
              <a routerLink="/auth/forgot-password" data-testid="request-new-link"
                >Request a new link</a
              >
            }
          </div>
        }

        <form [formGroup]="resetForm" (ngSubmit)="submit()" novalidate>
          <nx-input
            inputId="reset-new-password"
            formControlName="newPassword"
            [type]="showPassword() ? 'text' : 'password'"
            label="New password"
            autocomplete="new-password"
            [suffixIcon]="showPassword() ? 'visibility_off' : 'visibility'"
            [error]="passwordError()"
            (suffixIconClick)="showPassword.update((v) => !v)"
            aria-describedby="reset-strength-meter"
          />

          <app-password-strength-meter
            id="reset-strength-meter"
            [password]="resetForm.controls.newPassword.value"
          />

          <nx-button
            type="submit"
            variant="primary"
            size="lg"
            [fullWidth]="true"
            [loading]="loading()"
            [disabled]="resetForm.invalid || loading()"
            data-testid="reset-submit"
          >
            Reset password
          </nx-button>
        </form>

        <p class="reset-password-card__back-link">
          <a routerLink="/auth/login">Back to sign in</a>
        </p>
      </div>
    </div>
  `,
  styles: `
    :host {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: calc(100vh - 52px);
      padding: var(--nx-space-6);
      background-color: var(--nx-color-canvas);
    }

    .reset-password-card {
      display: flex;
      flex-direction: column;
      gap: var(--nx-space-5);
      width: 100%;
      max-width: 400px;
      padding: var(--nx-space-8);
      background-color: var(--nx-color-surface);
      border: 1px solid var(--nx-color-outline);
      border-radius: var(--nx-radius-lg);

      &__heading {
        margin: 0;
        font-size: var(--nx-text-2xl);
        font-weight: var(--nx-weight-semibold);
        color: var(--nx-color-on-surface);
        letter-spacing: var(--nx-tracking-card-title);
      }

      &__error-banner {
        padding: var(--nx-space-3) var(--nx-space-4);
        border-radius: var(--nx-radius-sm);
        background: var(--nx-color-error-surface);
        color: var(--nx-color-error);
        font-size: var(--nx-text-base);

        a {
          color: var(--nx-color-error);
          font-weight: var(--nx-weight-medium);
        }
      }

      &__back-link {
        margin: 0;
        font-size: var(--nx-text-sm);
        color: var(--nx-color-on-surface-faint);
        text-align: center;

        a {
          color: var(--nx-color-primary);
          text-decoration: none;

          &:hover {
            color: var(--nx-color-primary-hover);
            text-decoration: underline;
          }
        }
      }
    }
  `,
})
export class ResetPasswordComponent implements OnInit {
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  /**
   * Loading state: true while API request is in-flight.
   * Used to disable submit button and show loading indicator.
   */
  readonly loading = signal(false);

  /**
   * Error message state: null when no error, or error message string on failure.
   * Set by API error handler based on error code.
   * Displayed in alert banner for accessibility.
   */
  readonly errorMessage = signal<string | null>(null);

  /**
   * Password visibility toggle: false = masked, true = visible.
   * Allows user to toggle password input type between "password" and "text".
   * Improves UX on mobile or when typing a complex password.
   */
  readonly showPassword = signal(false);

  /**
   * Show "request new link" link: set to true only when token is expired/invalid (AUTH_RST_002).
   * Provides UX recovery path when the email link is stale.
   */
  readonly showForgotLink = signal(false);

  /**
   * The reset token extracted from URL query param.
   * Private signal because token should never be exposed in template or console.
   * Extracted in ngOnInit and immediately stripped from URL.
   */
  private readonly tokenFromUrl = signal('');

  /**
   * Reactive form group for new password input.
   * Validators:
   *   - required: Password cannot be empty
   *   - minLength(12): Password must be at least 12 characters (policy requirement)
   *   - maxLength(256): Maximum reasonable password length
   */
  readonly resetForm = new FormGroup({
    newPassword: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.minLength(12), Validators.maxLength(256)],
    }),
  });

  /**
   * Computed signal: derives error message from newPassword control validation state.
   * Only shows error if field is touched (user has interacted with it).
   * Maps validator errors to human-readable messages.
   * Returns empty string if valid or untouched.
   */
  readonly passwordError = computed(() => {
    const control = this.resetForm.controls.newPassword;
    if (!control.touched || control.valid) return '';
    if (control.hasError('required')) return 'Password is required.';
    if (control.hasError('minlength')) return 'Password must be at least 12 characters.';
    if (control.hasError('maxlength')) return 'Password must not exceed 256 characters.';
    return '';
  });

  /**
   * Component initialization: reads and clears the reset token from URL.
   *
   * Flow:
   * 1. Read token from query param ?token=...
   * 2. Store token in private signal (never exposed to template)
   * 3. Immediately navigate to same route without token (replaceUrl=true)
   *    - Prevents Referer header leakage if user navigates elsewhere
   *    - Removes token from browser history to prevent account takeover via shared device
   *
   * Security note: This mitigation works at client level; backend must also
   * validate token expiry and one-time use to prevent token reuse attacks.
   */
  ngOnInit(): void {
    this.tokenFromUrl.set(this.route.snapshot.queryParamMap.get('token') ?? '');
    // Strip token from URL to prevent Referer leakage and browser history exposure (LOW-1).
    this.router.navigate([], { relativeTo: this.route, queryParams: {}, replaceUrl: true });
  }

  /**
   * Submits the password reset request.
   *
   * Flow:
   * 1. Mark password field as touched to trigger error display
   * 2. Validate form and loading state
   * 3. Set loading=true and clear previous errors
   * 4. Call AuthService.resetPassword(token, newPassword)
   * 5. On success: navigate to login with reset=true query param (confirmation message)
   * 6. On error: decode error code and set user-friendly message, show retry link if applicable
   *
   * Error codes handled:
   *   - AUTH_RST_002: Token expired or already used → show "request new link" option
   *   - AUTH_PWD_001: Password policy violation (length)
   *   - AUTH_PWD_002: Password too common (dictionary check)
   *   - AUTH_RST_003: New password same as current (prevent reuse)
   *   - Default: Generic error message (never leak server details)
   */
  submit(): void {
    this.resetForm.controls.newPassword.markAsTouched();
    if (this.resetForm.invalid || this.loading()) return;

    this.loading.set(true);
    this.errorMessage.set(null);
    this.showForgotLink.set(false);
    const { newPassword } = this.resetForm.getRawValue();

    this.authService.resetPassword(this.tokenFromUrl(), newPassword).subscribe({
      next: () => {
        this.loading.set(false);
        this.router.navigate(['/auth/login'], { queryParams: { reset: 'true' } });
      },
      error: (err: AppError) => {
        this.loading.set(false);
        switch (err.code) {
          case 'AUTH_RST_002':
            this.errorMessage.set('This reset link has expired or already been used.');
            this.showForgotLink.set(true);
            break;
          case 'AUTH_PWD_001':
            this.errorMessage.set('Password must be at least 12 characters.');
            break;
          case 'AUTH_PWD_002':
            this.errorMessage.set('Password is too common. Choose a different one.');
            break;
          case 'AUTH_RST_003':
            this.errorMessage.set('New password must be different from your current password.');
            break;
          default:
            this.errorMessage.set('An unexpected error occurred. Please try again.');
        }
      },
    });
  }
}
