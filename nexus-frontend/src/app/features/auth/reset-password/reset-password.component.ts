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

  readonly loading = signal(false);
  readonly errorMessage = signal<string | null>(null);
  readonly showPassword = signal(false);
  readonly showForgotLink = signal(false);
  private readonly tokenFromUrl = signal('');

  readonly resetForm = new FormGroup({
    newPassword: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.minLength(12), Validators.maxLength(256)],
    }),
  });

  readonly passwordError = computed(() => {
    const control = this.resetForm.controls.newPassword;
    if (!control.touched || control.valid) return '';
    if (control.hasError('required')) return 'Password is required.';
    if (control.hasError('minlength')) return 'Password must be at least 12 characters.';
    if (control.hasError('maxlength')) return 'Password must not exceed 256 characters.';
    return '';
  });

  ngOnInit(): void {
    this.tokenFromUrl.set(this.route.snapshot.queryParamMap.get('token') ?? '');
    // Strip token from URL to prevent Referer leakage and browser history exposure (LOW-1).
    this.router.navigate([], { relativeTo: this.route, queryParams: {}, replaceUrl: true });
  }

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
