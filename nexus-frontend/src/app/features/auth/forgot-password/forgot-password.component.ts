import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { AuthService } from '../auth.service';
import { NxInput, NxButton } from '../../../shared/ui';

@Component({
  selector: 'nx-forgot-password',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, RouterLink, NxInput, NxButton],
  template: `
    <div class="forgot-password-container">
      <div class="forgot-password-card">
        <h2 class="forgot-password-card__heading">Reset your password</h2>

        @if (!submitted()) {
          <p class="forgot-password-card__description">
            Enter your email address and we'll send you a link to reset your password.
          </p>

          @if (errorMessage()) {
            <div class="forgot-password-card__error-banner" role="alert" data-testid="forgot-error">
              {{ errorMessage() }}
            </div>
          }

          <form [formGroup]="forgotForm" (ngSubmit)="submit()" novalidate>
            <nx-input
              inputId="forgot-email"
              formControlName="email"
              label="Email address"
              type="email"
              autocomplete="email"
              [error]="emailError()"
            />

            <nx-button
              type="submit"
              variant="primary"
              size="lg"
              [fullWidth]="true"
              [loading]="loading()"
              [disabled]="forgotForm.invalid || loading()"
              data-testid="forgot-submit"
            >
              Send reset link
            </nx-button>
          </form>
        } @else {
          <div class="forgot-password-card__confirmation" data-testid="forgot-confirmation">
            <p>
              If an account with that email exists, a reset link has been sent. Check your inbox and
              follow the instructions.
            </p>
          </div>
        }

        <p class="forgot-password-card__back-link">
          <a routerLink="/auth/login" data-testid="back-to-login">Back to sign in</a>
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

    .forgot-password-card {
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

      &__description {
        margin: 0;
        font-size: var(--nx-text-sm);
        color: var(--nx-color-on-surface-faint);
      }

      &__error-banner {
        padding: var(--nx-space-3) var(--nx-space-4);
        border-radius: var(--nx-radius-sm);
        background: var(--nx-color-error-surface);
        color: var(--nx-color-error);
        font-size: var(--nx-text-base);
      }

      &__confirmation {
        p {
          margin: 0;
          font-size: var(--nx-text-base);
          color: var(--nx-color-on-surface);
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
export class ForgotPasswordComponent {
  private readonly authService = inject(AuthService);

  readonly loading = signal(false);
  readonly submitted = signal(false);
  readonly errorMessage = signal<string | null>(null);

  readonly forgotForm = new FormGroup({
    email: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.email, Validators.maxLength(254)],
    }),
  });

  readonly emailError = computed(() => {
    const control = this.forgotForm.controls.email;
    if (!control.touched || control.valid) return '';
    if (control.hasError('required')) return 'Email is required.';
    if (control.hasError('email')) return 'Enter a valid email address.';
    if (control.hasError('maxlength')) return 'Email address must not exceed 254 characters.';
    return '';
  });

  submit(): void {
    this.forgotForm.controls.email.markAsTouched();
    if (this.forgotForm.invalid || this.loading()) return;

    this.loading.set(true);
    this.errorMessage.set(null);
    const { email } = this.forgotForm.getRawValue();

    this.authService.forgotPassword(email).subscribe({
      next: () => {
        this.loading.set(false);
        this.submitted.set(true);
      },
      error: () => {
        this.loading.set(false);
        this.errorMessage.set('An unexpected error occurred. Please try again.');
      },
    });
  }
}
