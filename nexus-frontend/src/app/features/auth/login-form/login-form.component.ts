import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { form, required, email, maxLength, FormField } from '@angular/forms/signals';
import { Router, RouterLink } from '@angular/router';
import { NxButton, NxInput } from '../../../shared/ui';
import { AuthService } from '../auth.service';
import { AppError } from '../../../shared/types/app-error';

@Component({
  selector: 'nx-login-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormField, RouterLink, NxInput, NxButton],
  template: `
    <div class="login-form-container">
      <form class="login-form" (ngSubmit)="submit()" novalidate>
        <h2 class="login-form__heading">Sign in to Nexus</h2>

        @if (errorMessage()) {
          <div class="login-form__error-banner" role="alert" data-testid="login-error">
            {{ errorMessage() }}
          </div>
        }

        <nx-input
          inputId="login-email"
          [formField]="loginForm.email"
          label="Email address"
          type="email"
          autocomplete="email"
          [error]="emailError()"
        />

        <nx-input
          inputId="login-password"
          [formField]="loginForm.password"
          [type]="showPassword() ? 'text' : 'password'"
          label="Password"
          autocomplete="current-password"
          [suffixIcon]="showPassword() ? 'visibility_off' : 'visibility'"
          [error]="passwordError()"
          (suffixIconClick)="showPassword.update((v) => !v)"
        />

        <nx-button
          type="submit"
          variant="primary"
          size="lg"
          [fullWidth]="true"
          [loading]="loading()"
          [disabled]="loginForm().invalid() || loading()"
          data-testid="login-submit"
        >
          Sign in
        </nx-button>

        <p class="login-form__register-link">
          No account? <a routerLink="/auth/register">Create one</a>
        </p>
      </form>
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

    .login-form {
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
        margin: 0 0 var(--nx-space-1);
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
      }

      &__register-link {
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
export class LoginFormComponent {
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);

  readonly loading = signal(false);
  readonly errorMessage = signal<string | null>(null);
  readonly showPassword = signal(false);

  readonly loginModel = signal({ email: '', password: '' });

  readonly loginForm = form(this.loginModel, (schema) => {
    required(schema.email, { message: 'Email is required.' });
    email(schema.email, { message: 'Enter a valid email address.' });
    maxLength(schema.email, 254, { message: 'Email is too long.' });

    required(schema.password, { message: 'Password is required.' });
    maxLength(schema.password, 256, { message: 'Password is too long.' });
  });

  readonly emailError = computed(() => {
    const emailField = this.loginForm.email();
    if (!emailField.touched() || emailField.valid()) return '';
    const errors = emailField.errors();
    const reqErr = errors.find((e) => e.kind === 'required');
    if (reqErr) return reqErr.message ?? 'Email is required.';
    const emailErr = errors.find((e) => e.kind === 'email');
    if (emailErr) return emailErr.message ?? 'Enter a valid email address.';
    return '';
  });

  readonly passwordError = computed(() => {
    const passwordField = this.loginForm.password();
    if (!passwordField.touched() || passwordField.valid()) return '';
    const errors = passwordField.errors();
    const reqErr = errors.find((e) => e.kind === 'required');
    if (reqErr) return reqErr.message ?? 'Password is required.';
    return '';
  });

  submit(): void {
    this.loginForm.email().markAsTouched();
    this.loginForm.password().markAsTouched();

    if (this.loginForm().invalid() || this.loading()) return;
    this.loading.set(true);
    this.errorMessage.set(null);
    const { email, password } = this.loginModel();
    this.authService.login(email, password).subscribe({
      next: () => {
        this.loading.set(false);
        this.router.navigate(['/dashboard']);
      },
      error: (err: AppError) => {
        this.loading.set(false);
        switch (err.code) {
          case 'AUTH_001':
            this.errorMessage.set('Invalid email or password.');
            break;
          case 'AUTH_002':
            this.errorMessage.set('Please verify your email before logging in.');
            break;
          case 'RATE_001':
            this.errorMessage.set('Too many attempts. Please try again later.');
            break;
          default:
            this.errorMessage.set('An unexpected error occurred. Please try again.');
        }
      },
    });
  }
}
