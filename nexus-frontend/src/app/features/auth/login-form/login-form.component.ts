import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  OnInit,
  signal,
} from '@angular/core';
import { FormGroup, FormControl, Validators, ReactiveFormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { NxButton, NxInput } from '../../../shared/ui';
import { AuthService } from '../auth.service';
import { AppError } from '../../../shared/types/app-error';

@Component({
  selector: 'nx-login-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, RouterLink, NxInput, NxButton],
  template: `
    <div class="login-form-container">
      <form class="login-form" [formGroup]="loginForm" (ngSubmit)="submit()" novalidate>
        <h2 class="login-form__heading">Sign in to Nexus</h2>

        @if (passwordReset()) {
          <div class="login-form__success-banner" role="status" data-testid="login-reset-success">
            Password reset successfully. You can now sign in with your new password.
          </div>
        }

        @if (errorMessage()) {
          <div class="login-form__error-banner" role="alert" data-testid="login-error">
            {{ errorMessage() }}
          </div>
        }

        <nx-input
          inputId="login-email"
          formControlName="email"
          label="Email address"
          type="email"
          autocomplete="email"
          [error]="emailError()"
        />

        <nx-input
          inputId="login-password"
          formControlName="password"
          [type]="showPassword() ? 'text' : 'password'"
          label="Password"
          autocomplete="current-password"
          [suffixIcon]="showPassword() ? 'visibility_off' : 'visibility'"
          [error]="passwordError()"
          (suffixIconClick)="showPassword.update((v) => !v)"
        />

        <div class="login-form__forgot-row">
          <a routerLink="/auth/forgot-password" data-testid="forgot-password-link"
            >Forgot password?</a
          >
        </div>

        <nx-button
          type="submit"
          variant="primary"
          size="lg"
          [fullWidth]="true"
          [loading]="loading()"
          [disabled]="loginForm.invalid || loading()"
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

      &__success-banner {
        padding: var(--nx-space-3) var(--nx-space-4);
        border-radius: var(--nx-radius-sm);
        background: var(--nx-color-success-surface);
        color: var(--nx-color-success);
        font-size: var(--nx-text-base);
      }

      &__error-banner {
        padding: var(--nx-space-3) var(--nx-space-4);
        border-radius: var(--nx-radius-sm);
        background: var(--nx-color-error-surface);
        color: var(--nx-color-error);
        font-size: var(--nx-text-base);
      }

      &__forgot-row {
        display: flex;
        justify-content: flex-end;
        margin-top: calc(-1 * var(--nx-space-2));

        a {
          font-size: var(--nx-text-sm);
          color: var(--nx-color-primary);
          text-decoration: none;

          &:hover {
            color: var(--nx-color-primary-hover);
            text-decoration: underline;
          }
        }
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
export class LoginFormComponent implements OnInit {
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  readonly loading = signal(false);
  readonly errorMessage = signal<string | null>(null);
  readonly showPassword = signal(false);
  readonly passwordReset = signal(false);

  ngOnInit(): void {
    this.passwordReset.set(this.route.snapshot.queryParamMap.get('reset') === 'true');
  }

  readonly loginForm = new FormGroup({
    email: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.email, Validators.maxLength(254)],
    }),
    password: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.maxLength(256)],
    }),
  });

  readonly emailError = computed(() => {
    const control = this.loginForm.controls.email;
    if (!control.touched || control.valid) return '';
    if (control.hasError('required')) return 'Email is required.';
    if (control.hasError('email')) return 'Enter a valid email address.';
    return '';
  });

  readonly passwordError = computed(() => {
    const control = this.loginForm.controls.password;
    if (!control.touched || control.valid) return '';
    if (control.hasError('required')) return 'Password is required.';
    return '';
  });

  submit(): void {
    this.loginForm.controls.email.markAsTouched();
    this.loginForm.controls.password.markAsTouched();

    if (this.loginForm.invalid || this.loading()) return;
    this.loading.set(true);
    this.errorMessage.set(null);
    const { email, password } = this.loginForm.getRawValue();
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
          case 'AUTH_LCK_001':
            this.errorMessage.set('Too many attempts. Try again later or reset your password.');
            break;
          default:
            this.errorMessage.set('An unexpected error occurred. Please try again.');
        }
      },
    });
  }
}
