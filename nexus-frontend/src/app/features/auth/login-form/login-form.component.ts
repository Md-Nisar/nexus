import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { toSignal } from '@angular/core/rxjs-interop';
import { Router, RouterLink } from '@angular/router';
import { NxButton, NxCard, NxInput } from '../../../shared/ui';
import { AuthService } from '../auth.service';
import { AppError } from '../../../shared/types/app-error';

@Component({
  selector: 'nx-login-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, RouterLink, NxInput, NxButton, NxCard],
  template: `
    <div class="login-form-container">
      <nx-card title="Sign in to Nexus" elevation="raised">
        <form [formGroup]="form" (ngSubmit)="submit()" novalidate>
          @if (errorMessage()) {
            <div class="login-form__error" role="alert" data-testid="login-error">
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
            label="Password"
            type="password"
            autocomplete="current-password"
            [error]="passwordError()"
          />

          <nx-button
            type="submit"
            variant="primary"
            size="lg"
            [fullWidth]="true"
            [loading]="loading()"
            [disabled]="form.invalid || loading()"
            data-testid="login-submit"
          >
            Sign in
          </nx-button>
        </form>

        <p class="login-form__register-link">
          No account? <a routerLink="/auth/register">Create one</a>
        </p>
      </nx-card>
    </div>
  `,
})
export class LoginFormComponent {
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);

  readonly loading = signal(false);
  readonly errorMessage = signal<string | null>(null);

  readonly form = new FormGroup({
    email: new FormControl('', {
      validators: [Validators.required, Validators.email, Validators.maxLength(254)],
      nonNullable: true,
    }),
    password: new FormControl('', {
      validators: [Validators.required, Validators.maxLength(256)],
      nonNullable: true,
    }),
  });

  private readonly formStatus = toSignal(this.form.statusChanges, {
    initialValue: this.form.status,
  });

  readonly emailError = computed(() => {
    this.formStatus();
    const ctrl = this.form.controls.email;
    if (!ctrl.touched || ctrl.valid) return '';
    if (ctrl.errors?.['required']) return 'Email is required.';
    return 'Enter a valid email address.';
  });

  readonly passwordError = computed(() => {
    this.formStatus();
    const ctrl = this.form.controls.password;
    if (!ctrl.touched || ctrl.valid) return '';
    return 'Password is required.';
  });

  submit(): void {
    if (this.form.invalid || this.loading()) return;
    this.loading.set(true);
    this.errorMessage.set(null);
    const { email, password } = this.form.getRawValue();
    this.authService.login(email, password).subscribe({
      next: () => this.router.navigate(['/dashboard']),
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
