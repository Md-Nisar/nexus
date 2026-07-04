import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { toSignal } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { AuthService } from '../auth.service';
import { AppError } from '../../../shared/types/app-error';
import { ViewState, failure, idle, loading, success } from '../../../shared/types/view-state';
import { PasswordStrengthMeterComponent } from './password-strength-meter/password-strength-meter.component';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { NxInput, NxButton } from '../../../shared/ui';

/**
 * User registration form component.
 *
 * Collects email, password, and consent acceptance. Includes:
 * - Real-time password strength meter
 * - Client-side form validation
 * - Server-side field error handling (email exists, password policy, etc.)
 * - Successful registration success state
 *
 * On successful registration, displays a success message and prompts user
 * to check their email for verification link.
 */
@Component({
  selector: 'app-registration-form',
  standalone: true,
  imports: [
    ReactiveFormsModule,
    RouterLink,
    MatIconModule,
    MatCheckboxModule,
    PasswordStrengthMeterComponent,
    NxInput,
    NxButton,
  ],
  templateUrl: './registration-form.component.html',
  styleUrl: './registration-form.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class RegistrationFormComponent {
  private readonly authService = inject(AuthService);

  /**
   * Reactive form with email, password, and terms acceptance controls.
   * Email: required, valid RFC 5321 format
   * Password: required, policy enforcement on backend
   * Consent: must be explicitly accepted
   */
  readonly form = new FormGroup({
    email: new FormControl('', {
      validators: [Validators.required, Validators.email],
      nonNullable: true,
    }),
    password: new FormControl('', {
      validators: [Validators.required],
      nonNullable: true,
    }),
    consentAccepted: new FormControl(false, {
      validators: [Validators.requiredTrue],
      nonNullable: true,
    }),
  });

  /** Current submission state (idle, loading, success, or error). */
  protected readonly state = signal<ViewState<void>>(idle);

  /** Controls password visibility toggle. */
  protected readonly showPassword = signal(false);

  /** Synced form validation state to trigger error recomputation. */
  private readonly formStatus = toSignal(this.form.statusChanges, {
    initialValue: this.form.status,
  });

  /**
   * Password field value stream for real-time strength meter updates.
   * Initial value is empty string.
   */
  protected readonly passwordValue = toSignal(this.form.controls.password.valueChanges, {
    initialValue: '',
  });

  /**
   * Computes error message for email field.
   * Prioritizes server-side errors (e.g., email already exists) over client validation.
   * Returns empty string if valid or untouched.
   */
  protected readonly emailError = computed(() => {
    this.formStatus();
    const ctrl = this.form.controls.email;
    if (!ctrl.touched || ctrl.valid) return '';
    if (ctrl.errors?.['required']) return 'Email is required.';
    if (ctrl.errors?.['server']) return ctrl.errors['server'] as string;
    return 'Enter a valid email address.';
  });

  /**
   * Computes error message for password field.
   * Prioritizes server-side errors (e.g., password policy violations) over client validation.
   * Returns empty string if valid or untouched.
   */
  protected readonly passwordError = computed(() => {
    this.formStatus();
    const ctrl = this.form.controls.password;
    if (!ctrl.touched || ctrl.valid) return '';
    if (ctrl.errors?.['required']) return 'Password is required.';
    if (ctrl.errors?.['server']) return ctrl.errors['server'] as string;
    return 'Password does not meet requirements.';
  });

  /**
   * Computes error message for consent checkbox.
   * Returns empty string if checked or untouched.
   */
  protected readonly consentError = computed(() => {
    this.formStatus();
    const ctrl = this.form.controls.consentAccepted;
    if (!ctrl.touched || ctrl.valid) return '';
    return 'You must accept the terms to continue.';
  });

  /**
   * Checks if the current error state includes field-level server validation errors.
   *
   * @returns true if error state exists and contains field errors, false otherwise
   */
  protected hasFieldErrors(): boolean {
    const state = this.state();
    if (state.kind !== 'error') return false;
    return (
      !!this.form.controls.email.errors?.['server'] ||
      !!this.form.controls.password.errors?.['server']
    );
  }

  /**
   * Extracts the error object from current state.
   *
   * @returns The AppError if in error state, otherwise empty error object
   */
  protected errorState(): AppError {
    const state = this.state();
    if (state.kind === 'error') return state.error;
    return { code: '', message: '' };
  }

  /**
   * Submits the registration form.
   *
   * On success, updates state to success which prompts email verification message.
   * On error, applies server-side field errors to affected controls and displays
   * a generic error banner.
   *
   * No-op if form invalid or submission already in flight.
   */
  protected submit(): void {
    if (this.form.invalid || this.state().kind === 'loading') return;
    this.state.set(loading);
    const { email, password, consentAccepted } = this.form.getRawValue();
    this.authService.register(email, password, consentAccepted).subscribe({
      next: () => this.state.set(success(undefined)),
      error: (err: AppError) => {
        if (err.details) {
          for (const fe of err.details) {
            const ctrl = this.form.get(fe.field);
            if (ctrl) {
              ctrl.setErrors({ server: fe.message });
              ctrl.markAsTouched();
            }
          }
          this.form.updateValueAndValidity();
        }
        this.state.set(failure(err));
      },
    });
  }
}
