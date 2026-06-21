import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatIconModule } from '@angular/material/icon';
import { AuthService } from '../auth.service';
import { AppError } from '../../../shared/types/app-error';
import { ViewState, failure, idle, loading, success } from '../../../shared/types/view-state';
import { PasswordStrengthMeterComponent } from './password-strength-meter/password-strength-meter.component';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { NxInput, NxButton } from '../../../shared/ui';

@Component({
  selector: 'app-registration-form',
  standalone: true,
  imports: [
    ReactiveFormsModule,
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

  protected readonly state = signal<ViewState<void>>(idle);

  private readonly formStatus = toSignal(this.form.statusChanges, {
    initialValue: this.form.status,
  });

  protected readonly passwordValue = toSignal(this.form.controls.password.valueChanges, {
    initialValue: '',
  });

  protected readonly emailError = computed(() => {
    this.formStatus();
    const ctrl = this.form.controls.email;
    if (!ctrl.touched || ctrl.valid) return '';
    if (ctrl.errors?.['required']) return 'Email is required.';
    if (ctrl.errors?.['server']) return ctrl.errors['server'] as string;
    return 'Enter a valid email address.';
  });

  protected readonly passwordError = computed(() => {
    this.formStatus();
    const ctrl = this.form.controls.password;
    if (!ctrl.touched || ctrl.valid) return '';
    if (ctrl.errors?.['required']) return 'Password is required.';
    if (ctrl.errors?.['server']) return ctrl.errors['server'] as string;
    return 'Password does not meet requirements.';
  });

  protected readonly consentError = computed(() => {
    this.formStatus();
    const ctrl = this.form.controls.consentAccepted;
    if (!ctrl.touched || ctrl.valid) return '';
    return 'You must accept the terms to continue.';
  });

  protected hasFieldErrors(): boolean {
    const state = this.state();
    if (state.kind !== 'error') return false;
    return (
      !!this.form.controls.email.errors?.['server'] ||
      !!this.form.controls.password.errors?.['server']
    );
  }

  protected errorState(): AppError {
    const state = this.state();
    if (state.kind === 'error') return state.error;
    return { code: '', message: '' };
  }

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
