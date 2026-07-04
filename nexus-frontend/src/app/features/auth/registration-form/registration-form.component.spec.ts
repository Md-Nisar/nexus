import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { provideRouter } from '@angular/router';
import { Subject, of, throwError } from 'rxjs';
import { describe, it, expect, vi } from 'vitest';
import { RegistrationFormComponent } from './registration-form.component';
import { AuthService } from '../auth.service';
import { AppError } from '../../../shared/types/app-error';

/**
 * Creates a mock AuthService with the specified register implementation.
 *
 * @param register Mock implementation of AuthService.register()
 * @returns Mock AuthService object
 */
function makeAuth(register: ReturnType<typeof vi.fn> = vi.fn(() => of(undefined as void))) {
  return { register };
}

/**
 * Sets up a test fixture with mocked AuthService.
 *
 * @param register Optional mock implementation of AuthService.register()
 * @returns Test fixture, component instance, and mock service
 */
function setup(register?: ReturnType<typeof vi.fn>) {
  const auth = makeAuth(register);
  TestBed.configureTestingModule({
    imports: [RegistrationFormComponent],
    providers: [
      { provide: AuthService, useValue: auth },
      provideAnimationsAsync(),
      provideRouter([]),
    ],
  });
  const fixture = TestBed.createComponent(RegistrationFormComponent);
  fixture.detectChanges();
  return { fixture, component: fixture.componentInstance, auth };
}

/**
 * Helper to fill the registration form with email, password, and consent.
 *
 * @param fixture The component fixture
 * @param email Email address (default: user@example.com)
 * @param password Password (default: ValidPass1!)
 * @param consent Whether to accept terms (default: true)
 */
function fillForm(
  fixture: ReturnType<typeof setup>['fixture'],
  email = 'user@example.com',
  password = 'ValidPass1!',
  consent = true,
) {
  const comp = fixture.componentInstance;
  comp.form.controls.email.setValue(email);
  comp.form.controls.password.setValue(password);
  comp.form.controls.consentAccepted.setValue(consent);
  fixture.detectChanges();
}

/**
 * Helper to locate the submit button element.
 * Navigates through <nx-button> host to the underlying <button>.
 *
 * @param fixture The component fixture
 * @returns The HTML submit button element
 */
function submitButton(fixture: ReturnType<typeof setup>['fixture']): HTMLButtonElement {
  // data-testid="reg-submit" is on the <nx-button> host; the actual <button> is one level inside.
  const host = fixture.debugElement.query(By.css('[data-testid="reg-submit"]'));
  return host.query(By.css('button')).nativeElement;
}

/**
 * Tests for RegistrationFormComponent: form validation, field errors, and submission.
 */
describe('RegistrationFormComponent', () => {
  it('should disable submit when consentAccepted is false', () => {
    const { fixture } = setup();
    fillForm(fixture, 'user@example.com', 'ValidPass1!', false);
    expect(submitButton(fixture).disabled).toBe(true);
  });

  it('should disable submit while request is in-flight', () => {
    const pending = new Subject<void>();
    const { fixture } = setup(vi.fn(() => pending.asObservable()));
    fillForm(fixture);
    submitButton(fixture).click();
    fixture.detectChanges();
    expect(submitButton(fixture).disabled).toBe(true);
  });

  it('should show success message after register() resolves', async () => {
    const { fixture } = setup(vi.fn(() => of(undefined as void)));
    fillForm(fixture);
    submitButton(fixture).click();
    fixture.detectChanges();
    const success = fixture.debugElement.query(By.css('[data-testid="reg-success"]'));
    expect(success).toBeTruthy();
  });

  it('should show field error when server returns details for a field', () => {
    const serverError: AppError = {
      code: 'VALIDATION_ERROR',
      message: 'Validation failed.',
      details: [{ field: 'email', message: 'Email already exists.' }],
    };
    const { fixture, component } = setup(vi.fn(() => throwError(() => serverError)));
    fillForm(fixture);
    submitButton(fixture).click();
    fixture.detectChanges();
    expect(component.form.controls.email.errors?.['server']).toBe('Email already exists.');
  });

  it('should pass current password value to the strength meter', () => {
    const { fixture, component } = setup();
    component.form.controls.password.setValue('Str0ng!Pass99');
    fixture.detectChanges();
    const meter = fixture.debugElement.query(By.css('app-password-strength-meter'));
    expect(meter).toBeTruthy();
    const statusEl: HTMLElement = meter.nativeElement.querySelector('[role="status"]');
    expect(statusEl.getAttribute('aria-label')).toContain('Very Strong');
  });

  it('should disable submit button when form is empty (initial state)', () => {
    const { fixture } = setup();
    // No values set — form is invalid by default (all fields required/requiredTrue)
    expect(submitButton(fixture).disabled).toBe(true);
  });

  it('should show error banner for non-field server error', () => {
    const serverError: AppError = {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred.',
    };
    const { fixture } = setup(vi.fn(() => throwError(() => serverError)));
    fillForm(fixture);
    submitButton(fixture).click();
    fixture.detectChanges();
    const banner = fixture.debugElement.query(By.css('[data-testid="reg-error-banner"]'));
    expect(banner).toBeTruthy();
    expect(banner.nativeElement.textContent).toContain('An unexpected error occurred.');
  });

  it('should NOT show error banner when server returns field-level details', () => {
    const serverError: AppError = {
      code: 'VALIDATION_ERROR',
      message: 'Validation failed.',
      details: [{ field: 'password', message: 'Password is too common.' }],
    };
    const { fixture } = setup(vi.fn(() => throwError(() => serverError)));
    fillForm(fixture);
    submitButton(fixture).click();
    fixture.detectChanges();
    // Field error replaces generic banner
    expect(fixture.debugElement.query(By.css('[data-testid="reg-error-banner"]'))).toBeNull();
  });
});
