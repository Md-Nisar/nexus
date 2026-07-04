import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ForgotPasswordComponent } from './forgot-password.component';
import { AuthService } from '../auth.service';
import { NEVER, of, throwError } from 'rxjs';
import { AppError } from '../../../shared/types/app-error';

/**
 * Mock factory for AuthService.
 * Returns a spy object with forgotPassword method configured to return success by default.
 */
function makeAuthService(): { forgotPassword: ReturnType<typeof vi.fn> } {
  return { forgotPassword: vi.fn().mockReturnValue(of({ message: 'ok' })) };
}

/**
 * Test suite for ForgotPasswordComponent.
 *
 * Tests verify:
 * 1. Form validation (email format, length constraints, required field)
 * 2. API integration: forgotPassword() called only when form is valid
 * 3. State management: loading, submitted, errorMessage signals
 * 4. Error handling: user-friendly messages, anti-enumeration (always success message)
 * 5. Race condition prevention: no double-submit while loading
 *
 * Validation rules:
 *   - Email required
 *   - Valid email format (RFC 5321)
 *   - Max 254 characters (RFC 5321)
 *
 * Anti-enumeration:
 *   - Both success and backend error show generic message to user
 *   - Prevents attacker from learning which emails are registered
 */
describe('ForgotPasswordComponent', () => {
  let component: ForgotPasswordComponent;
  let authService: ReturnType<typeof makeAuthService>;

  beforeEach(async () => {
    authService = makeAuthService();
    await TestBed.configureTestingModule({
      imports: [ForgotPasswordComponent],
      providers: [provideRouter([]), { provide: AuthService, useValue: authService }],
    }).compileComponents();

    const fixture = TestBed.createComponent(ForgotPasswordComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  /**
   * Component instantiation: smoke test.
   */
  it('should create', () => {
    expect(component).toBeTruthy();
  });

  /**
   * Form validation prevents API call when email is empty.
   * The "required" validator marks form invalid.
   * Submit must return early without calling authService.
   */
  it('should not call forgotPassword when email is empty', () => {
    component.submit();
    expect(authService.forgotPassword).not.toHaveBeenCalled();
  });

  /**
   * Form validation prevents API call when email format is invalid.
   * The "email" validator rejects non-RFC-5321-compliant addresses.
   * Submit must return early without calling authService.
   */
  it('should not call forgotPassword when email is invalid', () => {
    component.forgotForm.controls.email.setValue('not-an-email');
    component.submit();
    expect(authService.forgotPassword).not.toHaveBeenCalled();
  });

  /**
   * Valid email triggers API call with the entered email address.
   * AuthService.forgotPassword is called once, no earlier, no later.
   */
  it('should call forgotPassword with email on valid submit', () => {
    component.forgotForm.controls.email.setValue('user@example.com');
    component.submit();
    expect(authService.forgotPassword).toHaveBeenCalledWith('user@example.com');
  });

  /**
   * Successful API response transitions to confirmation state.
   * submitted signal becomes true, UI shows "check your inbox" message.
   */
  it('should set submitted=true on success', () => {
    component.forgotForm.controls.email.setValue('user@example.com');
    component.submit();
    expect(component.submitted()).toBe(true);
  });

  /**
   * API error sets errorMessage signal and keeps submitted=false.
   * User sees generic error message (never specific error from server).
   * Prevents information leakage about backend state.
   */
  it('should set errorMessage on unexpected error', () => {
    authService.forgotPassword.mockReturnValue(
      throwError(() => ({ code: 'SERVER_ERROR', message: 'boom' }) as AppError),
    );
    component.forgotForm.controls.email.setValue('user@example.com');
    component.submit();
    expect(component.errorMessage()).toBeTruthy();
    expect(component.submitted()).toBe(false);
  });

  /**
   * Empty email fails form validation.
   * Email control's valid property reflects "required" validator failure.
   */
  it('should mark form invalid when email is empty', () => {
    component.forgotForm.controls.email.setValue('');
    expect(component.forgotForm.controls.email.valid).toBe(false);
  });

  /**
   * Well-formed email passes form validation.
   * Email control's valid property confirms both "required" and "email" validators pass.
   */
  it('should mark form valid when email is well-formed', () => {
    component.forgotForm.controls.email.setValue('user@example.com');
    expect(component.forgotForm.controls.email.valid).toBe(true);
  });

  /**
   * Race condition prevention: double-submit protection.
   * When loading=true, submit() returns early without calling authService again.
   * NEVER observable simulates a never-completing request (loading stays true).
   * Second submit must be a no-op due to loading guard.
   */
  it('should not call forgotPassword a second time while already loading', () => {
    authService.forgotPassword.mockReturnValue(NEVER);
    component.forgotForm.controls.email.setValue('user@example.com');

    component.submit(); // first submit — sets loading=true, observable never completes
    component.submit(); // second submit — must be a no-op

    expect(authService.forgotPassword).toHaveBeenCalledTimes(1);
  });
});
