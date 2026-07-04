import { TestBed } from '@angular/core/testing';
import { provideRouter, ActivatedRoute } from '@angular/router';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ResetPasswordComponent } from './reset-password.component';
import { AuthService } from '../auth.service';
import { of, throwError } from 'rxjs';
import { AppError } from '../../../shared/types/app-error';

/**
 * Mock factory for AuthService.
 * Returns a spy object with resetPassword method configured to return success by default.
 */
function makeAuthService(): { resetPassword: ReturnType<typeof vi.fn> } {
  return {
    resetPassword: vi.fn().mockReturnValue(of({ message: 'Password reset successfully.' })),
  };
}

/** A typical 64-character reset token (matches backend token length). */
const VALID_TOKEN = 'a'.repeat(64);

/** A valid password meeting policy: 12+ chars, uppercase, digit, special char. */
const VALID_PASSWORD = 'MyStr0ngNewP@ss!';

/**
 * Test suite for ResetPasswordComponent.
 *
 * Tests verify:
 * 1. Token extraction and URL sanitization (Referer/history protection)
 * 2. Form validation (password length constraints, required field)
 * 3. API integration: resetPassword() called only when form is valid
 * 4. State management: loading, errorMessage, showPassword, showForgotLink signals
 * 5. Error handling: specific error codes mapped to user-friendly messages
 * 6. UX: password visibility toggle, token link on expiry, navigation on success
 *
 * Validation rules:
 *   - Password required
 *   - Min 12 characters (policy requirement)
 *   - Max 256 characters (reasonable limit)
 *
 * Error codes:
 *   - AUTH_RST_002: Token expired or already used (show "request new link")
 *   - AUTH_PWD_001: Password policy violation
 *   - AUTH_PWD_002: Password too common (dictionary check)
 *   - AUTH_RST_003: Password same as current (reuse prevention)
 *   - Unknown: Generic error message
 */
describe('ResetPasswordComponent', () => {
  let component: ResetPasswordComponent;
  let authService: ReturnType<typeof makeAuthService>;
  let routerNavigateSpy: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    authService = makeAuthService();
    routerNavigateSpy = vi.fn().mockResolvedValue(true);

    await TestBed.configureTestingModule({
      imports: [ResetPasswordComponent],
      providers: [
        provideRouter([]),
        { provide: AuthService, useValue: authService },
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { queryParamMap: { get: () => VALID_TOKEN } },
          },
        },
      ],
    }).compileComponents();

    const fixture = TestBed.createComponent(ResetPasswordComponent);
    component = fixture.componentInstance;
    // Patch router navigate directly on the injected router
    (component as unknown as { router: { navigate: typeof routerNavigateSpy } }).router.navigate =
      routerNavigateSpy;
    fixture.detectChanges();
  });

  /**
   * Component instantiation: smoke test.
   */
  it('should create', () => {
    expect(component).toBeTruthy();
  });

  /**
   * Token extraction from URL query param.
   * ngOnInit reads the token and stores it in private tokenFromUrl signal.
   * We verify indirectly by submitting and checking the API call argument.
   */
  it('should read token from URL on init', () => {
    component.ngOnInit();
    // tokenFromUrl is private; exercise via submit
    component.resetForm.controls.newPassword.setValue(VALID_PASSWORD);
    component.submit();
    expect(authService.resetPassword).toHaveBeenCalledWith(VALID_TOKEN, VALID_PASSWORD);
  });

  /**
   * Form validation prevents API call when password field is empty.
   * The "required" validator marks form invalid.
   * Submit must return early without calling authService.
   */
  it('should not call resetPassword when form is invalid', () => {
    component.resetForm.controls.newPassword.setValue('');
    component.submit();
    expect(authService.resetPassword).not.toHaveBeenCalled();
  });

  /**
   * Form validation prevents API call when password is below minimum length.
   * The "minlength(12)" validator rejects passwords < 12 chars.
   * Submit must return early without calling authService.
   */
  it('should not call resetPassword when password is too short', () => {
    component.resetForm.controls.newPassword.setValue('short');
    component.submit();
    expect(authService.resetPassword).not.toHaveBeenCalled();
  });

  /**
   * URL sanitization on component init.
   * ngOnInit must call router.navigate with empty queryParams and replaceUrl=true.
   * This removes the token from browser history and prevents Referer leakage.
   * routerNavigateSpy is patched before detectChanges, so ngOnInit already ran.
   */
  it('should strip token from URL on init to prevent Referer leakage', () => {
    // routerNavigateSpy is patched before detectChanges, so ngOnInit already ran
    expect(routerNavigateSpy).toHaveBeenCalledWith(
      [],
      expect.objectContaining({ queryParams: {}, replaceUrl: true }),
    );
  });

  /**
   * Form validation prevents API call when password exceeds maximum length.
   * The "maxlength(256)" validator rejects passwords > 256 chars.
   * Submit must return early without calling authService.
   */
  it('should not call resetPassword when password exceeds 256 characters', () => {
    component.resetForm.controls.newPassword.setValue('A1!'.repeat(86)); // 258 chars
    component.submit();
    expect(authService.resetPassword).not.toHaveBeenCalled();
  });

  /**
   * Successful API response navigates to login with reset=true query param.
   * The login component uses this param to show a success confirmation message.
   * loading signal is set to false on completion.
   */
  it('should navigate to login with reset=true on success', () => {
    routerNavigateSpy.mockClear();
    component.resetForm.controls.newPassword.setValue(VALID_PASSWORD);
    component.submit();
    expect(routerNavigateSpy).toHaveBeenCalledWith(['/auth/login'], {
      queryParams: { reset: 'true' },
    });
  });

  /**
   * AUTH_RST_002 error (token expired or already used).
   * errorMessage is set with a user-friendly message.
   * showForgotLink is set to true to offer "request new link" option.
   * Improves UX when user's email link has staled.
   */
  it('should set AUTH_RST_002 error message with forgot link on expired token', () => {
    authService.resetPassword.mockReturnValue(
      throwError(() => ({ code: 'AUTH_RST_002', message: 'expired' }) as AppError),
    );
    component.resetForm.controls.newPassword.setValue(VALID_PASSWORD);
    component.submit();
    expect(component.errorMessage()).toContain('expired or already been used');
    expect(component.showForgotLink()).toBe(true);
  });

  /**
   * AUTH_RST_003 error (new password same as current).
   * Prevents password reuse attacks.
   * errorMessage is set, showForgotLink is false (no need to retry).
   */
  it('should set AUTH_RST_003 error on same-password response', () => {
    authService.resetPassword.mockReturnValue(
      throwError(() => ({ code: 'AUTH_RST_003', message: 'same' }) as AppError),
    );
    component.resetForm.controls.newPassword.setValue(VALID_PASSWORD);
    component.submit();
    expect(component.errorMessage()).toContain('different');
    expect(component.showForgotLink()).toBe(false);
  });

  /**
   * AUTH_PWD_001 error (password policy violation, typically length).
   * Backend performs stricter validation than client-side minLength validator.
   * errorMessage reflects the constraint, showForgotLink is false.
   */
  it('should set AUTH_PWD_001 error on policy failure', () => {
    authService.resetPassword.mockReturnValue(
      throwError(() => ({ code: 'AUTH_PWD_001', message: 'too short' }) as AppError),
    );
    component.resetForm.controls.newPassword.setValue(VALID_PASSWORD);
    component.submit();
    expect(component.errorMessage()).toContain('12 characters');
  });

  /**
   * AUTH_PWD_002 error (password too common, e.g., in a breached-password dictionary).
   * Backend performs dictionary check that client cannot replicate.
   * errorMessage reflects the issue, showForgotLink is false.
   */
  it('should set AUTH_PWD_002 error when password is too common', () => {
    authService.resetPassword.mockReturnValue(
      throwError(() => ({ code: 'AUTH_PWD_002', message: 'too common' }) as AppError),
    );
    component.resetForm.controls.newPassword.setValue(VALID_PASSWORD);
    component.submit();
    expect(component.errorMessage()).toContain('common');
    expect(component.showForgotLink()).toBe(false);
  });

  /**
   * Unknown error code: fallback to generic error message.
   * Never leak server internals to the UI.
   * This protects against information disclosure from unexpected backend responses.
   */
  it('should set generic error on unknown error code', () => {
    authService.resetPassword.mockReturnValue(
      throwError(() => ({ code: 'UNKNOWN', message: 'boom' }) as AppError),
    );
    component.resetForm.controls.newPassword.setValue(VALID_PASSWORD);
    component.submit();
    expect(component.errorMessage()).toContain('unexpected');
  });

  /**
   * Password visibility toggle.
   * showPassword signal can be toggled via update() to switch input type.
   * Improves UX on mobile or when typing a complex password.
   */
  it('should toggle showPassword signal', () => {
    expect(component.showPassword()).toBe(false);
    component.showPassword.update((v) => !v);
    expect(component.showPassword()).toBe(true);
  });
});
