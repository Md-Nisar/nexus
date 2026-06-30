import { TestBed } from '@angular/core/testing';
import { provideRouter, ActivatedRoute } from '@angular/router';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ResetPasswordComponent } from './reset-password.component';
import { AuthService } from '../auth.service';
import { of, throwError } from 'rxjs';
import { AppError } from '../../../shared/types/app-error';

function makeAuthService(): { resetPassword: ReturnType<typeof vi.fn> } {
  return {
    resetPassword: vi.fn().mockReturnValue(of({ message: 'Password reset successfully.' })),
  };
}

const VALID_TOKEN = 'a'.repeat(64);
const VALID_PASSWORD = 'MyStr0ngNewP@ss!';

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

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should read token from URL on init', () => {
    component.ngOnInit();
    // tokenFromUrl is private; exercise via submit
    component.resetForm.controls.newPassword.setValue(VALID_PASSWORD);
    component.submit();
    expect(authService.resetPassword).toHaveBeenCalledWith(VALID_TOKEN, VALID_PASSWORD);
  });

  it('should not call resetPassword when form is invalid', () => {
    component.resetForm.controls.newPassword.setValue('');
    component.submit();
    expect(authService.resetPassword).not.toHaveBeenCalled();
  });

  it('should not call resetPassword when password is too short', () => {
    component.resetForm.controls.newPassword.setValue('short');
    component.submit();
    expect(authService.resetPassword).not.toHaveBeenCalled();
  });

  it('should strip token from URL on init to prevent Referer leakage', () => {
    // routerNavigateSpy is patched before detectChanges, so ngOnInit already ran
    expect(routerNavigateSpy).toHaveBeenCalledWith(
      [],
      expect.objectContaining({ queryParams: {}, replaceUrl: true }),
    );
  });

  it('should not call resetPassword when password exceeds 256 characters', () => {
    component.resetForm.controls.newPassword.setValue('A1!'.repeat(86)); // 258 chars
    component.submit();
    expect(authService.resetPassword).not.toHaveBeenCalled();
  });

  it('should navigate to login with reset=true on success', () => {
    routerNavigateSpy.mockClear();
    component.resetForm.controls.newPassword.setValue(VALID_PASSWORD);
    component.submit();
    expect(routerNavigateSpy).toHaveBeenCalledWith(['/auth/login'], {
      queryParams: { reset: 'true' },
    });
  });

  it('should set AUTH_RST_002 error message with forgot link on expired token', () => {
    authService.resetPassword.mockReturnValue(
      throwError(() => ({ code: 'AUTH_RST_002', message: 'expired' }) as AppError),
    );
    component.resetForm.controls.newPassword.setValue(VALID_PASSWORD);
    component.submit();
    expect(component.errorMessage()).toContain('expired or already been used');
    expect(component.showForgotLink()).toBe(true);
  });

  it('should set AUTH_RST_003 error on same-password response', () => {
    authService.resetPassword.mockReturnValue(
      throwError(() => ({ code: 'AUTH_RST_003', message: 'same' }) as AppError),
    );
    component.resetForm.controls.newPassword.setValue(VALID_PASSWORD);
    component.submit();
    expect(component.errorMessage()).toContain('different');
    expect(component.showForgotLink()).toBe(false);
  });

  it('should set AUTH_PWD_001 error on policy failure', () => {
    authService.resetPassword.mockReturnValue(
      throwError(() => ({ code: 'AUTH_PWD_001', message: 'too short' }) as AppError),
    );
    component.resetForm.controls.newPassword.setValue(VALID_PASSWORD);
    component.submit();
    expect(component.errorMessage()).toContain('12 characters');
  });

  it('should set AUTH_PWD_002 error when password is too common', () => {
    authService.resetPassword.mockReturnValue(
      throwError(() => ({ code: 'AUTH_PWD_002', message: 'too common' }) as AppError),
    );
    component.resetForm.controls.newPassword.setValue(VALID_PASSWORD);
    component.submit();
    expect(component.errorMessage()).toContain('common');
    expect(component.showForgotLink()).toBe(false);
  });

  it('should set generic error on unknown error code', () => {
    authService.resetPassword.mockReturnValue(
      throwError(() => ({ code: 'UNKNOWN', message: 'boom' }) as AppError),
    );
    component.resetForm.controls.newPassword.setValue(VALID_PASSWORD);
    component.submit();
    expect(component.errorMessage()).toContain('unexpected');
  });

  it('should toggle showPassword signal', () => {
    expect(component.showPassword()).toBe(false);
    component.showPassword.update((v) => !v);
    expect(component.showPassword()).toBe(true);
  });
});
