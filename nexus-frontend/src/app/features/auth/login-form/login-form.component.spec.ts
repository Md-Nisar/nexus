import { TestBed } from '@angular/core/testing';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { ActivatedRoute, provideRouter, Router } from '@angular/router';
import { NEVER, of, throwError } from 'rxjs';
import { describe, it, expect, vi } from 'vitest';
import { LoginFormComponent } from './login-form.component';
import { AuthService } from '../auth.service';
import { AppError } from '../../../shared/types/app-error';

/**
 * Sets up a test fixture with mocked AuthService and optional query parameters.
 *
 * @param loginFn Mock implementation of AuthService.login()
 * @param queryParams Query parameters to inject into ActivatedRoute
 * @returns Test fixture, component instance, mock service, and router spy
 */
function setup(
  loginFn: ReturnType<typeof vi.fn> = vi.fn(() => of(undefined)),
  queryParams: Record<string, string> = {},
) {
  const mockAuthService = { login: loginFn };

  TestBed.configureTestingModule({
    imports: [LoginFormComponent],
    providers: [
      { provide: AuthService, useValue: mockAuthService },
      provideAnimationsAsync(),
      provideRouter([]),
      {
        provide: ActivatedRoute,
        useValue: { snapshot: { queryParamMap: { get: (k: string) => queryParams[k] ?? null } } },
      },
    ],
  });

  const fixture = TestBed.createComponent(LoginFormComponent);
  fixture.detectChanges();
  const router = TestBed.inject(Router);
  const navigateSpy = vi.spyOn(router, 'navigate').mockResolvedValue(true);
  return { fixture, component: fixture.componentInstance, mockAuthService, navigateSpy };
}

/**
 * Helper to fill the login form with email and password.
 *
 * @param fixture The component fixture
 * @param email Email address (default: user@example.com)
 * @param password Password (default: pass123)
 */
function fillForm(
  fixture: ReturnType<typeof setup>['fixture'],
  email = 'user@example.com',
  password = 'pass123',
) {
  const comp = fixture.componentInstance;
  comp.loginForm.setValue({ email, password });
  fixture.detectChanges();
}

/**
 * Tests for LoginFormComponent: form validation, submission, and error handling.
 */
describe('LoginFormComponent', () => {
  it('submit() calls authService.login() with form email and password', () => {
    const loginFn = vi.fn(() => of(undefined));
    const { fixture, component, mockAuthService } = setup(loginFn);
    fillForm(fixture);
    component.submit();
    expect(mockAuthService.login).toHaveBeenCalledWith('user@example.com', 'pass123');
  });

  it('submit() does nothing when form is invalid', () => {
    const loginFn = vi.fn(() => of(undefined));
    const { component, mockAuthService } = setup(loginFn);
    // form is empty, so invalid
    component.submit();
    expect(mockAuthService.login).not.toHaveBeenCalled();
  });

  it('submit() does nothing when already loading', () => {
    const loginFn = vi.fn(() => NEVER);
    const { fixture, component, mockAuthService } = setup(loginFn);
    fillForm(fixture);
    component.submit(); // first submit — puts component in loading state
    fixture.detectChanges();
    component.submit(); // second submit — must be a no-op
    expect(mockAuthService.login).toHaveBeenCalledTimes(1);
  });

  it('AUTH_001 error sets invalid-credentials message and resets loading', () => {
    const err: AppError = { code: 'AUTH_001', message: 'Unauthorized.' };
    const loginFn = vi.fn(() => throwError(() => err));
    const { fixture, component } = setup(loginFn);
    fillForm(fixture);
    component.submit();
    fixture.detectChanges();
    expect(component.errorMessage()).toBe('Invalid email or password.');
    expect(component.loading()).toBe(false);
  });

  it('AUTH_002 error sets email-verification message and resets loading', () => {
    const err: AppError = { code: 'AUTH_002', message: 'Email not verified.' };
    const loginFn = vi.fn(() => throwError(() => err));
    const { fixture, component } = setup(loginFn);
    fillForm(fixture);
    component.submit();
    fixture.detectChanges();
    expect(component.errorMessage()).toBe('Please verify your email before logging in.');
    expect(component.loading()).toBe(false);
  });

  it('RATE_001 error sets rate-limit message and resets loading', () => {
    const err: AppError = { code: 'RATE_001', message: 'Too many requests.' };
    const loginFn = vi.fn(() => throwError(() => err));
    const { fixture, component } = setup(loginFn);
    fillForm(fixture);
    component.submit();
    fixture.detectChanges();
    expect(component.errorMessage()).toBe('Too many attempts. Please try again later.');
    expect(component.loading()).toBe(false);
  });

  it('AUTH_LCK_001 error sets lockout message, resets loading, and does not navigate', () => {
    const err: AppError = { code: 'AUTH_LCK_001', message: 'Account locked.' };
    const loginFn = vi.fn(() => throwError(() => err));
    const { fixture, component, navigateSpy } = setup(loginFn);
    fillForm(fixture);
    component.submit();
    fixture.detectChanges();
    expect(component.errorMessage()).toBe(
      'Too many attempts. Try again later or reset your password.',
    );
    expect(component.loading()).toBe(false);
    expect(navigateSpy).not.toHaveBeenCalled();
    const banner = fixture.nativeElement.querySelector(
      '[data-testid="login-error"]',
    ) as HTMLElement;
    expect(banner.textContent?.trim()).toBe(
      'Too many attempts. Try again later or reset your password.',
    );
  });

  it('unknown error code sets generic message', () => {
    const err: AppError = { code: 'UNKNOWN', message: 'Something went wrong.' };
    const loginFn = vi.fn(() => throwError(() => err));
    const { fixture, component } = setup(loginFn);
    fillForm(fixture);
    component.submit();
    fixture.detectChanges();
    expect(component.errorMessage()).toBe('An unexpected error occurred. Please try again.');
    expect(component.loading()).toBe(false);
  });

  it('success navigates to /dashboard', () => {
    const loginFn = vi.fn(() => of(undefined));
    const { fixture, component, navigateSpy } = setup(loginFn);
    fillForm(fixture);
    component.submit();
    fixture.detectChanges();
    expect(navigateSpy).toHaveBeenCalledWith(['/dashboard']);
  });

  it('shows reset-success banner when ?reset=true query param is present', () => {
    const { fixture, component } = setup(
      vi.fn(() => of(undefined)),
      { reset: 'true' },
    );
    component.ngOnInit();
    fixture.detectChanges();
    expect(component.passwordReset()).toBe(true);
    const banner = fixture.nativeElement.querySelector('[data-testid="login-reset-success"]');
    expect(banner).not.toBeNull();
  });

  it('does not show reset-success banner when ?reset param is absent', () => {
    const { fixture } = setup();
    fixture.detectChanges();
    const banner = fixture.nativeElement.querySelector('[data-testid="login-reset-success"]');
    expect(banner).toBeNull();
  });
});
