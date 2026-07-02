import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { ActivatedRoute } from '@angular/router';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { provideRouter } from '@angular/router';
import { Subject, of, throwError } from 'rxjs';
import { describe, it, expect, vi } from 'vitest';
import { VerificationLandingComponent } from './verification-landing.component';
import { AuthService } from '../auth.service';
import { AppError } from '../../../shared/types/app-error';

const VALID_TOKEN = 'a'.repeat(64);

const EXPIRED_ERROR: AppError = {
  code: 'AUTH_VRF_002',
  message: 'The verification link is invalid or has expired.',
};

const GENERIC_ERROR: AppError = {
  code: 'UNEXPECTED_ERROR',
  message: 'Something went wrong.',
};

function setup(token: string | undefined, verifyFn = vi.fn(() => of(undefined as void))) {
  const queryParams = token !== undefined ? { token } : {};
  const routerNavigateSpy = vi.fn().mockResolvedValue(true);
  TestBed.configureTestingModule({
    imports: [VerificationLandingComponent],
    providers: [
      { provide: AuthService, useValue: { verifyEmail: verifyFn } },
      provideRouter([]),
      provideAnimationsAsync(),
      // ActivatedRoute must come AFTER provideRouter so our mock takes precedence
      { provide: ActivatedRoute, useValue: { queryParams: of(queryParams) } },
    ],
  });
  const fixture = TestBed.createComponent(VerificationLandingComponent);
  // The mocked ActivatedRoute above has no `snapshot`, which the real Router needs to resolve
  // `relativeTo` — patch navigate directly, same pattern as ResetPasswordComponent's spec.
  (
    fixture.componentInstance as unknown as { router: { navigate: typeof routerNavigateSpy } }
  ).router.navigate = routerNavigateSpy;
  return { fixture, verifyFn, routerNavigateSpy };
}

describe('VerificationLandingComponent', () => {
  it('should show verifying spinner on init before the response arrives', () => {
    const pending = new Subject<void>();
    const { fixture } = setup(
      VALID_TOKEN,
      vi.fn(() => pending.asObservable()),
    );
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('[data-testid="verif-verifying"]'))).toBeTruthy();
    expect(fixture.debugElement.query(By.css('[data-testid="verif-success"]'))).toBeNull();
  });

  it('should show success state after verifyEmail resolves', () => {
    const { fixture } = setup(
      VALID_TOKEN,
      vi.fn(() => of(undefined as void)),
    );
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('[data-testid="verif-success"]'))).toBeTruthy();
    expect(fixture.debugElement.query(By.css('[data-testid="verif-error"]'))).toBeNull();
  });

  it('should show resend link when error code is AUTH_VRF_002 (410)', () => {
    const { fixture } = setup(
      VALID_TOKEN,
      vi.fn(() => throwError(() => EXPIRED_ERROR)),
    );
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('[data-testid="verif-error"]'))).toBeTruthy();
    expect(fixture.debugElement.query(By.css('[data-testid="verif-resend"]'))).toBeTruthy();
  });

  it('should NOT show resend link for a generic error', () => {
    const { fixture } = setup(
      VALID_TOKEN,
      vi.fn(() => throwError(() => GENERIC_ERROR)),
    );
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('[data-testid="verif-error"]'))).toBeTruthy();
    expect(fixture.debugElement.query(By.css('[data-testid="verif-resend"]'))).toBeNull();
  });

  it('should show error immediately when token is absent from query params', () => {
    const verifyFn = vi.fn();
    const { fixture } = setup(undefined, verifyFn);
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('[data-testid="verif-error"]'))).toBeTruthy();
    expect(verifyFn).not.toHaveBeenCalled();
  });

  it('should NOT show resend link when token is absent (INVALID_LINK code)', () => {
    // The component sets code = 'INVALID_LINK' when no token is in the URL.
    // The template only shows the resend link for 'AUTH_VRF_002', so INVALID_LINK suppresses it.
    const { fixture } = setup(undefined, vi.fn());
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('[data-testid="verif-resend"]'))).toBeNull();
  });

  it('should call verifyEmail with the exact token string from query params', () => {
    const verifyFn = vi.fn(() => of(undefined as void));
    const { fixture } = setup(VALID_TOKEN, verifyFn);
    fixture.detectChanges();
    expect(verifyFn).toHaveBeenCalledWith(VALID_TOKEN);
    expect(verifyFn).toHaveBeenCalledTimes(1);
  });

  it('should strip the token from the URL on init to prevent Referer/history leakage', () => {
    const { fixture, routerNavigateSpy } = setup(VALID_TOKEN);
    fixture.detectChanges();
    expect(routerNavigateSpy).toHaveBeenCalledWith(
      [],
      expect.objectContaining({ queryParams: {}, replaceUrl: true }),
    );
  });

  it('should strip the URL even when no token is present', () => {
    const { fixture, routerNavigateSpy } = setup(undefined);
    fixture.detectChanges();
    expect(routerNavigateSpy).toHaveBeenCalledWith(
      [],
      expect.objectContaining({ queryParams: {}, replaceUrl: true }),
    );
  });
});
