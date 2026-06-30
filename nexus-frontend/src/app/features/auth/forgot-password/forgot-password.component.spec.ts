import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ForgotPasswordComponent } from './forgot-password.component';
import { AuthService } from '../auth.service';
import { NEVER, of, throwError } from 'rxjs';
import { AppError } from '../../../shared/types/app-error';

function makeAuthService(): { forgotPassword: ReturnType<typeof vi.fn> } {
  return { forgotPassword: vi.fn().mockReturnValue(of({ message: 'ok' })) };
}

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

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should not call forgotPassword when email is empty', () => {
    component.submit();
    expect(authService.forgotPassword).not.toHaveBeenCalled();
  });

  it('should not call forgotPassword when email is invalid', () => {
    component.forgotForm.controls.email.setValue('not-an-email');
    component.submit();
    expect(authService.forgotPassword).not.toHaveBeenCalled();
  });

  it('should call forgotPassword with email on valid submit', () => {
    component.forgotForm.controls.email.setValue('user@example.com');
    component.submit();
    expect(authService.forgotPassword).toHaveBeenCalledWith('user@example.com');
  });

  it('should set submitted=true on success', () => {
    component.forgotForm.controls.email.setValue('user@example.com');
    component.submit();
    expect(component.submitted()).toBe(true);
  });

  it('should set errorMessage on unexpected error', () => {
    authService.forgotPassword.mockReturnValue(
      throwError(() => ({ code: 'SERVER_ERROR', message: 'boom' }) as AppError),
    );
    component.forgotForm.controls.email.setValue('user@example.com');
    component.submit();
    expect(component.errorMessage()).toBeTruthy();
    expect(component.submitted()).toBe(false);
  });

  it('should mark form invalid when email is empty', () => {
    component.forgotForm.controls.email.setValue('');
    expect(component.forgotForm.controls.email.valid).toBe(false);
  });

  it('should mark form valid when email is well-formed', () => {
    component.forgotForm.controls.email.setValue('user@example.com');
    expect(component.forgotForm.controls.email.valid).toBe(true);
  });

  it('should not call forgotPassword a second time while already loading', () => {
    authService.forgotPassword.mockReturnValue(NEVER);
    component.forgotForm.controls.email.setValue('user@example.com');

    component.submit(); // first submit — sets loading=true, observable never completes
    component.submit(); // second submit — must be a no-op

    expect(authService.forgotPassword).toHaveBeenCalledTimes(1);
  });
});
