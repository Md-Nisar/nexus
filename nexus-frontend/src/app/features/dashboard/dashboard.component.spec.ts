import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { provideRouter, Router } from '@angular/router';
import { NEVER, of, Subject, throwError } from 'rxjs';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { DashboardComponent } from './dashboard.component';
import { AuthService } from '../auth/auth.service';
import { NxToast } from '../../shared/ui';
import { APP_CONFIG } from '../../core/config/app-config';

const TEST_CONFIG = {
  production: false,
  apiBaseUrl: 'http://localhost:1000/api',
  logLevel: 'debug' as const,
};

function setup(logoutFn: ReturnType<typeof vi.fn> = vi.fn(() => of(undefined))) {
  const mockAuthService = { logout: logoutFn };
  const mockToast = {
    success: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    warning: vi.fn(),
    show: vi.fn(),
  };

  TestBed.configureTestingModule({
    imports: [DashboardComponent],
    providers: [
      { provide: AuthService, useValue: mockAuthService },
      { provide: NxToast, useValue: mockToast },
      { provide: APP_CONFIG, useValue: TEST_CONFIG },
      provideAnimationsAsync(),
      provideRouter([]),
      provideHttpClient(),
      provideHttpClientTesting(),
    ],
  });

  const fixture = TestBed.createComponent(DashboardComponent);
  const httpMock = TestBed.inject(HttpTestingController);
  const router = TestBed.inject(Router);
  const navigateSpy = vi.spyOn(router, 'navigate').mockResolvedValue(true);

  fixture.detectChanges(); // triggers httpResource → GET /v1/users/me
  httpMock.expectOne(`${TEST_CONFIG.apiBaseUrl}/v1/users/me`).flush({});

  return {
    fixture,
    component: fixture.componentInstance,
    mockAuthService,
    mockToast,
    navigateSpy,
    httpMock,
  };
}

describe('DashboardComponent', () => {
  afterEach(() => TestBed.inject(HttpTestingController).verify());

  it('shows logout button in the dashboard', () => {
    const { fixture } = setup();
    const btn = fixture.nativeElement.querySelector('[data-testid="logout-button"]');
    expect(btn).not.toBeNull();
  });

  it('sets loggingOut to true while logout is in-flight and disables the button', () => {
    const { fixture, component } = setup(vi.fn(() => NEVER));

    expect(component.loggingOut()).toBe(false);

    component.onLogout();
    fixture.detectChanges();

    expect(component.loggingOut()).toBe(true);
    const inner = fixture.nativeElement.querySelector('[data-testid="logout-button"] button');
    expect(inner?.disabled).toBe(true);
  });

  it('shows success toast and navigates to /auth/login on successful logout', () => {
    const logoutSubject = new Subject<void>();
    const { component, mockToast, navigateSpy } = setup(vi.fn(() => logoutSubject.asObservable()));

    component.onLogout();
    logoutSubject.next();
    logoutSubject.complete();

    expect(mockToast.success).toHaveBeenCalledWith('You have been logged out.');
    expect(navigateSpy).toHaveBeenCalledWith(['/auth/login']);
  });

  it('shows error toast and still navigates to /auth/login on logout HTTP failure', () => {
    const { component, mockToast, navigateSpy } = setup(
      vi.fn(() => throwError(() => new Error('network error'))),
    );

    component.onLogout();

    expect(mockToast.error).toHaveBeenCalled();
    expect(navigateSpy).toHaveBeenCalledWith(['/auth/login']);
  });

  it('resets loggingOut to false after logout completes', () => {
    const logoutSubject = new Subject<void>();
    const { component, fixture } = setup(vi.fn(() => logoutSubject.asObservable()));

    component.onLogout();
    fixture.detectChanges();
    expect(component.loggingOut()).toBe(true);

    logoutSubject.next();
    logoutSubject.complete();
    fixture.detectChanges();

    expect(component.loggingOut()).toBe(false);
  });
});
