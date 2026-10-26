import { HttpClient } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { PartialMatchRouteSnapshot, Route, UrlSegment } from '@angular/router';
import { describe, expect, it, vi } from 'vitest';
import { AuthService } from '../../features/auth/auth.service';
import { AuthStore } from '../auth/auth.store';
import { APP_CONFIG, AppConfig } from '../config/app-config';
import { accessConsoleEnabledGuard } from './access-console-enabled.guard';

function config(accessConsoleEnabled: boolean): AppConfig {
  return {
    production: false,
    apiBaseUrl: '/api',
    logLevel: 'debug',
    supportContact: null,
    accessConsoleEnabled,
  };
}

function runGuard(): unknown {
  return TestBed.runInInjectionContext(() =>
    accessConsoleEnabledGuard(
      { path: 'admin/access' } as Route,
      [] as UrlSegment[],
      {} as PartialMatchRouteSnapshot,
    ),
  );
}

/**
 * accessConsoleEnabledGuard: the console's release control (RC-76). It is not an access control;
 * it reads configuration only, because `canMatch` runs before the shell's `authGuard`.
 */
describe('accessConsoleEnabledGuard', () => {
  it('matches when accessConsoleEnabled is true', () => {
    TestBed.configureTestingModule({
      providers: [{ provide: APP_CONFIG, useValue: config(true) }],
    });
    expect(runGuard()).toBe(true);
  });

  it('does not match when accessConsoleEnabled is false', () => {
    TestBed.configureTestingModule({
      providers: [{ provide: APP_CONFIG, useValue: config(false) }],
    });
    expect(runGuard()).toBe(false);
  });

  it('injects neither AuthStore, AuthService nor HttpClient', () => {
    const authStore = vi.fn(() => ({}));
    const authService = vi.fn(() => ({}));
    const httpClient = vi.fn(() => ({}));
    TestBed.configureTestingModule({
      providers: [
        { provide: APP_CONFIG, useValue: config(true) },
        { provide: AuthStore, useFactory: authStore },
        { provide: AuthService, useFactory: authService },
        { provide: HttpClient, useFactory: httpClient },
      ],
    });

    runGuard();

    expect(authStore).not.toHaveBeenCalled();
    expect(authService).not.toHaveBeenCalled();
    expect(httpClient).not.toHaveBeenCalled();
  });
});
