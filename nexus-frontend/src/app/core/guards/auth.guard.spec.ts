import { TestBed } from '@angular/core/testing';
import {
  Router,
  UrlTree,
  MaybeAsync,
  GuardResult,
  ActivatedRouteSnapshot,
  RouterStateSnapshot,
} from '@angular/router';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { firstValueFrom, Observable, of, throwError } from 'rxjs';
import { authGuard } from './auth.guard';
import { AuthStore } from '../auth/auth.store';
import { AuthService } from '../../features/auth/auth.service';

/**
 * authGuard — route protection with silent session restoration.
 *
 * Verifies that the guard grants access to authenticated users immediately,
 * attempts silent refresh on cold start with a valid refresh token, and
 * redirects to login when the user is unauthenticated and refresh fails.
 */
describe('authGuard', () => {
  let mockAuthStore: { isAuthenticated: ReturnType<typeof vi.fn> };
  let mockAuthService: { refresh: ReturnType<typeof vi.fn> };

  const dummyRoute = {} as ActivatedRouteSnapshot;
  const dummyState = {} as RouterStateSnapshot;

  /**
   * Executes the guard in the test injection context.
   *
   * @returns The guard result (true, UrlTree, or Observable).
   */
  function runGuard(): MaybeAsync<GuardResult> {
    return TestBed.runInInjectionContext(() => authGuard(dummyRoute, dummyState));
  }

  beforeEach(() => {
    mockAuthStore = { isAuthenticated: vi.fn(() => false) };
    mockAuthService = { refresh: vi.fn() };

    TestBed.configureTestingModule({
      providers: [
        { provide: AuthStore, useValue: mockAuthStore },
        { provide: AuthService, useValue: mockAuthService },
        {
          provide: Router,
          useValue: {
            createUrlTree: (commands: string[]) => ({ _commands: commands }) as unknown as UrlTree,
            navigate: vi.fn(),
          },
        },
      ],
    });
  });

  it('returns true immediately when already authenticated — no refresh attempted', () => {
    mockAuthStore.isAuthenticated.mockReturnValue(true);
    const result = runGuard();
    expect(result).toBe(true);
    expect(mockAuthService.refresh).not.toHaveBeenCalled();
  });

  it('attempts silent refresh on cold start (session null); returns true when cookie is valid', async () => {
    mockAuthStore.isAuthenticated.mockReturnValue(false);
    mockAuthService.refresh.mockReturnValue(of({ accessToken: 'restored-token' }));

    const result = await firstValueFrom(runGuard() as Observable<GuardResult>);
    expect(result).toBe(true);
    expect(mockAuthService.refresh).toHaveBeenCalledTimes(1);
  });

  it('redirects to /auth/login when session is null and refresh cookie is expired/revoked', async () => {
    mockAuthStore.isAuthenticated.mockReturnValue(false);
    mockAuthService.refresh.mockReturnValue(throwError(() => new Error('cookie gone')));

    const result = await firstValueFrom(runGuard() as Observable<GuardResult>);
    const urlTree = result as unknown as { _commands: string[] };
    expect(urlTree._commands).toEqual(['/auth/login']);
  });
});
