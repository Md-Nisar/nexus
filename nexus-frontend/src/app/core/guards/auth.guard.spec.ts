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
import { firstValueFrom, Observable, of, Subject, throwError } from 'rxjs';
import { authGuard } from './auth.guard';
import { AuthStore } from '../auth/auth.store';
import { LoggerService, LogParams } from '../logging/logger.service';
import { UnavailableState } from '../routing/unavailable-state';
import { AuthService } from '../../features/auth/auth.service';
import { AppError } from '../../shared/types/app-error';

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
  let mockUnavailableState: { record: ReturnType<typeof vi.fn> };
  let mockLogger: { warn: ReturnType<typeof vi.fn> };

  const dummyRoute = {} as ActivatedRouteSnapshot;
  const dummyState = { url: '/role-test?tab=x' } as RouterStateSnapshot;

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
    mockUnavailableState = { record: vi.fn() };
    mockLogger = { warn: vi.fn() };

    TestBed.configureTestingModule({
      providers: [
        { provide: AuthStore, useValue: mockAuthStore },
        { provide: AuthService, useValue: mockAuthService },
        { provide: UnavailableState, useValue: mockUnavailableState },
        { provide: LoggerService, useValue: mockLogger },
        {
          provide: Router,
          useValue: {
            createUrlTree: (commands: string[], extras?: unknown) =>
              ({ _commands: commands, _extras: extras }) as unknown as UrlTree,
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
    const urlTree = result as unknown as { _commands: string[]; _extras: unknown };
    expect(urlTree._commands).toEqual(['/auth/login']);
    expect(urlTree._extras).toEqual({ queryParams: { returnUrl: '/role-test?tab=x' } });
  });

  /**
   * US-020 design §4.5 (Q4 amended): "nobody authoritative answered" goes to the unavailable view;
   * every backend problem document still goes to login.
   */
  describe('cold-start classification (US-020 T-002)', () => {
    const UNAVAILABLE: readonly (readonly [string, AppError])[] = [
      [
        'NETWORK_ERROR',
        { code: 'NETWORK_ERROR', message: 'Could not reach the server.', correlationId: 'c-1' },
      ],
      [
        'HTTP_ERROR',
        { code: 'HTTP_ERROR', message: 'Request failed with status 502.', correlationId: 'c-2' },
      ],
      [
        'AUTH_005',
        {
          code: 'AUTH_005',
          message: 'Server text: epoch store down.',
          traceId: 'trace-3',
          correlationId: 'c-3',
          retryAfterSeconds: 30,
        },
      ],
    ];

    const LOGIN: readonly (readonly [string, AppError])[] = [
      ['AUTH_004', { code: 'AUTH_004', message: 'Refresh token invalid.', correlationId: 'c-4' }],
      ['RATE_001', { code: 'RATE_001', message: 'Too many requests.', retryAfterSeconds: 60 }],
      ['INTERNAL_ERROR', { code: 'INTERNAL_ERROR', message: 'Unexpected.', traceId: 't-6' }],
    ];

    it.each(UNAVAILABLE)(
      'sends %s to /unavailable with returnUrl and records the state',
      async (_n, error) => {
        mockAuthService.refresh.mockReturnValue(throwError(() => error));

        const result = await firstValueFrom(runGuard() as Observable<GuardResult>);

        const urlTree = result as unknown as { _commands: string[]; _extras: unknown };
        expect(urlTree._commands).toEqual(['/unavailable']);
        expect(urlTree._extras).toEqual({ queryParams: { returnUrl: '/role-test?tab=x' } });
        expect(mockUnavailableState.record).toHaveBeenCalledTimes(1);
        expect(mockUnavailableState.record).toHaveBeenCalledWith(error);
        expect(mockAuthService.refresh).toHaveBeenCalledTimes(1);
      },
    );

    it.each(UNAVAILABLE)(
      'logs auth_guard_unavailable for %s with errorCode and correlationId only',
      async (_n, error) => {
        mockAuthService.refresh.mockReturnValue(throwError(() => error));

        await firstValueFrom(runGuard() as Observable<GuardResult>);

        expect(mockLogger.warn).toHaveBeenCalledTimes(1);
        const [message, params] = mockLogger.warn.mock.calls[0] as [string, LogParams];
        expect(params).toEqual({
          event: 'auth_guard_unavailable',
          errorCode: error.code,
          correlationId: error.correlationId,
        });
        // No URL, server text or trace id in the message either.
        expect(message).not.toContain('role-test');
        expect(message).not.toContain(error.message);
        expect(JSON.stringify([message, params])).not.toContain('trace-');
      },
    );

    it.each(LOGIN)(
      'sends the backend problem document %s to /auth/login with returnUrl',
      async (_n, error) => {
        mockAuthService.refresh.mockReturnValue(throwError(() => error));

        const result = await firstValueFrom(runGuard() as Observable<GuardResult>);

        const urlTree = result as unknown as { _commands: string[]; _extras: unknown };
        expect(urlTree._commands).toEqual(['/auth/login']);
        expect(urlTree._extras).toEqual({ queryParams: { returnUrl: '/role-test?tab=x' } });
        expect(mockUnavailableState.record).not.toHaveBeenCalled();
        expect(mockLogger.warn).not.toHaveBeenCalled();
        expect(mockAuthService.refresh).toHaveBeenCalledTimes(1);
      },
    );

    it('sends a code-shaped value without a message (not an AppError) to login', async () => {
      mockAuthService.refresh.mockReturnValue(throwError(() => ({ code: 'NETWORK_ERROR' })));

      const result = await firstValueFrom(runGuard() as Observable<GuardResult>);

      expect((result as unknown as { _commands: string[] })._commands).toEqual(['/auth/login']);
      expect(mockUnavailableState.record).not.toHaveBeenCalled();
    });

    it('never returns true before refresh() has emitted a session', () => {
      const pending = new Subject<unknown>();
      mockAuthService.refresh.mockReturnValue(pending);
      const emitted: GuardResult[] = [];

      (runGuard() as Observable<GuardResult>).subscribe((r) => emitted.push(r));

      expect(emitted).toEqual([]);
      expect(mockAuthService.refresh).toHaveBeenCalledTimes(1);
      pending.error({ code: 'NETWORK_ERROR', message: 'x' });
      expect(emitted).toHaveLength(1);
      expect(emitted[0]).not.toBe(true);
    });

    it.each([...UNAVAILABLE, ...LOGIN])(
      'never returns true when refresh fails with %s',
      async (_n, e) => {
        mockAuthService.refresh.mockReturnValue(throwError(() => e));
        expect(await firstValueFrom(runGuard() as Observable<GuardResult>)).not.toBe(true);
      },
    );
  });
});
