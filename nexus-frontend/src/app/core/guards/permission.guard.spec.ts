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
import { permissionGuard } from './permission.guard';
import { AuthStore } from '../auth/auth.store';
import { LoggerService } from '../logging/logger.service';
import { createAuthStoreStub, AuthStoreStub } from '../../shared/testing/auth.fixtures';

/**
 * permissionGuard — UX-only route protection based on AuthStore's permissions signal.
 *
 * Verifies: allow/deny on permission match, fail-open on route misconfiguration, and
 * that a denial (and only a denial) emits exactly one structured debug log with the
 * query string stripped from the attempted route.
 */
describe('permissionGuard', () => {
  let stub: AuthStoreStub;
  let mockLogger: { debug: ReturnType<typeof vi.fn> };

  function buildRoute(data: Record<string, unknown>): ActivatedRouteSnapshot {
    return { data } as unknown as ActivatedRouteSnapshot;
  }

  function buildState(url: string): RouterStateSnapshot {
    return { url } as RouterStateSnapshot;
  }

  function runGuard(data: Record<string, unknown>, url = '/gated'): MaybeAsync<GuardResult> {
    return TestBed.runInInjectionContext(() => permissionGuard(buildRoute(data), buildState(url)));
  }

  beforeEach(() => {
    stub = createAuthStoreStub({ permissions: ['roles:read'] });
    mockLogger = { debug: vi.fn() };

    TestBed.configureTestingModule({
      providers: [
        { provide: AuthStore, useValue: stub },
        { provide: LoggerService, useValue: mockLogger },
        {
          provide: Router,
          useValue: {
            createUrlTree: (commands: string[]) => ({ _commands: commands }) as unknown as UrlTree,
          },
        },
      ],
    });
  });

  it('returns true when the user holds the required permission', () => {
    const result = runGuard({ permission: 'roles:read' });
    expect(result).toBe(true);
  });

  it('returns a UrlTree to /access-denied when the user lacks the required permission', () => {
    const result = runGuard({ permission: 'roles:write' });
    const urlTree = result as unknown as { _commands: string[] };
    expect(urlTree._commands).toEqual(['/access-denied']);
  });

  it('fails open (returns true) when data.permission is missing', () => {
    const result = runGuard({});
    expect(result).toBe(true);
  });

  it('fails open (returns true) when data.permission is not a string', () => {
    const result = runGuard({ permission: 42 });
    expect(result).toBe(true);
  });

  it('fails open (returns true) when data.permission is explicitly null', () => {
    // typeof null === 'object', not 'string' — distinct from the missing-key case
    // (undefined) already covered above; asserted separately so a future refactor of
    // the typeof guard to e.g. `required == null` cannot silently regress this branch.
    const result = runGuard({ permission: null });
    expect(result).toBe(true);
  });

  it('fails open (returns true) when data.permission is an empty string', () => {
    const result = runGuard({ permission: '' });
    expect(result).toBe(true);
  });

  it('logs a debug event exactly once on denial, with the permission and query-stripped route path', () => {
    runGuard({ permission: 'roles:write' }, '/gated?from=/dashboard&token=secret');

    expect(mockLogger.debug).toHaveBeenCalledTimes(1);
    expect(mockLogger.debug).toHaveBeenCalledWith('Permission check denied navigation', {
      event: 'permission_denied_client',
      outcome: 'FAILURE',
      context: { permission: 'roles:write', route: '/gated' },
    });
  });

  it('strips the URL fragment (not just the query string) from the logged route on denial', () => {
    // SEC-1 (07-security-review.md): a fragment can carry a token, e.g. after an
    // OAuth-style redirect — must never reach the log, same as the query string.
    runGuard({ permission: 'roles:write' }, '/gated#access_token=secret');

    expect(mockLogger.debug).toHaveBeenCalledWith('Permission check denied navigation', {
      event: 'permission_denied_client',
      outcome: 'FAILURE',
      context: { permission: 'roles:write', route: '/gated' },
    });
  });

  it('does not log anything when access is allowed', () => {
    runGuard({ permission: 'roles:read' });
    expect(mockLogger.debug).not.toHaveBeenCalled();
  });

  it('does not log anything on fail-open', () => {
    runGuard({});
    expect(mockLogger.debug).not.toHaveBeenCalled();
  });
});
