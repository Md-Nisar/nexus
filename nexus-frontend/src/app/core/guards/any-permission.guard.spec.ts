import { TestBed } from '@angular/core/testing';
import {
  ActivatedRouteSnapshot,
  GuardResult,
  MaybeAsync,
  Router,
  RouterStateSnapshot,
  UrlTree,
} from '@angular/router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthStore } from '../auth/auth.store';
import { LoggerService } from '../logging/logger.service';
import { PERMISSIONS } from '../../shared/types/permission';
import { createAuthStoreStub } from '../../shared/testing/auth.fixtures';
import { anyPermissionGuard } from './any-permission.guard';

const DENIED = { _commands: ['/access-denied'] } as unknown as UrlTree;

/**
 * anyPermissionGuard: UX-only, fail-closed any-of route gate (US-020 design §4.3).
 *
 * Verifies: allow through any member, deny with a bare `/access-denied` UrlTree, deny (without
 * reading the store) on every malformed `data.anyOf`, and a single path-only error log for the
 * misconfiguration.
 */
describe('anyPermissionGuard', () => {
  let createUrlTree: ReturnType<typeof vi.fn>;
  let logger: { error: ReturnType<typeof vi.fn>; debug: ReturnType<typeof vi.fn> };

  function configure(store: unknown): void {
    TestBed.configureTestingModule({
      providers: [
        { provide: AuthStore, useValue: store },
        { provide: LoggerService, useValue: logger },
        { provide: Router, useValue: { createUrlTree } },
      ],
    });
  }

  function runGuard(data: Record<string, unknown>, url = '/admin/access'): MaybeAsync<GuardResult> {
    const route = { data } as unknown as ActivatedRouteSnapshot;
    const state = { url } as RouterStateSnapshot;
    return TestBed.runInInjectionContext(() => anyPermissionGuard(route, state));
  }

  beforeEach(() => {
    createUrlTree = vi.fn((commands: string[]) => ({ _commands: commands }) as unknown as UrlTree);
    logger = { error: vi.fn(), debug: vi.fn() };
  });

  describe('with a valid data.anyOf', () => {
    const data = { anyOf: ['role:read', 'user:directory:read'] };

    it('allows a user holding the first member', () => {
      configure(createAuthStoreStub({ permissions: ['role:read'] }));
      expect(runGuard(data)).toBe(true);
    });

    it('allows a user holding only the second member', () => {
      configure(createAuthStoreStub({ permissions: ['user:directory:read'] }));
      expect(runGuard(data)).toBe(true);
    });

    it('redirects to /access-denied with no query params when the user holds neither', () => {
      configure(createAuthStoreStub({ permissions: ['user:read', 'role:write'] }));
      expect(runGuard(data)).toEqual(DENIED);
      expect(createUrlTree).toHaveBeenCalledTimes(1);
      expect(createUrlTree.mock.calls[0]).toEqual([['/access-denied']]);
    });

    it('redirects to /access-denied when the user holds no permissions', () => {
      configure(createAuthStoreStub({ permissions: [] }));
      expect(runGuard(data)).toEqual(DENIED);
      expect(createUrlTree.mock.calls[0]).toEqual([['/access-denied']]);
    });

    it('logs nothing when access is allowed', () => {
      configure(createAuthStoreStub({ permissions: ['role:read'] }));
      runGuard(data);
      expect(logger.error).not.toHaveBeenCalled();
      expect(logger.debug).not.toHaveBeenCalled();
    });

    it('logs nothing on a plain denial (C-3)', () => {
      configure(createAuthStoreStub({ permissions: [] }));
      runGuard(data);
      expect(logger.error).not.toHaveBeenCalled();
      expect(logger.debug).not.toHaveBeenCalled();
    });
  });

  describe('fails closed on a misconfigured data.anyOf', () => {
    it.each([
      ['a missing key', {}],
      ['null', { anyOf: null }],
      ['an empty array', { anyOf: [] }],
      ['a bare string', { anyOf: 'role:read' }],
      ['an array-like object', { anyOf: { 0: 'role:read', length: 1 } }],
      ['a non-catalogue member', { anyOf: ['roles:read'] }],
      ['a catalogue member mixed with a non-catalogue one', { anyOf: ['role:read', 'bogus'] }],
      ['a nested array', { anyOf: [['role:read']] }],
      ['a non-string member', { anyOf: [42] }],
    ])('denies even a user holding every permission when data.anyOf is %s', (_name, data) => {
      const permissions = vi.fn(() => PERMISSIONS);
      configure({ ...createAuthStoreStub(), permissions });

      expect(runGuard(data)).toEqual(DENIED);
      expect(createUrlTree.mock.calls).toEqual([[['/access-denied']]]);
      expect(permissions).not.toHaveBeenCalled();
      expect(logger.error).toHaveBeenCalledTimes(1);
    });

    it('logs any_permission_guard_misconfigured once, with the path only', () => {
      configure(createAuthStoreStub({ permissions: [...PERMISSIONS] }));

      runGuard({ anyOf: ['role:read', 'bogus-value'] }, '/admin/access?returnUrl=x&token=s#frag');

      expect(logger.error).toHaveBeenCalledTimes(1);
      expect(logger.error).toHaveBeenCalledWith(expect.any(String), {
        event: 'any_permission_guard_misconfigured',
        outcome: 'FAILURE',
        context: { route: '/admin/access' },
      });
      const logged = JSON.stringify(logger.error.mock.calls);
      expect(logged).not.toContain('bogus-value');
      expect(logged).not.toContain('returnUrl');
      expect(logged).not.toContain('token');
      expect(logged).not.toContain('frag');
    });

    it('strips a fragment as well as a query from the logged path', () => {
      configure(createAuthStoreStub());

      runGuard({}, '/admin/access#access_token=secret');

      expect(logger.error).toHaveBeenCalledWith(expect.any(String), {
        event: 'any_permission_guard_misconfigured',
        outcome: 'FAILURE',
        context: { route: '/admin/access' },
      });
    });
  });
});
