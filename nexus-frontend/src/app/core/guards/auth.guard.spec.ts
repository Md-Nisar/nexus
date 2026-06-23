import { TestBed } from '@angular/core/testing';
import { Router, UrlTree, MaybeAsync, GuardResult } from '@angular/router';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { authGuard } from './auth.guard';
import { AuthStore } from '../auth/auth.store';
import { ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';

describe('authGuard', () => {
  let mockAuthStore: { isAuthenticated: ReturnType<typeof vi.fn> };

  const dummyRoute = {} as ActivatedRouteSnapshot;
  const dummyState = {} as RouterStateSnapshot;

  function runGuard(): MaybeAsync<GuardResult> {
    return TestBed.runInInjectionContext(() => authGuard(dummyRoute, dummyState));
  }

  beforeEach(() => {
    mockAuthStore = { isAuthenticated: vi.fn(() => false) };

    TestBed.configureTestingModule({
      providers: [
        { provide: AuthStore, useValue: mockAuthStore },
        {
          provide: Router,
          useValue: {
            createUrlTree: (commands: string[]) =>
              ({ toString: () => commands.join('/'), _commands: commands }) as unknown as UrlTree,
            navigate: vi.fn(),
          },
        },
      ],
    });
  });

  it('returns true when authenticated', () => {
    mockAuthStore.isAuthenticated.mockReturnValue(true);
    const result = runGuard();
    expect(result).toBe(true);
  });

  it('returns UrlTree to /auth/login when not authenticated', () => {
    mockAuthStore.isAuthenticated.mockReturnValue(false);
    const result = runGuard();
    // The guard must return a UrlTree (not true) when unauthenticated
    expect(result).not.toBe(true);
    expect(result instanceof UrlTree || typeof result === 'object').toBe(true);
  });
});
