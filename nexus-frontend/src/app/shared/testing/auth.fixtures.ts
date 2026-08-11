import { computed, signal, Signal, WritableSignal } from '@angular/core';
import { AuthSession, AuthUser } from '../types/auth';

/**
 * Builds an {@link AuthUser} with sensible defaults and per-test overrides.
 *
 * Single source of truth for the user test shape: adding a field to `AuthUser` should be
 * a one-line change here, not a fan-out across every spec.
 */
export function createAuthUser(overrides: Partial<AuthUser> = {}): AuthUser {
  return {
    userId: 'user-123',
    tenantId: 'tenant-456',
    emailVerified: true,
    roles: ['USER'],
    permissions: [],
    tokenVersion: 1,
    ...overrides,
  };
}

/**
 * Builds a valid, unexpired {@link AuthSession}.
 *
 * `user` may be overridden wholesale, or shaped via {@link createAuthUser}.
 */
export function createAuthSession(overrides: Partial<AuthSession> = {}): AuthSession {
  return {
    accessToken: 'test-access-token',
    tokenType: 'Bearer',
    expiresIn: 3600,
    expiresAt: Date.now() + 3600 * 1000,
    user: createAuthUser(),
    ...overrides,
  };
}

/** Read-side stub of AuthStore, backed by real signals so tests can drive reactivity. */
export interface AuthStoreStub {
  readonly session: WritableSignal<AuthSession | null>;
  readonly permissions: WritableSignal<readonly string[]>;
  readonly currentUser: Signal<AuthUser | null>;
  readonly accessToken: Signal<string | null>;
  readonly isAuthenticated: Signal<boolean>;
}

/**
 * Creates a read-side AuthStore stub for `{ provide: AuthStore, useValue: … }`.
 *
 * `permissions` is a real `WritableSignal`, so a test can call `.set([...])` and assert
 * that a consumer (guard, directive) reacts — which is exactly what US-013's
 * reactive-update scenario needs and what a `vi.fn()` mock cannot express.
 *
 * Write-side members (`setSession`, `clearSession`) are intentionally absent: specs that
 * assert on those should spread this stub and add their own spies, keeping this module
 * free of any test-framework import (see the file-level constraint below).
 */
export function createAuthStoreStub(
  init: { session?: AuthSession | null; permissions?: readonly string[] } = {},
): AuthStoreStub {
  const session = signal<AuthSession | null>(init.session ?? null);
  const permissions = signal<readonly string[]>(
    init.permissions ?? init.session?.user.permissions ?? [],
  );
  return {
    session,
    permissions,
    currentUser: computed(() => session()?.user ?? null),
    accessToken: computed(() => session()?.accessToken ?? null),
    isAuthenticated: computed(() => {
      const s = session();
      return s !== null && Date.now() < s.expiresAt;
    }),
  };
}
