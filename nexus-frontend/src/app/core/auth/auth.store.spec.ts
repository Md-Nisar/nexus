import { TestBed } from '@angular/core/testing';
import { describe, it, expect, beforeEach } from 'vitest';
import { AuthStore } from './auth.store';
import { LoggerService } from '../logging/logger.service';
import { AuthSession } from '../../shared/types/auth';
import { createAuthSession, createAuthUser } from '../../shared/testing/auth.fixtures';

// eslint-disable-next-line @typescript-eslint/no-empty-function
const mockLogger = { debug: () => {} };

/**
 * A valid session with non-expired access token.
 *
 * Used across all test cases to verify session storage, computed signal updates,
 * and authentication status.
 */
const TEST_SESSION: AuthSession = createAuthSession({
  user: createAuthUser({
    userId: 'user-123',
    tenantId: 'tenant-456',
    roles: ['USER'],
    permissions: ['users:read'],
  }),
});

/**
 * AuthStore — reactive session management via Angular signals.
 *
 * Verifies that the store correctly manages session state through `setSession()` and
 * `clearSession()`, and that computed signals (`isAuthenticated`, `currentUser`, `accessToken`)
 * reflect the current session state.
 */
describe('AuthStore', () => {
  let store: AuthStore;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [AuthStore, { provide: LoggerService, useValue: mockLogger }],
    });
    store = TestBed.inject(AuthStore);
  });

  it('isAuthenticated() returns false with no session', () => {
    expect(store.isAuthenticated()).toBe(false);
  });

  it('isAuthenticated() returns true after setSession()', () => {
    store.setSession(TEST_SESSION);
    expect(store.isAuthenticated()).toBe(true);
  });

  it('setSession() updates currentUser signal', () => {
    store.setSession(TEST_SESSION);
    expect(store.currentUser()).toEqual(TEST_SESSION.user);
  });

  it('clearSession() resets session to null', () => {
    store.setSession(TEST_SESSION);
    store.clearSession();
    expect(store.isAuthenticated()).toBe(false);
    expect(store.currentUser()).toBeNull();
  });

  it('accessToken() returns null when no session', () => {
    expect(store.accessToken()).toBeNull();
  });

  it('accessToken() returns token value after setSession()', () => {
    store.setSession(TEST_SESSION);
    expect(store.accessToken()).toBe('test-access-token');
  });

  it('permissions() returns an empty array when no session', () => {
    expect(store.permissions()).toEqual([]);
  });

  it("permissions() returns the session user's permissions after setSession()", () => {
    store.setSession(TEST_SESSION);
    expect(store.permissions()).toEqual(['users:read']);
  });

  it('permissions() returns a stable reference across calls when no session', () => {
    // Verifies the frozen NO_PERMISSIONS constant is reused, not a fresh array per call —
    // downstream computed()/effect() consumers rely on this reference stability.
    expect(store.permissions()).toBe(store.permissions());
  });

  it('permissions() reuses the same frozen empty-array reference after a session is set and cleared', () => {
    // Calling permissions() twice with no session ever set could pass merely because
    // computed() caches its result — it doesn't prove NO_PERMISSIONS is a genuinely
    // shared module-level constant. Driving a real session set/clear transition in
    // between proves the empty-array reference is the same constant both before and
    // after, not just memoized within one no-session period.
    const before = store.permissions();
    store.setSession(TEST_SESSION);
    store.clearSession();
    expect(store.permissions()).toBe(before);
  });
});
