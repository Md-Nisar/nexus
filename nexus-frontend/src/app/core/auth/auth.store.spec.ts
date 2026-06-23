import { TestBed } from '@angular/core/testing';
import { describe, it, expect, beforeEach } from 'vitest';
import { AuthStore } from './auth.store';
import { LoggerService } from '../logging/logger.service';
import { AuthSession } from '../../shared/types/auth';

// eslint-disable-next-line @typescript-eslint/no-empty-function
const mockLogger = { debug: () => {} };

const TEST_SESSION: AuthSession = {
  accessToken: 'test-access-token',
  tokenType: 'Bearer',
  expiresIn: 3600,
  expiresAt: Date.now() + 3600 * 1000,
  user: {
    userId: 'user-123',
    tenantId: 'tenant-456',
    emailVerified: true,
    roles: ['USER'],
    tokenVersion: 1,
  },
};

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
});
