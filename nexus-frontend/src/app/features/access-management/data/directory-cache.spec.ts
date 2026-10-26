import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { AuthStore } from '../../../core/auth/auth.store';
import {
  AuthStoreStub,
  createAuthSession,
  createAuthStoreStub,
  createAuthUser,
} from '../../../shared/testing/auth.fixtures';
import type { UserDirectoryEntry } from '../../../shared/types/api/user-directory';
import { DirectoryCache } from './directory-cache';

const USER_A = '0190a000-0000-7000-8000-000000000001';
const USER_B = '0190a000-0000-7000-8000-000000000002';

function entry(userId: string, email: string): UserDirectoryEntry {
  return {
    userId,
    email,
    status: 'ACTIVE',
    emailVerified: true,
    createdAt: '2026-01-01T00:00:00Z',
  };
}

describe('DirectoryCache (US-020 design §12.8, FR-X5)', () => {
  let cache: DirectoryCache;
  let authStore: AuthStoreStub;

  beforeEach(() => {
    authStore = createAuthStoreStub({
      session: createAuthSession({ user: createAuthUser({ userId: 'caller-1' }) }),
    });
    TestBed.configureTestingModule({
      providers: [{ provide: AuthStore, useValue: authStore }, DirectoryCache],
    });
    cache = TestBed.inject(DirectoryCache);
  });

  it('gives the address of an entry it was handed, by user id', () => {
    cache.remember([entry(USER_A, 'first@cache.invalid'), entry(USER_B, 'second@cache.invalid')]);

    expect(cache.email(USER_A)).toBe('first@cache.invalid');
    expect(cache.email(USER_B)).toBe('second@cache.invalid');
  });

  it('gives null for an id it was never handed: it never fetches one', () => {
    cache.remember([entry(USER_A, 'first@cache.invalid')]);

    expect(cache.email(USER_B)).toBeNull();
  });

  it('keeps the newest address for an id seen twice', () => {
    cache.remember([entry(USER_A, 'old@cache.invalid')]);
    cache.remember([entry(USER_A, 'new@cache.invalid')]);

    expect(cache.email(USER_A)).toBe('new@cache.invalid');
  });

  it('shows nothing to another signed-in user, and starts empty for them (design §6.2)', () => {
    cache.remember([entry(USER_A, 'first@cache.invalid')]);

    authStore.session.set(createAuthSession({ user: createAuthUser({ userId: 'caller-2' }) }));
    expect(cache.email(USER_A)).toBeNull();

    cache.remember([entry(USER_B, 'second@cache.invalid')]);
    authStore.session.set(createAuthSession({ user: createAuthUser({ userId: 'caller-1' }) }));
    expect(cache.email(USER_A)).toBeNull();
    expect(cache.email(USER_B)).toBeNull();
  });

  it('remembers nothing while signed out', () => {
    authStore.session.set(null);
    cache.remember([entry(USER_A, 'first@cache.invalid')]);

    authStore.session.set(createAuthSession({ user: createAuthUser({ userId: 'caller-1' }) }));
    expect(cache.email(USER_A)).toBeNull();
  });
});
