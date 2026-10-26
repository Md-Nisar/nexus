import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { AuthStore } from '../../../core/auth/auth.store';
import type { PermissionResponse, RoleResponse } from '../../../shared/types/api/rbac';
import { CloneSourceCache } from './clone-source';

const ROLE: RoleResponse = {
  id: '0190a000-0000-7000-8000-0000000000c1',
  name: 'Support',
  description: 'Handles tickets',
  isSystemRole: false,
  createdAt: '2026-01-01T00:00:00Z',
  memberCount: 3,
  permissionCount: 1,
};

const SET: readonly PermissionResponse[] = [
  {
    id: '0190a000-0000-7000-8000-000000000104',
    name: 'role:read',
    description: 'd',
    isSensitive: false,
  },
];

describe('CloneSourceCache (design §6.5 "Create": the source read is reused)', () => {
  const userId = signal<string | null>('user-1');
  let cache: CloneSourceCache;

  beforeEach(() => {
    userId.set('user-1');
    TestBed.configureTestingModule({
      providers: [
        {
          provide: AuthStore,
          useValue: {
            currentUser: () => (userId() === null ? null : { userId: userId() }),
          },
        },
      ],
    });
    cache = TestBed.inject(CloneSourceCache);
  });

  it('gives the offered role and set back once, for that role', () => {
    cache.offer(ROLE, SET);
    expect(cache.take(ROLE.id)).toEqual({ role: ROLE, permissions: SET });
    expect(cache.take(ROLE.id)).toBeNull();
  });

  it('gives nothing for another role, and drops the entry', () => {
    cache.offer(ROLE, SET);
    expect(cache.take('0190a000-0000-7000-8000-0000000000c2')).toBeNull();
    expect(cache.take(ROLE.id)).toBeNull();
  });

  it('never gives one user what another user offered', () => {
    cache.offer(ROLE, SET);
    userId.set('user-2');
    expect(cache.take(ROLE.id)).toBeNull();
  });

  it('keeps nothing while signed out', () => {
    userId.set(null);
    cache.offer(ROLE, SET);
    userId.set('user-1');
    expect(cache.take(ROLE.id)).toBeNull();
  });
});
