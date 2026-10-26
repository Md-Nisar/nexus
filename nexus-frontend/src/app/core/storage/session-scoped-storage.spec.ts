import { DOCUMENT } from '@angular/common';
import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { LoggerService } from '../logging/logger.service';
import {
  ACCESS_DRAFT_PREFIX,
  SESSION_SCOPED_PREFIX,
  SessionScopedStorage,
} from './session-scoped-storage';

const USER_A = '0190a000-0000-7000-8000-0000000000a1';
const USER_B = '0190a000-0000-7000-8000-0000000000b2';
const ROLE = '0190a000-0000-7000-8000-0000000000c1';

function seed(entries: Record<string, string>): void {
  for (const [key, value] of Object.entries(entries)) sessionStorage.setItem(key, value);
}

function keys(): string[] {
  return Object.keys(sessionStorage).sort();
}

describe('SessionScopedStorage (US-020 design §10; RC-74)', () => {
  afterEach(() => {
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it('names the prefixes the console and the sweep share', () => {
    expect(SESSION_SCOPED_PREFIX).toBe('nexus.session.');
    expect(ACCESS_DRAFT_PREFIX).toBe('nexus.session.access-draft.v1.');
  });

  it('clearSessionScopedStorage removes every nexus.session. key and nothing else', () => {
    seed({
      [`${ACCESS_DRAFT_PREFIX}${USER_A}.${ROLE}`]: '{}',
      'nexus.session.other': 'x',
      'nx-theme': 'dark',
      'nexus.sessionless': 'kept',
      'other.nexus.session.x': 'kept',
    });

    TestBed.inject(SessionScopedStorage).clearSessionScopedStorage();

    expect(keys()).toEqual(['nexus.sessionless', 'nx-theme', 'other.nexus.session.x']);
  });

  it("removeDraftsNotOwnedBy removes another owner's draft keys only (RC-74 item 1)", () => {
    seed({
      [`${ACCESS_DRAFT_PREFIX}${USER_A}.${ROLE}`]: 'a',
      [`${ACCESS_DRAFT_PREFIX}${USER_B}.${ROLE}`]: 'b',
      'nexus.session.other': 'x',
      'nx-theme': 'dark',
    });

    TestBed.inject(SessionScopedStorage).removeDraftsNotOwnedBy(USER_B);

    expect(keys()).toEqual([
      `${ACCESS_DRAFT_PREFIX}${USER_B}.${ROLE}`,
      'nexus.session.other',
      'nx-theme',
    ]);
  });

  it('use() runs against the tab storage and returns its result', () => {
    seed({ 'nexus.session.k': 'v' });
    const value = TestBed.inject(SessionScopedStorage).use(
      (s) => s.getItem('nexus.session.k'),
      null,
    );
    expect(value).toBe('v');
  });

  describe('when the browser refuses storage', () => {
    function refusing(): { storage: SessionScopedStorage; debug: ReturnType<typeof vi.spyOn> } {
      const view = {};
      Object.defineProperty(view, 'sessionStorage', {
        get: () => {
          throw new DOMException('The operation is insecure.', 'SecurityError');
        },
      });
      TestBed.configureTestingModule({
        providers: [{ provide: DOCUMENT, useValue: { defaultView: view } }],
      });
      const debug = vi.spyOn(TestBed.inject(LoggerService), 'debug');
      return { storage: TestBed.inject(SessionScopedStorage), debug };
    }

    it('is a silent no-op with one debug log however often it is used', () => {
      const { storage, debug } = refusing();

      expect(() => storage.clearSessionScopedStorage()).not.toThrow();
      expect(() => storage.removeDraftsNotOwnedBy(USER_A)).not.toThrow();
      expect(storage.use(() => 'never', 'fallback')).toBe('fallback');

      expect(debug).toHaveBeenCalledTimes(1);
      expect(debug.mock.calls[0][1]).toEqual({ event: 'session_storage_unavailable' });
    });

    it('treats a throwing operation the same way', () => {
      const debug = vi.spyOn(TestBed.inject(LoggerService), 'debug');
      const storage = TestBed.inject(SessionScopedStorage);
      vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
        throw new DOMException('Quota exceeded', 'QuotaExceededError');
      });

      expect(storage.use((s) => (s.setItem('nexus.session.k', 'v'), true), false)).toBe(false);
      expect(storage.use((s) => (s.setItem('nexus.session.k', 'v'), true), false)).toBe(false);
      expect(debug).toHaveBeenCalledTimes(1);
    });
  });
});
