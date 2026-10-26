import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LoggerService } from '../../../core/logging/logger.service';
import { DRAFT_MAX_AGE_MS, DRAFT_MAX_ENTRIES, DraftStorage, RoleDraft } from './draft-storage';

const USER_A = '0190a000-0000-7000-8000-0000000000a1';
const USER_B = '0190a000-0000-7000-8000-0000000000b2';
const ROLE = '0190a000-0000-7000-8000-0000000000c1';
const P1 = '0190a000-0000-7000-8000-000000000101';
const P2 = '0190a000-0000-7000-8000-000000000102';
const P3 = '0190a000-0000-7000-8000-000000000103';
const CATALOGUE: ReadonlySet<string> = new Set([P1, P2, P3]);
const KEY = `nexus.session.access-draft.v1.${USER_A}.${ROLE}`;
const NOW = Date.parse('2026-10-24T12:00:00Z');

function draft(overrides: Partial<RoleDraft> = {}): RoleDraft {
  return { add: [P1], remove: [P2], baseEtag: '"v1"', savedAt: NOW - 60_000, ...overrides };
}

describe('DraftStorage (US-020 design §10; RC-74; D-6)', () => {
  let drafts: DraftStorage;
  let debug: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
    debug = vi.spyOn(TestBed.inject(LoggerService), 'debug');
    drafts = TestBed.inject(DraftStorage);
  });

  afterEach(() => {
    sessionStorage.clear();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('stores ids, the base tag and the time only, under the user and role key', () => {
    drafts.write(USER_A, ROLE, draft());

    expect(Object.keys(sessionStorage)).toEqual([KEY]);
    expect(JSON.parse(sessionStorage.getItem(KEY) as string)).toEqual({
      v: 1,
      add: [P1],
      remove: [P2],
      baseEtag: '"v1"',
      savedAt: NOW - 60_000,
    });
  });

  it('reads back what it wrote', () => {
    drafts.write(USER_A, ROLE, draft({ baseEtag: null }));
    expect(drafts.read(USER_A, ROLE, CATALOGUE)).toEqual(draft({ baseEtag: null }));
  });

  it('gives null when there is no draft, without logging', () => {
    expect(drafts.read(USER_A, ROLE, CATALOGUE)).toBeNull();
    expect(debug).not.toHaveBeenCalled();
  });

  it("gives another user nothing of a user's draft (SD-16)", () => {
    drafts.write(USER_A, ROLE, draft());

    expect(drafts.read(USER_B, ROLE, CATALOGUE)).toBeNull();
    expect(sessionStorage.getItem(KEY)).not.toBeNull();
  });

  it('clear removes the key', () => {
    drafts.write(USER_A, ROLE, draft());
    drafts.clear(USER_A, ROLE);
    expect(sessionStorage.getItem(KEY)).toBeNull();
  });

  it('clears instead of storing more than the read limit allows', () => {
    drafts.write(USER_A, ROLE, draft());
    const many = Array.from(
      { length: DRAFT_MAX_ENTRIES + 1 },
      (_, i) => `0190a000-0000-7000-8000-${String(i).padStart(12, '0')}`,
    );
    drafts.write(USER_A, ROLE, draft({ add: many, remove: [] }));
    expect(sessionStorage.getItem(KEY)).toBeNull();
  });

  describe('treats storage as untrusted: anything invalid deletes the key', () => {
    const valid = { v: 1, add: [P1], remove: [P2], baseEtag: '"v1"', savedAt: NOW - 60_000 };
    const cases: readonly (readonly [string, string])[] = [
      ['invalid JSON', '{not json'],
      ['a non-object', '[1,2]'],
      ['the wrong version', JSON.stringify({ ...valid, v: 2 })],
      ['a non-UUID', JSON.stringify({ ...valid, add: ['role:write'] })],
      ['an upper-case UUID', JSON.stringify({ ...valid, add: [P1.toUpperCase()] })],
      [
        'an id outside the catalogue',
        JSON.stringify({ ...valid, add: ['0190a000-0000-7000-8000-000000000999'] }),
      ],
      ['a duplicate id', JSON.stringify({ ...valid, add: [P1, P1] })],
      ['an id both added and removed', JSON.stringify({ ...valid, remove: [P1] })],
      ['a non-array', JSON.stringify({ ...valid, add: P1 })],
      ['a non-string tag', JSON.stringify({ ...valid, baseEtag: 7 })],
      ['an extra field', JSON.stringify({ ...valid, name: 'Support' })],
      ['a missing savedAt', JSON.stringify({ ...valid, savedAt: undefined })],
      ['an expired draft', JSON.stringify({ ...valid, savedAt: NOW - DRAFT_MAX_AGE_MS - 1 })],
      ['a future savedAt (D-6)', JSON.stringify({ ...valid, savedAt: NOW + 1 })],
    ];

    for (const [name, raw] of cases) {
      it(name, () => {
        sessionStorage.setItem(KEY, raw);

        expect(drafts.read(USER_A, ROLE, CATALOGUE)).toBeNull();
        expect(sessionStorage.getItem(KEY)).toBeNull();
        expect(debug).toHaveBeenCalledWith(expect.any(String), {
          event: 'access_console_draft_discarded_invalid',
          context: { roleId: ROLE },
        });
      });
    }

    it('more than 100 ids in total', () => {
      const ids = Array.from(
        { length: DRAFT_MAX_ENTRIES + 1 },
        (_, i) => `0190a000-0000-7000-8000-${String(i).padStart(12, '0')}`,
      );
      sessionStorage.setItem(KEY, JSON.stringify({ ...valid, add: ids, remove: [] }));

      expect(drafts.read(USER_A, ROLE, new Set(ids))).toBeNull();
      expect(sessionStorage.getItem(KEY)).toBeNull();
    });

    it('accepts exactly 100 ids and exactly 12 hours', () => {
      const ids = Array.from(
        { length: DRAFT_MAX_ENTRIES },
        (_, i) => `0190a000-0000-7000-8000-${String(i).padStart(12, '0')}`,
      );
      const edge = { ...valid, add: ids, remove: [], savedAt: NOW - DRAFT_MAX_AGE_MS };
      sessionStorage.setItem(KEY, JSON.stringify(edge));

      expect(drafts.read(USER_A, ROLE, new Set(ids))?.add).toHaveLength(DRAFT_MAX_ENTRIES);
    });
  });

  it('is a silent no-op when storage throws', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('denied', 'SecurityError');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('Quota exceeded', 'QuotaExceededError');
    });
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => {
      throw new DOMException('denied', 'SecurityError');
    });

    expect(() => drafts.write(USER_A, ROLE, draft())).not.toThrow();
    expect(drafts.read(USER_A, ROLE, CATALOGUE)).toBeNull();
    expect(() => drafts.clear(USER_A, ROLE)).not.toThrow();
    expect(debug).toHaveBeenCalledTimes(1);
  });

  it('refuses ids that would break the key format', () => {
    drafts.write('user.with.dots', ROLE, draft());
    drafts.write(USER_A, 'role.with.dots', draft());
    expect(Object.keys(sessionStorage)).toEqual([]);
    expect(drafts.read('user.with.dots', ROLE, CATALOGUE)).toBeNull();
  });
});
