import { Service, inject } from '@angular/core';
import { LoggerService } from '../../../core/logging/logger.service';
import {
  ACCESS_DRAFT_PREFIX,
  SessionScopedStorage,
} from '../../../core/storage/session-scoped-storage';

/** A draft older than this is discarded on read (design §10). */
export const DRAFT_MAX_AGE_MS = 12 * 60 * 60 * 1000;

/** At most this many ids, added and removed together (design §10). */
export const DRAFT_MAX_ENTRIES = 100;

/** A role editor's unsaved work: permission ids, the tag it was staged on, and when. */
export interface RoleDraft {
  readonly add: readonly string[];
  readonly remove: readonly string[];
  /** The strong tag the work was staged on. Only ever compared; never sent as `If-Match`. */
  readonly baseEtag: string | null;
  /** Epoch milliseconds of the last change. */
  readonly savedAt: number;
}

const VERSION = 1;
const FIELDS = ['add', 'baseEtag', 'remove', 'savedAt', 'v'];
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Role-editor drafts in `sessionStorage` (US-020 design §10; RC-74; D-6), so staged work survives
 * a session expiry or a reload in this tab.
 *
 * - **Key** `nexus.session.access-draft.v1.<userId>.<roleId>`; **value**
 *   `{ v: 1, add, remove, baseEtag, savedAt }`: ids, a tag and a time only. Never a name, a
 *   description, a label or an address (SD-16).
 * - **Read** treats storage as untrusted: the exact shape, `v === 1`, canonical UUIDs that are all
 *   in the catalogue, no duplicates or overlap, at most 100, and `savedAt` neither in the future
 *   (D-6) nor older than 12 h. Anything else deletes the key.
 * - A read is per user id, so one user is never given another user's draft. `AuthService` also
 *   removes other users' drafts when a session starts, and every draft on logout.
 * - Storage may be unavailable; drafts are then silently off ({@link SessionScopedStorage}).
 */
@Service()
export class DraftStorage {
  private readonly storage = inject(SessionScopedStorage);
  private readonly logger = inject(LoggerService);

  /** Stores `draft`; a draft the read would reject for its size is cleared instead. */
  write(userId: string, roleId: string, draft: RoleDraft): void {
    const key = keyOf(userId, roleId);
    if (key === null) return;
    if (draft.add.length + draft.remove.length > DRAFT_MAX_ENTRIES) {
      this.clear(userId, roleId);
      return;
    }
    const value = JSON.stringify({
      v: VERSION,
      add: draft.add,
      remove: draft.remove,
      baseEtag: draft.baseEtag,
      savedAt: draft.savedAt,
    });
    this.storage.use((storage) => storage.setItem(key, value), undefined);
  }

  /** The user's valid draft for the role, or `null`; an invalid one is deleted. */
  read(userId: string, roleId: string, catalogueIds: ReadonlySet<string>): RoleDraft | null {
    const key = keyOf(userId, roleId);
    if (key === null) return null;
    const raw = this.storage.use((storage) => storage.getItem(key), null);
    if (raw === null) return null;
    const draft = parseDraft(raw, catalogueIds, Date.now());
    if (draft === null) {
      this.storage.use((storage) => storage.removeItem(key), undefined);
      this.logger.debug('Access console discarded an invalid draft', {
        event: 'access_console_draft_discarded_invalid',
        context: { roleId },
      });
    }
    return draft;
  }

  clear(userId: string, roleId: string): void {
    const key = keyOf(userId, roleId);
    if (key === null) return;
    this.storage.use((storage) => storage.removeItem(key), undefined);
  }
}

/** The key, or `null` for an id that would make the owner unreadable from the key. */
function keyOf(userId: string, roleId: string): string | null {
  if (userId === '' || roleId === '' || userId.includes('.') || roleId.includes('.')) return null;
  return `${ACCESS_DRAFT_PREFIX}${userId}.${roleId}`;
}

function parseDraft(raw: string, catalogueIds: ReadonlySet<string>, now: number): RoleDraft | null {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join() !== FIELDS.join()) return null;
  const { v, add, remove, baseEtag, savedAt } = record;
  if (v !== VERSION) return null;
  if (baseEtag !== null && typeof baseEtag !== 'string') return null;
  if (typeof savedAt !== 'number' || !Number.isFinite(savedAt)) return null;
  if (savedAt > now || now - savedAt > DRAFT_MAX_AGE_MS) return null;
  if (!isIdList(add, catalogueIds) || !isIdList(remove, catalogueIds)) return null;
  if (add.length + remove.length > DRAFT_MAX_ENTRIES) return null;
  const all = new Set([...add, ...remove]);
  if (all.size !== add.length + remove.length) return null;
  return { add, remove, baseEtag, savedAt };
}

function isIdList(value: unknown, catalogueIds: ReadonlySet<string>): value is string[] {
  return (
    Array.isArray(value) &&
    value.every(
      (id): id is string =>
        typeof id === 'string' && CANONICAL_UUID.test(id) && catalogueIds.has(id),
    )
  );
}
