import { DOCUMENT } from '@angular/common';
import { Service, inject } from '@angular/core';
import { LoggerService } from '../logging/logger.service';

/** Every `sessionStorage` key that belongs to the signed-in session starts with this. */
export const SESSION_SCOPED_PREFIX = 'nexus.session.';

/**
 * Access-console drafts: `nexus.session.access-draft.v1.<userId>.<roleId>` (US-020 design §10). It
 * lives here, not in the console, so that `AuthService` can sweep drafts without importing a feature.
 */
export const ACCESS_DRAFT_PREFIX = `${SESSION_SCOPED_PREFIX}access-draft.v1.`;

/**
 * The tab's `sessionStorage`, for state that belongs to one signed-in session (US-020 design §10;
 * RC-74, D-6).
 *
 * - Storage is optional: reading `sessionStorage` itself can throw (disabled storage, sandboxed
 *   frames), and so can any operation (quota, private mode). Every access goes through
 *   {@link use}, which catches, returns the fallback, and logs one debug line per app lifetime.
 * - {@link clearSessionScopedStorage} is for explicit logout only. It must never run on
 *   `AuthStore.clearSession()`, which also runs when a refresh fails: a draft must survive a
 *   session expiry so the same user can restore it after signing in again (FR-G4).
 */
@Service()
export class SessionScopedStorage {
  private readonly document = inject(DOCUMENT);
  private readonly logger = inject(LoggerService);
  private reported = false;

  /** Runs `operation` on the tab's storage; any failure gives `fallback`. */
  use<T>(operation: (storage: Storage) => T, fallback: T): T {
    try {
      const storage = this.document.defaultView?.sessionStorage;
      return storage === undefined ? fallback : operation(storage);
    } catch {
      if (!this.reported) {
        this.reported = true;
        this.logger.debug('Session storage is unavailable; drafts are off', {
          event: 'session_storage_unavailable',
        });
      }
      return fallback;
    }
  }

  /** Removes every key starting with `nexus.session.`, and nothing else. */
  clearSessionScopedStorage(): void {
    this.removeWhere((key) => key.startsWith(SESSION_SCOPED_PREFIX));
  }

  /**
   * Removes the access-console drafts of every user other than `userId` (RC-74 item 1): another
   * user's draft ids must not linger in a tab someone else signed in to.
   */
  removeDraftsNotOwnedBy(userId: string): void {
    this.removeWhere(
      (key) =>
        key.startsWith(ACCESS_DRAFT_PREFIX) &&
        key.slice(ACCESS_DRAFT_PREFIX.length).split('.')[0] !== userId,
    );
  }

  private removeWhere(matches: (key: string) => boolean): void {
    this.use((storage) => {
      const doomed: string[] = [];
      for (let index = 0; index < storage.length; index++) {
        const key = storage.key(index);
        if (key !== null && matches(key)) doomed.push(key);
      }
      for (const key of doomed) storage.removeItem(key);
    }, undefined);
  }
}
