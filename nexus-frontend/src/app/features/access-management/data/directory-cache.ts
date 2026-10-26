import { Injectable, computed, inject, linkedSignal } from '@angular/core';
import { AuthStore } from '../../../core/auth/auth.store';
import type { UserDirectoryEntry } from '../../../shared/types/api/user-directory';

interface OwnedAddresses {
  readonly owner: string | null;
  readonly byId: ReadonlyMap<string, string>;
}

const EMPTY: ReadonlyMap<string, string> = new Map();

/** Addresses held at most; the least recently received go first (MN-6). */
const MAX_ADDRESSES = 500;

/**
 * The addresses of directory entries the caller has already received in this console session:
 * the users-list pages, a lookup hit and the user page's own read (US-020 design §12.8; FR-X5).
 * The user page shows an "Assigned by" id as an address only when it is held here.
 *
 * - **Never fetches** (threat model C10): nothing is requested to fill it, so an address appears
 *   only where the caller's own directory permission already returned it.
 * - **Owner-keyed** (design §6.2): addresses are held for the signed-in user id they were received
 *   under; another user, or a signed-out session, sees none, and a change of user drops them.
 * - **Bounded:** at most {@link MAX_ADDRESSES}; receiving an address again makes it the newest.
 * - **Lifetime:** provided on the console's layout route, so it outlives the users list (whose
 *   store is scoped to the `users` route) and ends with the console. In memory only; never
 *   written to storage, a URL or a log.
 */
@Injectable()
export class DirectoryCache {
  private readonly authStore = inject(AuthStore);
  private readonly currentUserId = computed(() => this.authStore.currentUser()?.userId ?? null);
  /** Reset whenever the signed-in user changes, so no address outlives its owner's session. */
  private readonly held = linkedSignal<string | null, OwnedAddresses>({
    source: this.currentUserId,
    computation: (owner) => ({ owner, byId: EMPTY }),
  });
  private readonly mine = computed(() => {
    const { owner, byId } = this.held();
    return owner !== null && owner === this.currentUserId() ? byId : EMPTY;
  });

  /** Holds the address of each entry by user id; the newest address for an id wins. */
  remember(entries: readonly UserDirectoryEntry[]): void {
    const owner = this.currentUserId();
    if (owner === null || entries.length === 0) return;
    const byId = new Map(this.mine());
    for (const entry of entries) {
      // Re-inserted, so insertion order is recency order.
      byId.delete(entry.userId);
      byId.set(entry.userId, entry.email);
    }
    for (const oldest of byId.keys()) {
      if (byId.size <= MAX_ADDRESSES) break;
      byId.delete(oldest);
    }
    this.held.set({ owner, byId });
  }

  /** The address held for `userId`, or `null`. Reactive when read in a template or `computed`. */
  email(userId: string): string | null {
    return this.mine().get(userId) ?? null;
  }
}
