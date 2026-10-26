import { DestroyRef, Injectable, computed, inject, signal } from '@angular/core';
import { Subscription } from 'rxjs';
import { AuthStore } from '../../../core/auth/auth.store';
import { LoggerService } from '../../../core/logging/logger.service';
import type {
  UserDirectoryEntry,
  UserDirectoryPage,
  UserStatus,
} from '../../../shared/types/api/user-directory';
import { AppError, isAppError } from '../../../shared/types/app-error';
import { DirectoryApi } from '../data/directory-api';
import type { LoadState } from '../data/load-state';
import { createRetryCountdown, retryAfterSeconds } from '../util/retry-after';

/** One view of the directory list: zero-based `page`, `size`, and the status filter or none. */
export interface UsersQuery {
  readonly page: number;
  readonly size: number;
  readonly status: UserStatus | null;
}

/**
 * The exact-email lookup. It holds the result only: the address the user typed is never stored
 * here, in the URL or in a log (SD-13).
 */
export type LookupState =
  | { readonly status: 'idle' }
  | { readonly status: 'loading' }
  | { readonly status: 'hit'; readonly entry: UserDirectoryEntry }
  | { readonly status: 'miss' }
  | { readonly status: 'error'; readonly error: AppError; readonly failedAt: number };

interface OwnedList {
  readonly owner: string | null;
  readonly query: UsersQuery | null;
  readonly state: LoadState<UserDirectoryPage>;
  /** The page shown before the load in flight, kept on screen until the next one arrives. */
  readonly previous: UserDirectoryPage | null;
}

interface OwnedLookup {
  readonly owner: string | null;
  readonly state: LookupState;
}

const IDLE: LoadState<UserDirectoryPage> = { status: 'idle' };
const LOOKUP_IDLE: LookupState = { status: 'idle' };
/** The throttle codes whose wait turns the lookup control off (design §7.4, FR-X2). */
const THROTTLE_CODES: ReadonlySet<string> = new Set(['USER_DIR_001', 'USER_DIR_002']);

function sameQuery(a: UsersQuery | null, b: UsersQuery): boolean {
  return a !== null && a.page === b.page && a.size === b.size && a.status === b.status;
}

function toAppError(error: unknown, message: string): AppError {
  return isAppError(error) ? error : { code: 'UNEXPECTED_ERROR', message };
}

/**
 * The users list and the exact-email lookup (US-020 design §6.2, §6.5, §7.1, §7.4, §12.7).
 *
 * - **List:** one `GET /users` per page view. {@link load} with the query already loading or
 *   loaded sends nothing; a different query cancels the one in flight, and {@link shown} keeps the
 *   previous page until the new one arrives. After a failure the same query loads again (Retry).
 * - **Lookup:** one `POST /users/lookup` per {@link lookup} call; a call while one is in flight,
 *   or while a 429 wait runs, is ignored. A 429 `USER_DIR_001`/`USER_DIR_002` starts
 *   {@link lookupWait} from `Retry-After` (else 30 s); at zero the control is usable again and
 *   nothing is sent by itself (RC-63(l)). The address is a parameter only; it is never kept.
 * - **User change:** both states are keyed by the signed-in user id, so another user never sees
 *   them (design §6.2).
 * - **RC-73:** every failure is caught into `error`; an `AppError` never reaches `ErrorHandler`,
 *   and logs carry codes and ids only, never an address or the lookup text.
 *
 * Provided on the `users` route; not `providedIn: 'root'`.
 *
 * @security UX only. The server decides every request.
 */
@Injectable()
export class UsersListStore {
  private readonly api = inject(DirectoryApi);
  private readonly authStore = inject(AuthStore);
  private readonly logger = inject(LoggerService);

  private readonly list = signal<OwnedList>({
    owner: null,
    query: null,
    state: IDLE,
    previous: null,
  });
  private readonly found = signal<OwnedLookup>({ owner: null, state: LOOKUP_IDLE });
  private listRequest: Subscription | null = null;
  private lookupRequest: Subscription | null = null;

  private readonly currentUserId = computed(() => this.authStore.currentUser()?.userId ?? null);

  /** The list state for the signed-in user; `idle` when it belongs to anyone else. */
  readonly state = computed<LoadState<UserDirectoryPage>>(() => {
    const { owner, state } = this.list();
    return owner !== null && owner === this.currentUserId() ? state : IDLE;
  });

  /**
   * The page to show: the loaded one, or while the next query loads, the one before it, so the
   * table and its paginator (and keyboard focus) stay in place. `null` after a failure.
   */
  readonly shown = computed<UserDirectoryPage | null>(() => {
    const state = this.state();
    if (state.status === 'ready') return state.data;
    return state.status === 'loading' ? this.list().previous : null;
  });

  /** The lookup state for the signed-in user; `idle` when it belongs to anyone else. */
  readonly lookupState = computed<LookupState>(() => {
    const { owner, state } = this.found();
    return owner !== null && owner === this.currentUserId() ? state : LOOKUP_IDLE;
  });

  /** The wait after a throttled lookup; the lookup control is off while it is active. */
  readonly lookupWait = createRetryCountdown(inject(DestroyRef));

  constructor() {
    inject(DestroyRef).onDestroy(() => {
      this.listRequest?.unsubscribe();
      this.lookupRequest?.unsubscribe();
    });
  }

  /** Reads one page of the directory, unless this query is already loading or loaded. */
  load(query: UsersQuery): void {
    const owner = this.currentUserId();
    if (owner === null) return;
    const current = this.list();
    const status = this.state().status;
    if (
      current.owner === owner &&
      sameQuery(current.query, query) &&
      (status === 'loading' || status === 'ready')
    ) {
      return;
    }

    this.listRequest?.unsubscribe();
    const previous = current.owner === owner ? this.shown() : null;
    this.list.set({ owner, query, state: { status: 'loading' }, previous });
    const request = this.api.listUsers({
      page: query.page,
      size: query.size,
      ...(query.status === null ? {} : { status: query.status }),
    });
    this.listRequest = request.subscribe({
      next: (data) =>
        this.list.set({
          owner,
          query,
          state: { status: 'ready', data, loadedAt: Date.now() },
          previous: null,
        }),
      error: (error: unknown) => {
        const appError = toAppError(error, 'The users could not be read.');
        this.logFailure('access_console_users_load_failed', 'load', appError);
        this.list.set({
          owner,
          query,
          state: { status: 'error', error: appError, failedAt: Date.now() },
          previous: null,
        });
      },
    });
  }

  /**
   * Looks up the tenant's user with exactly this address (trimmed). Ignored when blank, while a
   * lookup runs, and while a 429 wait runs.
   */
  lookup(email: string): void {
    const owner = this.currentUserId();
    const address = email.trim();
    if (owner === null || address === '' || this.lookupWait.active()) return;
    if (this.lookupState().status === 'loading') return;

    this.found.set({ owner, state: { status: 'loading' } });
    this.lookupRequest = this.api.lookupUser(address).subscribe({
      next: (response) => {
        const entry = response.data[0];
        this.found.set({
          owner,
          state: entry === undefined ? { status: 'miss' } : { status: 'hit', entry },
        });
      },
      error: (error: unknown) => {
        const appError = toAppError(error, 'The lookup failed.');
        this.logFailure('access_console_user_lookup_failed', 'lookup', appError);
        if (THROTTLE_CODES.has(appError.code)) this.lookupWait.start(retryAfterSeconds(appError));
        this.found.set({
          owner,
          state: { status: 'error', error: appError, failedAt: Date.now() },
        });
      },
    });
  }

  /** Back to the list: forgets the lookup result and cancels a lookup in flight. */
  clearLookup(): void {
    this.lookupRequest?.unsubscribe();
    this.lookupRequest = null;
    this.found.set({ owner: this.currentUserId(), state: LOOKUP_IDLE });
  }

  private logFailure(event: string, action: 'load' | 'lookup', error: AppError): void {
    this.logger.warn('Access console directory request failed', {
      event,
      errorCode: error.code,
      correlationId: error.correlationId,
      context: { area: 'users', action, traceId: error.traceId },
    });
  }
}
