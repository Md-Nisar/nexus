import { DestroyRef, Injectable, computed, inject, signal } from '@angular/core';
import { Subscription, forkJoin, tap } from 'rxjs';
import { AuthStore } from '../../../core/auth/auth.store';
import { LoggerService } from '../../../core/logging/logger.service';
import type { RoleListResponse, RoleResponse } from '../../../shared/types/api/rbac';
import { AppError, isAppError } from '../../../shared/types/app-error';
import type { LoadState } from './load-state';
import { RbacApi } from './rbac-api';

/** Roles per request: the server's maximum page size (design §6.4). */
const PAGE_SIZE = 100;
/** Hard bound on pages fetched, i.e. 2000 roles, four times the default role cap (DQ-12). */
const MAX_PAGES = 20;

/** Every role of the tenant, as far as the bound allows. */
export interface RolesData {
  /** In the server's `(name, id)` order. */
  readonly roles: readonly RoleResponse[];
  /** Roles the server reports; greater than `roles.length` only when {@link truncated}. */
  readonly total: number;
  /** True when the tenant has more than {@link MAX_PAGES} pages; search then covers a subset. */
  readonly truncated: boolean;
}

/** How much of a running load has arrived, for "Loading roles: {loaded} of {total}". */
export interface RolesProgress {
  readonly loaded: number;
  readonly total: number;
}

interface OwnedState {
  readonly owner: string | null;
  readonly state: LoadState<RolesData>;
}

const IDLE: LoadState<RolesData> = { status: 'idle' };
const LOADING: LoadState<RolesData> = { status: 'loading' };

/**
 * All roles of the tenant for the roles list and, later, the user page's role join (US-020 design
 * §6.4, §6.5). Search, filter and order run client-side over this list.
 *
 * - **Fetch-all:** page 0 first (it carries the page count), then pages 1 to
 *   `min(totalPages, 20) - 1` in parallel. That is ⌈total/100⌉ requests, at most 20.
 * - **All or nothing:** any failing page fails the whole load and cancels the others. A partial
 *   list that looks complete would be a wrong answer to "which roles exist".
 * - **Truncation:** beyond 20 pages the list is flagged `truncated` and the page says so.
 * - **Warm:** `loadAll` is a no-op when `ready`, and joins a load in flight. {@link invalidate}
 *   (after create, save, rename, delete) returns to `idle`.
 * - **User change:** state is keyed by the signed-in user id, so another user never sees this
 *   list, and a signed-out store reads nothing (design §6.2).
 * - **RC-73:** every failure is caught into `error`; an `AppError` never reaches `ErrorHandler`,
 *   and logs carry codes and ids only, never role names.
 *
 * Provided on the console's layout route; not `providedIn: 'root'`.
 *
 * @security UX only. The server decides every request.
 */
@Injectable()
export class RolesStore {
  private readonly api = inject(RbacApi);
  private readonly authStore = inject(AuthStore);
  private readonly logger = inject(LoggerService);

  private readonly owned = signal<OwnedState>({ owner: null, state: IDLE });
  private readonly running = signal<RolesProgress | null>(null);
  private inFlight: { readonly owner: string; readonly subscription: Subscription } | null = null;

  private readonly currentUserId = computed(() => this.authStore.currentUser()?.userId ?? null);

  /** The load state for the signed-in user; `idle` when it belongs to anyone else. */
  readonly state = computed<LoadState<RolesData>>(() => {
    const { owner, state } = this.owned();
    return owner !== null && owner === this.currentUserId() ? state : IDLE;
  });

  /** Roles received so far of the total, while loading and once page 0 has answered. */
  readonly progress = computed<RolesProgress | null>(() =>
    this.state().status === 'loading' ? this.running() : null,
  );

  constructor() {
    inject(DestroyRef).onDestroy(() => this.cancel());
  }

  /** Reads every role, or joins the read in flight; sends nothing when already `ready`. */
  loadAll(): void {
    const owner = this.currentUserId();
    if (owner === null) {
      this.cancel();
      this.owned.set({ owner: null, state: IDLE });
      return;
    }
    const current = this.state();
    if (current.status === 'ready' || this.inFlight?.owner === owner) return;

    this.cancel();
    this.running.set(null);
    this.owned.set({ owner, state: LOADING });
    const subscription = new Subscription();
    // Set before reading, so a settle that happens synchronously clears it rather than racing it.
    this.inFlight = { owner, subscription };
    this.read(owner, subscription);
  }

  /** Forgets the list, e.g. after a create or save, so the next `loadAll` reads it again. */
  invalidate(): void {
    this.cancel();
    this.running.set(null);
    this.owned.set({ owner: this.currentUserId(), state: IDLE });
  }

  private read(owner: string, subscription: Subscription): void {
    let loaded = 0;
    const received = (page: RoleListResponse): void => {
      loaded += page.data.length;
      this.running.set({ loaded, total: page.page.totalElements });
    };

    subscription.add(
      this.api.listRoles(0, PAGE_SIZE).subscribe({
        next: (first) => {
          received(first);
          const pages = Math.min(first.page.totalPages, MAX_PAGES);
          if (pages <= 1) {
            this.settle(owner, this.toReady([first], first, false));
            return;
          }
          const rest = Array.from({ length: pages - 1 }, (_, i) =>
            this.api.listRoles(i + 1, PAGE_SIZE).pipe(tap(received)),
          );
          subscription.add(
            forkJoin(rest).subscribe({
              next: (others) =>
                this.settle(
                  owner,
                  this.toReady([first, ...others], first, first.page.totalPages > MAX_PAGES),
                ),
              error: (error: unknown) => this.settle(owner, this.toError(error)),
            }),
          );
        },
        error: (error: unknown) => this.settle(owner, this.toError(error)),
      }),
    );
  }

  private settle(owner: string, state: LoadState<RolesData>): void {
    this.inFlight = null;
    this.running.set(null);
    this.owned.set({ owner, state });
  }

  private cancel(): void {
    this.inFlight?.subscription.unsubscribe();
    this.inFlight = null;
  }

  private toReady(
    pages: readonly RoleListResponse[],
    first: RoleListResponse,
    truncated: boolean,
  ): LoadState<RolesData> {
    // Keyed by id: a role created while the pages load shifts later pages and repeats one.
    const byId = new Map<string, RoleResponse>();
    for (const page of pages) for (const role of page.data) byId.set(role.id, role);
    const total = first.page.totalElements;
    if (truncated) {
      this.logger.warn('Access console roles list is truncated', {
        event: 'access_console_roles_truncated',
        context: { area: 'roles', count: total },
      });
    }
    return {
      status: 'ready',
      loadedAt: Date.now(),
      data: { roles: [...byId.values()], total, truncated },
    };
  }

  private toError(error: unknown): LoadState<RolesData> {
    const appError: AppError = isAppError(error)
      ? error
      : { code: 'UNEXPECTED_ERROR', message: 'The roles could not be read.' };
    this.logger.warn('Access console roles load failed', {
      event: 'access_console_roles_load_failed',
      errorCode: appError.code,
      correlationId: appError.correlationId,
      context: { area: 'roles', traceId: appError.traceId },
    });
    return { status: 'error', error: appError, failedAt: Date.now() };
  }
}
