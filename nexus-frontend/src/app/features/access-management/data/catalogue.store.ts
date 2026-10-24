import { DestroyRef, Injectable, computed, inject, signal } from '@angular/core';
import { Subscription, forkJoin } from 'rxjs';
import { AuthStore } from '../../../core/auth/auth.store';
import { LoggerService } from '../../../core/logging/logger.service';
import type { PermissionPageResponse, PermissionResponse } from '../../../shared/types/api/rbac';
import { AppError, isAppError } from '../../../shared/types/app-error';
import { CONSOLE_COPY } from '../copy/console-copy';
import {
  PERMISSION_GROUP_LABELS,
  PERMISSION_GROUP_ORDER,
  permissionLabel,
} from '../copy/permission-labels';
import type { LoadState } from './load-state';
import { RbacApi } from './rbac-api';

/** Permissions per request: the server's maximum page size (design §6.4). */
const PAGE_SIZE = 100;

/** Permissions of one resource, or `other` for a resource this build has no group label for. */
export interface PermissionGroup {
  readonly resource: string;
  readonly label: string;
  /** Alphabetical by code. */
  readonly permissions: readonly PermissionResponse[];
}

/** The whole permission catalogue and its indexes (design §6.4). */
export interface CatalogueData {
  /** In the server's name order. */
  readonly permissions: readonly PermissionResponse[];
  readonly byId: ReadonlyMap<string, PermissionResponse>;
  readonly byName: ReadonlyMap<string, PermissionResponse>;
  /** Fixed group order, alphabetical inside; empty groups are left out. */
  readonly groups: readonly PermissionGroup[];
  readonly total: number;
}

interface OwnedState {
  readonly owner: string | null;
  readonly state: LoadState<CatalogueData>;
}

const IDLE: LoadState<CatalogueData> = { status: 'idle' };
const LOADING: LoadState<CatalogueData> = { status: 'loading' };
const OTHER = 'other';

function byCode(a: PermissionResponse, b: PermissionResponse): number {
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
}

function resourceOf(code: string): string {
  const colon = code.indexOf(':');
  return colon === -1 ? OTHER : code.slice(0, colon);
}

/**
 * The permission catalogue for the console (US-020 design §6.4, §6.5), read once per console
 * session: `GET /permissions?page=0&size=100`. The catalogue holds nine entries today, so one
 * request is the norm. If the server reports more than one page, the remaining pages are fetched
 * in parallel and a single defect-signal warn is logged.
 *
 * - **All or nothing:** a failing page fails the whole load.
 * - **Unlabelled codes:** a code outside the `Permission` union stays in the data; one warn per
 *   code is logged when the catalogue arrives, carrying the code only (a catalogue code, not
 *   personal data), never the description.
 * - **Warm:** `load` is a no-op when `ready`, and joins a load in flight.
 * - **User change:** state is keyed by the signed-in user id (design §6.2).
 * - **RC-73:** every failure is caught into `error`; an `AppError` never reaches `ErrorHandler`.
 *
 * Provided on the console's layout route; not `providedIn: 'root'`.
 *
 * @security UX only. The server decides every request.
 */
@Injectable()
export class CatalogueStore {
  private readonly api = inject(RbacApi);
  private readonly authStore = inject(AuthStore);
  private readonly logger = inject(LoggerService);

  private readonly owned = signal<OwnedState>({ owner: null, state: IDLE });
  private inFlight: { readonly owner: string; readonly subscription: Subscription } | null = null;

  private readonly currentUserId = computed(() => this.authStore.currentUser()?.userId ?? null);

  /** The load state for the signed-in user; `idle` when it belongs to anyone else. */
  readonly state = computed<LoadState<CatalogueData>>(() => {
    const { owner, state } = this.owned();
    return owner !== null && owner === this.currentUserId() ? state : IDLE;
  });

  constructor() {
    inject(DestroyRef).onDestroy(() => this.cancel());
  }

  /** Reads the catalogue, or joins the read in flight; sends nothing when already `ready`. */
  load(): void {
    const owner = this.currentUserId();
    if (owner === null) {
      this.cancel();
      this.owned.set({ owner: null, state: IDLE });
      return;
    }
    if (this.state().status === 'ready') return;
    if (this.inFlight?.owner === owner) return;

    this.cancel();
    this.owned.set({ owner, state: LOADING });
    const subscription = new Subscription();
    // Set before reading, so a settle that happens synchronously clears it rather than racing it.
    this.inFlight = { owner, subscription };
    this.read(owner, subscription);
  }

  private read(owner: string, subscription: Subscription): void {
    subscription.add(
      this.api.listPermissions(0, PAGE_SIZE).subscribe({
        next: (first) => {
          const pages = first.page.totalPages;
          if (pages <= 1) {
            this.settle(owner, this.toReady([first], first));
            return;
          }
          const rest = Array.from({ length: pages - 1 }, (_, i) =>
            this.api.listPermissions(i + 1, PAGE_SIZE),
          );
          subscription.add(
            forkJoin(rest).subscribe({
              next: (others) => this.settle(owner, this.toReady([first, ...others], first)),
              error: (error: unknown) => this.settle(owner, this.toError(error)),
            }),
          );
        },
        error: (error: unknown) => this.settle(owner, this.toError(error)),
      }),
    );
  }

  private settle(owner: string, state: LoadState<CatalogueData>): void {
    this.inFlight = null;
    this.owned.set({ owner, state });
  }

  private cancel(): void {
    this.inFlight?.subscription.unsubscribe();
    this.inFlight = null;
  }

  private toReady(
    pages: readonly PermissionPageResponse[],
    first: PermissionPageResponse,
  ): LoadState<CatalogueData> {
    const byName = new Map<string, PermissionResponse>();
    for (const page of pages) for (const entry of page.data) byName.set(entry.name, entry);
    const permissions = [...byName.values()];
    const total = first.page.totalElements;

    if (first.page.totalPages > 1) {
      this.logger.warn('Access console catalogue needed more than one page', {
        event: 'access_console_catalogue_paged',
        context: { area: 'permissions', count: total },
      });
    }
    for (const entry of [...permissions].sort(byCode)) {
      if (permissionLabel(entry.name) === undefined) {
        this.logger.warn('Access console catalogue has a permission without a label', {
          event: 'access_console_permission_unlabelled',
          context: { area: 'permissions', permission: entry.name },
        });
      }
    }

    return {
      status: 'ready',
      loadedAt: Date.now(),
      data: {
        permissions,
        byId: new Map(permissions.map((entry) => [entry.id, entry])),
        byName,
        groups: this.group(permissions),
        total,
      },
    };
  }

  private group(permissions: readonly PermissionResponse[]): PermissionGroup[] {
    const buckets = new Map<string, PermissionResponse[]>();
    for (const entry of permissions) {
      const resource = resourceOf(entry.name);
      const key = PERMISSION_GROUP_ORDER.some((known) => known === resource) ? resource : OTHER;
      buckets.set(key, [...(buckets.get(key) ?? []), entry]);
    }
    const groups: PermissionGroup[] = [];
    for (const resource of [...PERMISSION_GROUP_ORDER, OTHER]) {
      const members = buckets.get(resource);
      if (members === undefined) continue;
      groups.push({
        resource,
        label:
          resource === OTHER
            ? CONSOLE_COPY.catalogue.otherGroup
            : PERMISSION_GROUP_LABELS[resource as keyof typeof PERMISSION_GROUP_LABELS],
        permissions: members.sort(byCode),
      });
    }
    return groups;
  }

  private toError(error: unknown): LoadState<CatalogueData> {
    const appError: AppError = isAppError(error)
      ? error
      : { code: 'UNEXPECTED_ERROR', message: 'The permissions could not be read.' };
    this.logger.warn('Access console catalogue load failed', {
      event: 'access_console_catalogue_load_failed',
      errorCode: appError.code,
      correlationId: appError.correlationId,
      context: { area: 'permissions', traceId: appError.traceId },
    });
    return { status: 'error', error: appError, failedAt: Date.now() };
  }
}
