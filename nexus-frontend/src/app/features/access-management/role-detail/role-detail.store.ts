import { DestroyRef, Injectable, computed, inject, signal } from '@angular/core';
import { Subscription, forkJoin } from 'rxjs';
import { AuthStore } from '../../../core/auth/auth.store';
import { LoggerService } from '../../../core/logging/logger.service';
import type { PermissionResponse, RoleResponse } from '../../../shared/types/api/rbac';
import { AppError, isAppError } from '../../../shared/types/app-error';
import type { EtagState } from '../data/etag';
import type { LoadState } from '../data/load-state';
import { RbacApi, VersionedPermissionSet } from '../data/rbac-api';

/**
 * Whether the set as read can be saved (design §7.2). `etag-unusable`: the tag is weak or missing,
 * so the server would refuse any save (428). The editor (T-010, T-011) must not let work be staged.
 */
export type SaveAvailability = 'available' | 'etag-unusable';

/** One role and its permission set, read together (design §6.5 "Role detail"). */
export interface RoleDetailData {
  readonly role: RoleResponse;
  readonly permissions: readonly PermissionResponse[];
  /** The set's version tag; `value` of a strong tag is verbatim and is the only `If-Match`. */
  readonly etag: EtagState;
  /** `X-Correlation-Id` of the set GET, or `null`: the reference shown when saving is off. */
  readonly correlationId: string | null;
  readonly saveAvailability: SaveAvailability;
}

interface OwnedState {
  readonly owner: string | null;
  readonly roleId: string | null;
  readonly state: LoadState<RoleDetailData>;
}

const IDLE: LoadState<RoleDetailData> = { status: 'idle' };
const LOADING: LoadState<RoleDetailData> = { status: 'loading' };

/** Codes that mean the role is gone or the id is not a role: a Refresh cannot keep the old view. */
const GONE: ReadonlySet<string> = new Set(['ROLE_NOT_FOUND', 'VALIDATION_FAILED']);

type ReadMode = 'load' | 'refresh';

/**
 * The role detail page's data (US-020 design §6.1, §6.5, §7.1, §7.2): `GET /roles/{id}` and
 * `GET /roles/{id}/permissions` **in parallel**, all or nothing.
 *
 * - **Version tag:** the set's `ETag` is classified (`classifyEtag`) and kept verbatim. A weak or
 *   missing tag sets `saveAvailability = 'etag-unusable'` and logs one
 *   `access_console_etag_unusable` warn per read, with `roleId`, `etagKind` and `correlationId`
 *   only. The read view stays: only saving is off.
 * - **load(roleId):** always reads both (warm budget 2), cancelling any read of another role.
 * - **refresh():** re-reads both together (Q24), never the profile or the catalogue. The current
 *   view stays while it runs; a failure keeps it and is exposed as `refreshError`, except when the
 *   role is gone (`ROLE_NOT_FOUND`, or a malformed id), which becomes the error state. A refresh
 *   while one runs is ignored.
 * - **User change:** state is keyed by the signed-in user id (design §6.2).
 * - **RC-73:** every failure is caught; an `AppError` never reaches `ErrorHandler`. Logs carry
 *   codes and ids only, never the role name or description.
 *
 * Provided on the `roles/:roleId` route; not `providedIn: 'root'`.
 *
 * @security UX only. The server decides every request and refuses any save without a strong tag.
 */
@Injectable()
export class RoleDetailStore {
  private readonly api = inject(RbacApi);
  private readonly authStore = inject(AuthStore);
  private readonly logger = inject(LoggerService);

  private readonly owned = signal<OwnedState>({ owner: null, roleId: null, state: IDLE });
  private readonly refreshRunning = signal(false);
  private readonly refreshFailure = signal<AppError | null>(null);
  private inFlight: Subscription | null = null;

  private readonly currentUserId = computed(() => this.authStore.currentUser()?.userId ?? null);
  private readonly mine = computed(() => {
    const owned = this.owned();
    return owned.owner !== null && owned.owner === this.currentUserId() ? owned : null;
  });

  /** The load state for the signed-in user; `idle` when it belongs to anyone else. */
  readonly state = computed<LoadState<RoleDetailData>>(() => this.mine()?.state ?? IDLE);

  /** The role the state is about, or `null`. */
  readonly roleId = computed(() => this.mine()?.roleId ?? null);

  /** A Refresh is running; the ready view is still shown. */
  readonly refreshing = computed(() => this.state().status === 'ready' && this.refreshRunning());

  /** Why the last Refresh failed while the previous view was kept, or `null`. */
  readonly refreshError = computed(() =>
    this.state().status === 'ready' ? this.refreshFailure() : null,
  );

  constructor() {
    inject(DestroyRef).onDestroy(() => this.cancel());
  }

  /** Reads the role and its set, replacing whatever was shown. */
  load(roleId: string): void {
    this.cancel();
    this.refreshRunning.set(false);
    this.refreshFailure.set(null);
    const owner = this.currentUserId();
    if (owner === null) {
      this.owned.set({ owner: null, roleId: null, state: IDLE });
      return;
    }
    this.owned.set({ owner, roleId, state: LOADING });
    this.read(owner, roleId, 'load');
  }

  /** Re-reads the role and its set together, keeping the current view until they arrive. */
  refresh(): void {
    const mine = this.mine();
    if (mine === null || mine.roleId === null || mine.state.status !== 'ready') return;
    if (this.inFlight !== null) return;
    this.refreshRunning.set(true);
    this.read(mine.owner as string, mine.roleId, 'refresh');
  }

  private read(owner: string, roleId: string, mode: ReadMode): void {
    const subscription = new Subscription();
    // Set before reading, so a settle that happens synchronously clears it rather than racing it.
    this.inFlight = subscription;
    subscription.add(
      forkJoin([this.api.getRole(roleId), this.api.getRolePermissions(roleId)]).subscribe({
        next: ([role, set]) => this.succeed(owner, roleId, role, set),
        error: (error: unknown) => this.fail(owner, roleId, mode, error),
      }),
    );
  }

  private succeed(
    owner: string,
    roleId: string,
    role: RoleResponse,
    set: VersionedPermissionSet,
  ): void {
    this.settled();
    this.refreshFailure.set(null);
    const saveAvailability: SaveAvailability =
      set.etag.kind === 'strong' ? 'available' : 'etag-unusable';
    if (saveAvailability === 'etag-unusable') {
      this.logger.warn('Access console role permission set has no usable version tag', {
        event: 'access_console_etag_unusable',
        ...(set.correlationId === null ? {} : { correlationId: set.correlationId }),
        context: { roleId, etagKind: set.etag.kind },
      });
    }
    this.owned.set({
      owner,
      roleId,
      state: {
        status: 'ready',
        loadedAt: Date.now(),
        data: {
          role,
          permissions: set.permissions,
          etag: set.etag,
          correlationId: set.correlationId,
          saveAvailability,
        },
      },
    });
  }

  private fail(owner: string, roleId: string, mode: ReadMode, error: unknown): void {
    this.settled();
    const appError: AppError = isAppError(error)
      ? error
      : { code: 'UNEXPECTED_ERROR', message: 'The role could not be read.' };
    this.logger.warn('Access console role detail load failed', {
      event: 'access_console_role_detail_load_failed',
      errorCode: appError.code,
      correlationId: appError.correlationId,
      context: {
        area: 'roles',
        roleId,
        traceId: appError.traceId,
        ...(mode === 'refresh' ? { action: 'refresh' } : {}),
      },
    });
    if (mode === 'refresh' && !GONE.has(appError.code)) {
      this.refreshFailure.set(appError);
      return;
    }
    this.refreshFailure.set(null);
    this.owned.set({
      owner,
      roleId,
      state: { status: 'error', error: appError, failedAt: Date.now() },
    });
  }

  private settled(): void {
    this.inFlight = null;
    this.refreshRunning.set(false);
  }

  private cancel(): void {
    this.inFlight?.unsubscribe();
    this.inFlight = null;
  }
}
