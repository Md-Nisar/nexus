import { DestroyRef, Injectable, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Subscription } from 'rxjs';
import { AuthStore } from '../../../core/auth/auth.store';
import { LoggerService } from '../../../core/logging/logger.service';
import type { CallerAuthorizationResponse } from '../../../shared/types/api/rbac';
import { AppError, isAppError } from '../../../shared/types/app-error';
import { PERMISSIONS, Permission } from '../../../shared/types/permission';
import type { LoadState } from './load-state';
import { RbacApi } from './rbac-api';

/** Why the profile is read again (design §6.3). Logged; never changes how it is read. */
export type ProfileReloadReason = 'own-access-change' | 'denied-predicted-allowed' | 'user-changed';

/** The caller's live authorization, as the console's affordances use it. */
export interface AuthorizationProfile {
  readonly userId: string;
  readonly isAdministrator: boolean;
  /** Catalogue permissions only; unknown names from the server are dropped. */
  readonly permissions: ReadonlySet<Permission>;
  readonly roleIds: ReadonlySet<string>;
}

/** The state together with the user it belongs to, so it can never leak to another user. */
interface OwnedState {
  readonly owner: string | null;
  readonly state: LoadState<AuthorizationProfile>;
}

const IDLE: LoadState<AuthorizationProfile> = { status: 'idle' };
const LOADING: LoadState<AuthorizationProfile> = { status: 'loading' };
const NO_PERMISSIONS: ReadonlySet<Permission> = new Set();
const NO_ROLES: ReadonlySet<string> = new Set();
const CATALOGUE: ReadonlySet<string> = new Set(PERMISSIONS);

function isPermission(name: string): name is Permission {
  return CATALOGUE.has(name);
}

/**
 * The caller's live authorization profile, the source of every mutating affordance in the
 * console (US-020 design §2.2, §6.3; ADR-0028 decision 2). Navigation and guards keep reading
 * `AuthStore`; the server stays the decision.
 *
 * - **Lifetime:** provided on the console's layout route. `AccessConsoleLayout` calls {@link load}
 *   once per console entry; child navigation does not, so it is one `GET` per entry (§6.5).
 * - **Coalescing:** one request in flight per user; a `load` or `reload` while it runs joins it.
 * - **Fail closed (Q8):** `mutationsEnabled` is true only while a profile for the signed-in user is
 *   `ready`. Loading, any failure, and a different or absent user all turn every change off.
 * - **User change (DQ-7):** state is keyed by the `AuthStore` user id, so another user never sees
 *   this profile, even before anything reloads; a read for a new user cancels the old one.
 * - **Never refreshes the session** (RC-65, ADR-0028 decision 5): after an own-access change the
 *   re-read gets a 401 on the bumped epoch, and `authInterceptor`'s single shared refresh renews
 *   the session and replays it. This class must not inject `AuthService`.
 * - **RC-73:** every failure is caught into `error`; an `AppError` never reaches `ErrorHandler`,
 *   and logs carry codes and ids only.
 */
@Injectable()
export class AuthorizationProfileStore {
  private readonly api = inject(RbacApi);
  private readonly authStore = inject(AuthStore);
  private readonly logger = inject(LoggerService);
  private readonly destroyRef = inject(DestroyRef);

  private readonly owned = signal<OwnedState>({ owner: null, state: IDLE });
  private inFlight: { readonly owner: string; readonly subscription: Subscription } | null = null;

  private readonly currentUserId = computed(() => this.authStore.currentUser()?.userId ?? null);

  /** The load state for the signed-in user; `idle` when it belongs to anyone else. */
  readonly state = computed<LoadState<AuthorizationProfile>>(() => {
    const { owner, state } = this.owned();
    return owner !== null && owner === this.currentUserId() ? state : IDLE;
  });

  private readonly profile = computed(() => {
    const state = this.state();
    return state.status === 'ready' ? state.data : null;
  });

  readonly userId = computed(() => this.profile()?.userId ?? null);
  readonly isAdministrator = computed(() => this.profile()?.isAdministrator ?? false);
  readonly permissions = computed(() => this.profile()?.permissions ?? NO_PERMISSIONS);
  readonly roleIds = computed(() => this.profile()?.roleIds ?? NO_ROLES);

  /** True only when the live profile is `ready`: every mutating control is off otherwise. */
  readonly mutationsEnabled = computed(() => this.state().status === 'ready');

  constructor() {
    this.destroyRef.onDestroy(() => this.cancel());
  }

  /** Whether the live profile holds `permission`. Reactive when read in a template or `computed`. */
  can(permission: Permission): boolean {
    return this.permissions().has(permission);
  }

  /** Reads the profile on console entry, or joins the read already in flight. */
  load(): void {
    this.read();
  }

  /** Reads the profile again after an own-access event, a predicted-allow 403 or a user change. */
  reload(reason: ProfileReloadReason): void {
    this.logger.info('Access console profile reload', {
      event: 'access_console_profile_reload',
      context: { area: 'profile', reason },
    });
    this.read();
  }

  private read(): void {
    const owner = this.currentUserId();
    if (owner === null) {
      // Signed out: nothing to read, and nothing may stay visible.
      this.cancel();
      this.owned.set({ owner: null, state: IDLE });
      return;
    }
    if (this.inFlight?.owner === owner) return;

    this.cancel();
    this.owned.set({ owner, state: LOADING });
    const subscription = this.api
      .getMyAuthorization()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (body) => this.settle(owner, this.toReady(body)),
        error: (error: unknown) => this.settle(owner, this.toError(error)),
      });
    if (!subscription.closed) this.inFlight = { owner, subscription };
  }

  private settle(owner: string, state: LoadState<AuthorizationProfile>): void {
    this.inFlight = null;
    this.owned.set({ owner, state });
  }

  private cancel(): void {
    this.inFlight?.subscription.unsubscribe();
    this.inFlight = null;
  }

  private toReady(body: CallerAuthorizationResponse): LoadState<AuthorizationProfile> {
    const known = body.permissions.filter(isPermission);
    const unknown = body.permissions.filter((name) => !isPermission(name));
    if (unknown.length > 0) {
      this.logger.warn('Access console profile has permissions outside the catalogue', {
        event: 'access_console_profile_unknown_permissions',
        context: { area: 'profile', count: unknown.length, permissions: unknown },
      });
    }
    return {
      status: 'ready',
      loadedAt: Date.now(),
      data: {
        userId: body.userId,
        isAdministrator: body.isAdministrator,
        permissions: new Set(known),
        roleIds: new Set(body.roles.map((role) => role.roleId)),
      },
    };
  }

  private toError(error: unknown): LoadState<AuthorizationProfile> {
    const appError: AppError = isAppError(error)
      ? error
      : { code: 'UNEXPECTED_ERROR', message: 'The access profile could not be read.' };
    this.logger.warn('Access console profile load failed', {
      event: 'access_console_profile_load_failed',
      errorCode: appError.code,
      correlationId: appError.correlationId,
      context: { area: 'profile', traceId: appError.traceId },
    });
    return { status: 'error', error: appError, failedAt: Date.now() };
  }
}
