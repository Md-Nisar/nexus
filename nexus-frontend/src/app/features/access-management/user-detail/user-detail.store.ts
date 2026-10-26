import { DestroyRef, Injectable, computed, inject, signal } from '@angular/core';
import { Subscription } from 'rxjs';
import { AuthStore } from '../../../core/auth/auth.store';
import { LoggerService } from '../../../core/logging/logger.service';
import type {
  RoleAssignmentListResponse,
  RoleAssignmentResponse,
} from '../../../shared/types/api/rbac';
import type { UserDirectoryEntry } from '../../../shared/types/api/user-directory';
import { AppError, isAppError } from '../../../shared/types/app-error';
import { DirectoryApi } from '../data/directory-api';
import { DirectoryCache } from '../data/directory-cache';
import type { LoadState } from '../data/load-state';
import { RbacApi } from '../data/rbac-api';

/** Assignments per request: the server's maximum page size; only page 0 is read (design §6.5). */
const ASSIGNMENTS_PAGE_SIZE = 100;

/** A user's active role assignments, as far as one page holds them. */
export interface UserAssignments {
  readonly assignments: readonly RoleAssignmentResponse[];
  /** Assignments the server reports; greater than `assignments.length` only past one page. */
  readonly total: number;
}

interface OwnedState {
  readonly owner: string | null;
  readonly userId: string | null;
  readonly user: LoadState<UserDirectoryEntry>;
  readonly assignments: LoadState<UserAssignments>;
}

const IDLE: OwnedState = {
  owner: null,
  userId: null,
  user: { status: 'idle' },
  assignments: { status: 'idle' },
};

function toAppError(error: unknown, message: string): AppError {
  return isAppError(error) ? error : { code: 'UNEXPECTED_ERROR', message };
}

/**
 * One person's page data (US-020 design §6.1, §6.5 "User page", §7.1, §12.8; Q19):
 * `GET /users/{id}` and, only when `AuthStore` holds `user:read`, `GET /users/{id}/roles?page=0
 * &size=100`, sent together.
 *
 * - **Independent reads:** the two states settle separately, so a failed or forbidden assignments
 *   read leaves the header shown. Without `user:read` the assignments are never requested and stay
 *   `idle` ({@link canReadAssignments} says why). Read gating follows the JWT, as navigation does
 *   (ADR-0028): reads must work while the live profile is loading or unavailable (Q8).
 * - **Not found:** a missing id and another tenant's id are the same 404 `USER_NOT_FOUND`
 *   (SD-20); the page shows them alike.
 * - **load(userId)** reads both and cancels any read of another user;
 *   **loadAssignments()** re-reads only the assignments of the user shown (Retry, and the re-read
 *   after an assign or revoke).
 * - **Directory cache:** the user read is handed to {@link DirectoryCache}.
 * - **User change:** state is keyed by the signed-in user id (design §6.2).
 * - **RC-73:** every failure is caught into `error`; an `AppError` never reaches `ErrorHandler`.
 *   Logs carry codes and ids only, never an address.
 *
 * Provided on the `users/:userId` route; not `providedIn: 'root'`.
 *
 * @security UX only. The server decides every request.
 */
@Injectable()
export class UserDetailStore {
  private readonly directory = inject(DirectoryApi);
  private readonly rbac = inject(RbacApi);
  private readonly cache = inject(DirectoryCache);
  private readonly authStore = inject(AuthStore);
  private readonly logger = inject(LoggerService);

  private readonly owned = signal<OwnedState>(IDLE);
  private userRequest: Subscription | null = null;
  private assignmentsRequest: Subscription | null = null;

  private readonly currentUserId = computed(() => this.authStore.currentUser()?.userId ?? null);
  private readonly mine = computed(() => {
    const owned = this.owned();
    return owned.owner !== null && owned.owner === this.currentUserId() ? owned : IDLE;
  });

  /** The user the page is about, or `null`. */
  readonly userId = computed(() => this.mine().userId);

  /** The directory entry for the signed-in caller; `idle` when it belongs to anyone else. */
  readonly state = computed<LoadState<UserDirectoryEntry>>(() => this.mine().user);

  /** The user's assignments; `idle` without `user:read`, before a load, or for anyone else. */
  readonly assignments = computed<LoadState<UserAssignments>>(() => this.mine().assignments);

  /** The JWT holds `user:read`, so the assignments are requested. UX only. */
  readonly canReadAssignments = computed(() => this.authStore.permissions().includes('user:read'));

  constructor() {
    inject(DestroyRef).onDestroy(() => this.cancel());
  }

  /** Reads the user, and their assignments when permitted, replacing whatever was shown. */
  load(userId: string): void {
    this.cancel();
    const owner = this.currentUserId();
    if (owner === null) {
      this.owned.set(IDLE);
      return;
    }
    this.owned.set({
      owner,
      userId,
      user: { status: 'loading' },
      assignments: { status: 'idle' },
    });
    this.readUser(owner, userId);
    this.loadAssignments();
  }

  /** Re-reads the assignments of the user shown; nothing without `user:read`. */
  loadAssignments(): void {
    const mine = this.mine();
    if (mine.owner === null || mine.userId === null || !this.canReadAssignments()) return;
    const { owner, userId } = mine;
    this.assignmentsRequest?.unsubscribe();
    this.patch(owner, userId, { assignments: { status: 'loading' } });
    this.assignmentsRequest = this.rbac
      .listAssignments(userId, 0, ASSIGNMENTS_PAGE_SIZE)
      .subscribe({
        next: (page) =>
          this.patch(owner, userId, {
            assignments: {
              status: 'ready',
              loadedAt: Date.now(),
              data: this.toAssignments(userId, page),
            },
          }),
        error: (error: unknown) => {
          const appError = toAppError(error, 'The role assignments could not be read.');
          this.logFailure('access_console_user_roles_load_failed', 'assignments', userId, appError);
          this.patch(owner, userId, {
            assignments: { status: 'error', error: appError, failedAt: Date.now() },
          });
        },
      });
  }

  private readUser(owner: string, userId: string): void {
    this.userRequest = this.directory.getUser(userId).subscribe({
      next: (entry) => {
        this.cache.remember([entry]);
        this.patch(owner, userId, {
          user: { status: 'ready', loadedAt: Date.now(), data: entry },
        });
      },
      error: (error: unknown) => {
        const appError = toAppError(error, 'The user could not be read.');
        this.logFailure('access_console_user_load_failed', 'users', userId, appError);
        this.patch(owner, userId, {
          user: { status: 'error', error: appError, failedAt: Date.now() },
        });
      },
    });
  }

  /** Applies a settled read, unless the page has moved to another user or caller since. */
  private patch(
    owner: string,
    userId: string,
    change: Partial<Pick<OwnedState, 'user' | 'assignments'>>,
  ): void {
    const current = this.owned();
    if (current.owner !== owner || current.userId !== userId) return;
    this.owned.set({ ...current, ...change });
  }

  private toAssignments(userId: string, page: RoleAssignmentListResponse): UserAssignments {
    const total = page.page.totalElements;
    if (total > page.data.length) {
      this.logger.warn('Access console user roles exceed one page', {
        event: 'access_console_user_roles_truncated',
        context: { area: 'assignments', userId, count: total },
      });
    }
    return { assignments: page.data, total };
  }

  private logFailure(
    event: string,
    area: 'users' | 'assignments',
    userId: string,
    error: AppError,
  ): void {
    this.logger.warn('Access console user page request failed', {
      event,
      errorCode: error.code,
      correlationId: error.correlationId,
      context: { area, userId, traceId: error.traceId },
    });
  }

  private cancel(): void {
    this.userRequest?.unsubscribe();
    this.assignmentsRequest?.unsubscribe();
    this.userRequest = null;
    this.assignmentsRequest = null;
  }
}
