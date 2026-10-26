import {
  Component,
  DestroyRef,
  Injector,
  TemplateRef,
  computed,
  inject,
  input,
  output,
  signal,
  viewChild,
} from '@angular/core';
import { takeUntilDestroyed, toObservable } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { first } from 'rxjs';
import { LoggerService } from '../../../core/logging/logger.service';
import type { PermissionResponse } from '../../../shared/types/api/rbac';
import { AppError, isAppError } from '../../../shared/types/app-error';
import { NxButton, NxDialog, NxToast } from '../../../shared/ui';
import { CONSOLE_COPY, RbacErrorMessages, format } from '../copy/console-copy';
import { permissionLabel } from '../copy/permission-labels';
import { propagationFor } from '../copy/propagation';
import { ConsoleErrorView, resolveConsoleError } from '../copy/resolve-console-error';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { CatalogueStore } from '../data/catalogue.store';
import type { LoadState } from '../data/load-state';
import { RbacApi } from '../data/rbac-api';
import { RolesStore } from '../data/roles.store';
import { TargetIdentity } from '../ui/target-identity';
import { UserText, UserTextMode } from '../ui/user-text';
import { UserDetailStore } from '../user-detail/user-detail.store';
import { isAdminDefiningHint } from '../util/admin-defining-hint';
import { DEFAULT_RETRY_AFTER_SECONDS, createRetryCountdown } from '../util/retry-after';

/** Which Revoke dialog a row opens (design §12.10). */
export type RevokeVariant = 'standard' | 'self';

export interface RevokeVariantInput {
  /** The user the page is about: the route's `userId`. */
  readonly routeUserId: string | null;
  /** The caller, from the live profile. */
  readonly callerUserId: string | null;
  /** Whether the role looks administrator-defining; `null` when that is not known. */
  readonly adminHint: boolean | null;
}

/**
 * D-5: the typed self-revoke variant (no identity line) is chosen **only by user-id equality**,
 * never by comparing addresses, and only for a role that looks administrator-defining. The hint is
 * a hint (Gate 1 Q17), so an unknown hint fails closed to the typed variant: for the caller's own
 * roles the extra confirmation costs one typed name, while the standard variant could let a
 * one-click slip remove the caller's administrator access.
 */
export function chooseRevokeVariant(input: RevokeVariantInput): RevokeVariant {
  const self =
    input.routeUserId !== null &&
    input.callerUserId !== null &&
    input.routeUserId === input.callerUserId;
  return self && input.adminHint !== false ? 'self' : 'standard';
}

/** The assignment a row asks to remove. */
export interface RevokeTarget {
  readonly roleId: string;
  readonly roleName: string;
}

interface ActiveRevoke extends RevokeTarget {
  readonly userId: string;
  readonly variant: RevokeVariant;
  readonly adminHint: boolean | null;
}

type LossView = { readonly kind: 'loading' } | { readonly kind: 'ready'; readonly text: string };

type RevokeDialogRef = ReturnType<NxDialog['openTemplate']>;

const TITLE_ID = 'revoke-dialog-title';
const DIALOG_WAIT_ID = 'revoke-dialog-wait';
const TAB_WAIT_ID = 'user-roles-revoke-wait';

const [TITLE_START, TITLE_REST = ''] = CONSOLE_COPY.revoke.title.split('{role}');
const [TITLE_MIDDLE, TITLE_END = ''] = TITLE_REST.split('{person}');

const LOADING: LossView = { kind: 'loading' };
const GENERIC: LossView = { kind: 'ready', text: CONSOLE_COPY.revoke.losesGeneric };

/** Codes of a 403 the live profile predicted would be allowed (design §2.2). */
const DENIED: ReadonlySet<string> = new Set(['RBAC_001', 'ACCESS_DENIED']);

/**
 * Removing a role from a person (US-020 design §6.3, §6.5, §11.4, §12.10; RC-68 item 2, D-5;
 * FR-C5, FR-C6 as amended, FR-G3, FR-G5, FR-G6, FR-X2, FR-F3). Rendered by {@link UserRolesTab},
 * whose rows call {@link open}.
 *
 * - **Standard** (`NxDialog.openTemplate`, `danger` confirm "Remove role"): titled with the role and
 *   the address through {@link UserText} (email mode), {@link TargetIdentity} under the title, and
 *   "They will lose: {labels}" from `GET /roles/{id}/permissions`, read only when the live profile
 *   holds `role:read` and cached per role for this page (the generic line otherwise, or when the
 *   read fails). The administrator warning shows when the role is hinted admin-defining
 *   (`isAdminDefiningHint`, from the roles list and the catalogue total only when already loaded).
 * - **Self** ({@link chooseRevokeVariant}, D-5): `NxDialog.confirmTyped` with the role name as the
 *   text to type; no identity line, no request before the confirm.
 * - **Outcomes:** 204 re-reads the list, toasts "Role removed." and hands the revoke propagation
 *   line to the tab; 404 `ROLE_ASSIGNMENT_NOT_FOUND` converges ("already removed") with the same
 *   re-read; every other failure stays inline (in the dialog, which stays open, or on the tab after
 *   the typed confirm), including 409 `RBAC_002` (nothing changed). A 403 also re-reads the live
 *   profile; a 429 holds every Remove control and the confirm for the wait (no automatic retry).
 *   The server decides the last administrator: there is no up-front block, and `memberCount` is
 *   never read (Q16).
 * - **Own access:** when the target is the caller (by id), the live profile is re-read (its 401 on
 *   the bumped epoch is renewed by the interceptor's shared refresh, which also updates nav); once
 *   that read settles, the toast "Your own access has changed." and, after the typed self variant,
 *   a navigation to `/dashboard`. This class never calls `AuthService.refresh()` (RC-65).
 * - **PII:** the address is rendered only; logs carry ids and codes, toasts carry copy only.
 *
 * @security UX only. The server decides every request.
 */
@Component({
  selector: 'app-revoke-dialogs',
  imports: [NxButton, TargetIdentity, UserText],
  template: `
    @if (tabError(); as failure) {
      <div class="revoke-tab__error" role="alert" data-testid="user-roles-revoke-error">
        <p class="revoke-tab__error-title">{{ failure.title }}</p>
        @if (!failure.showsWait) {
          <p>{{ failure.body }}</p>
        }
        @if (failure.reference; as reference) {
          <p>
            {{ copy.reference }} <span class="revoke-tab__id">{{ reference }}</span>
          </p>
        }
      </div>
    }
    @if (waiting()) {
      <p class="revoke-tab__wait" [id]="tabWaitId" data-testid="user-roles-revoke-wait">
        {{ waitText() }}
      </p>
    }

    <ng-template #standardDialog>
      @if (active(); as revoke) {
        <div class="revoke-dialog" data-testid="revoke-dialog">
          <h2
            class="revoke-dialog__title"
            [id]="titleId"
            tabindex="-1"
            data-testid="revoke-dialog-title"
          >
            {{ titleStart }}<app-user-text [text]="revoke.roleName" />{{ titleMiddle
            }}<app-user-text [text]="person().text" [mode]="person().mode" />{{ titleEnd }}
          </h2>

          <div class="revoke-dialog__content">
            <app-target-identity [target]="target()" />

            @if (loss(); as summary) {
              @if (summary.kind === 'loading') {
                <p class="revoke-dialog__note" aria-busy="true" data-testid="revoke-loss-loading">
                  {{ copy.revoke.loadingLoss }}
                </p>
              } @else {
                <p class="revoke-dialog__loss" data-testid="revoke-loss">{{ summary.text }}</p>
              }
            }

            @if (revoke.adminHint === true) {
              <p class="revoke-dialog__warning" data-testid="revoke-admin-warning">
                {{ copy.revoke.adminWarning }}
              </p>
            }

            @if (dialogError(); as failure) {
              <div class="revoke-dialog__error" role="alert" data-testid="revoke-dialog-error">
                <p class="revoke-dialog__error-title">{{ failure.title }}</p>
                @if (!failure.showsWait) {
                  <p>{{ failure.body }}</p>
                }
                @if (failure.reference; as reference) {
                  <p>
                    {{ copy.reference }} <span class="revoke-tab__id">{{ reference }}</span>
                  </p>
                }
              </div>
            }
          </div>

          <div class="revoke-dialog__actions">
            @if (waiting()) {
              <p class="revoke-dialog__wait" [id]="dialogWaitId" data-testid="revoke-dialog-wait">
                {{ waitText() }}
              </p>
            }
            <nx-button
              variant="secondary"
              [disabled]="revoking()"
              (clicked)="close()"
              data-testid="revoke-cancel"
              >{{ copy.revoke.cancel }}</nx-button
            >
            <nx-button
              variant="danger"
              [loading]="revoking()"
              [ariaDisabled]="!canConfirm()"
              [ariaDescribedBy]="confirmDescribedBy()"
              (clicked)="confirm()"
              data-testid="revoke-confirm"
              >{{ copy.revoke.confirm }}</nx-button
            >
          </div>
        </div>
      }
    </ng-template>
  `,
  styles: `
    :host {
      display: contents;
    }

    .revoke-tab__error,
    .revoke-dialog__error {
      display: grid;
      gap: var(--nx-space-1);
      padding: var(--nx-space-3);
      border-radius: var(--nx-radius-md);
      background-color: var(--nx-color-error-surface);
      color: var(--nx-color-on-surface);
    }

    .revoke-tab__error p,
    .revoke-dialog p {
      margin: 0;
    }

    .revoke-tab__error-title,
    .revoke-dialog__error-title {
      font-weight: var(--nx-weight-semibold);
    }

    .revoke-tab__id {
      font-family: var(--nx-font-family-mono);
      overflow-wrap: anywhere;
    }

    .revoke-tab__wait,
    .revoke-dialog__note,
    .revoke-dialog__wait {
      margin: 0;
      color: var(--nx-color-on-surface-muted);
    }

    .revoke-dialog,
    .revoke-dialog__content {
      display: grid;
      gap: var(--nx-space-4);
      min-width: 0;
    }

    .revoke-dialog {
      padding: var(--nx-space-6);
      color: var(--nx-color-on-surface);
    }

    .revoke-dialog__title {
      margin: 0;
      font-size: var(--nx-text-lg);
      font-weight: var(--nx-weight-semibold);
      overflow-wrap: anywhere;
    }

    .revoke-dialog__content {
      max-height: 60vh;
      overflow-y: auto;
    }

    .revoke-dialog__loss {
      overflow-wrap: anywhere;
    }

    .revoke-dialog__warning {
      padding: var(--nx-space-3);
      border-radius: var(--nx-radius-md);
      background-color: var(--nx-color-warning-surface);
    }

    .revoke-dialog__actions {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: flex-end;
      gap: var(--nx-space-2);
    }

    .revoke-dialog__wait {
      margin-inline-end: auto;
    }
  `,
})
export class RevokeDialogs {
  private readonly store = inject(UserDetailStore);
  private readonly roles = inject(RolesStore);
  private readonly catalogue = inject(CatalogueStore);
  private readonly profile = inject(AuthorizationProfileStore);
  private readonly api = inject(RbacApi);
  private readonly dialog = inject(NxDialog);
  private readonly toast = inject(NxToast);
  private readonly router = inject(Router);
  private readonly logger = inject(LoggerService);
  private readonly injector = inject(Injector);
  private readonly destroyRef = inject(DestroyRef);

  /** The propagation lines of a completed revoke (design §9.3), shown by the tab. */
  readonly revoked = output<readonly string[]>();

  /** The person no longer holds the role (a 204 or a convergent 404): member counts changed. */
  readonly assignmentsChanged = output<void>();

  protected readonly copy = CONSOLE_COPY;
  protected readonly titleId = TITLE_ID;
  protected readonly titleStart = TITLE_START;
  protected readonly titleMiddle = TITLE_MIDDLE;
  protected readonly titleEnd = TITLE_END;
  protected readonly dialogWaitId = DIALOG_WAIT_ID;
  protected readonly tabWaitId = TAB_WAIT_ID;

  private readonly standardTemplate = viewChild.required<TemplateRef<unknown>>('standardDialog');
  private ref: RevokeDialogRef | null = null;

  /** The revoke being confirmed or sent; one at a time (FR-G5). */
  protected readonly active = signal<ActiveRevoke | null>(null);
  protected readonly revoking = signal(false);
  protected readonly dialogError = signal<ConsoleErrorView | null>(null);
  protected readonly tabError = signal<ConsoleErrorView | null>(null);
  /** What each role grants, for the "They will lose" line; kept for this page (design §6.5). */
  private readonly losses = signal<ReadonlyMap<string, LoadState<readonly PermissionResponse[]>>>(
    new Map(),
  );

  /** Holds every Remove control after a 429 or 503 until the wait is over (design §7.4). */
  private readonly wait = createRetryCountdown(this.destroyRef);
  protected readonly waiting = this.wait.active;
  protected readonly waitText = computed(() =>
    format(CONSOLE_COPY.revoke.wait, { n: this.wait.remaining() }),
  );

  /** The rows' Remove buttons: off unless the live profile is ready (Q8), and while held. */
  readonly controlOff = computed(
    () => !this.profile.mutationsEnabled() || this.revoking() || this.waiting(),
  );

  /** The rows' Remove buttons point at the wait while one holds them. */
  readonly controlDescribedBy = computed(() => (this.waiting() ? TAB_WAIT_ID : ''));

  /** The person the page is about, once read. */
  protected readonly target = computed(() => {
    const state = this.store.state();
    return state.status === 'ready' ? state.data : null;
  });

  /** The title's `{person}`: the address in email mode, or "this person" without an entry. */
  protected readonly person = computed<{ readonly text: string; readonly mode: UserTextMode }>(
    () => {
      const target = this.target();
      return target === null
        ? { text: CONSOLE_COPY.assign.person, mode: 'text' }
        : { text: target.email, mode: 'email' };
    },
  );

  protected readonly loss = computed<LossView>(() => {
    const active = this.active();
    if (active === null || !this.profile.can('role:read')) return GENERIC;
    const state = this.losses().get(active.roleId);
    if (state === undefined || state.status === 'idle' || state.status === 'loading')
      return LOADING;
    if (state.status === 'error' || state.data.length === 0) return GENERIC;
    return {
      kind: 'ready',
      text: format(CONSOLE_COPY.revoke.loses, {
        labels: state.data
          .map((entry) => permissionLabel(entry.name) ?? entry.name)
          .join(CONSOLE_COPY.save.listSeparator),
      }),
    };
  });

  protected readonly canConfirm = computed(() => !this.revoking() && !this.waiting());

  protected readonly confirmDescribedBy = computed(() => (this.waiting() ? DIALOG_WAIT_ID : ''));

  constructor() {
    this.destroyRef.onDestroy(() => this.ref?.close());
  }

  /**
   * Opens the Revoke dialog for one of the page's assignments: the typed self variant or the
   * standard one (D-5). Ignored while the controls are off or another revoke is open.
   */
  open(row: RevokeTarget): void {
    const userId = this.store.userId();
    if (this.controlOff() || this.active() !== null || userId === null) return;
    const adminHint = this.adminHint(row.roleId);
    const active: ActiveRevoke = {
      roleId: row.roleId,
      roleName: row.roleName,
      userId,
      adminHint,
      variant: chooseRevokeVariant({
        routeUserId: userId,
        callerUserId: this.profile.userId(),
        adminHint,
      }),
    };
    this.active.set(active);
    this.dialogError.set(null);
    this.tabError.set(null);
    if (active.variant === 'self') {
      this.openSelf(active);
    } else {
      this.openStandard(active);
    }
  }

  protected close(): void {
    if (this.revoking()) return;
    this.ref?.close();
  }

  protected confirm(): void {
    const active = this.active();
    const ref = this.ref;
    if (!this.canConfirm() || active === null || ref === null) return;
    this.send(active, ref);
  }

  private openSelf(active: ActiveRevoke): void {
    this.dialog
      .confirmTyped({
        title: format(CONSOLE_COPY.revoke.selfTitle, { role: active.roleName }),
        message: CONSOLE_COPY.revoke.selfMessage,
        expectedText: active.roleName,
        confirmLabel: CONSOLE_COPY.revoke.selfConfirm,
        cancelLabel: CONSOLE_COPY.revoke.cancel,
      })
      .afterClosed()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((confirmed) => {
        if (confirmed === true) {
          this.send(active, null);
        } else {
          this.active.set(null);
        }
      });
  }

  private openStandard(active: ActiveRevoke): void {
    if (this.profile.can('role:read')) this.readLoss(active.roleId);
    const ref = this.dialog.openTemplate<void>(this.standardTemplate(), {
      ariaLabelledBy: TITLE_ID,
      autoFocus: `#${TITLE_ID}`,
    });
    this.ref = ref;
    ref
      .afterClosed()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(() => {
        this.ref = null;
        this.active.set(null);
        this.dialogError.set(null);
      });
  }

  /** One `DELETE`; `ref` is the open standard dialog, or `null` after the typed confirm. */
  private send(active: ActiveRevoke, ref: RevokeDialogRef | null): void {
    if (this.revoking()) return;
    this.revoking.set(true);
    if (ref !== null) ref.disableClose = true;
    this.dialogError.set(null);
    this.api
      .revokeRole(active.userId, active.roleId)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => this.removed(active, ref, false),
        error: (error: unknown) => {
          const appError = toAppError(error);
          if (appError.code === 'ROLE_ASSIGNMENT_NOT_FOUND') {
            this.removed(active, ref, true);
            return;
          }
          this.failed(active, ref, appError);
        },
      });
  }

  /** A 204, or `ROLE_ASSIGNMENT_NOT_FOUND`: the person no longer holds the role (FR-G3). */
  private removed(active: ActiveRevoke, ref: RevokeDialogRef | null, already: boolean): void {
    this.revoking.set(false);
    if (ref === null) {
      this.active.set(null);
    } else {
      ref.disableClose = false;
      ref.close();
    }
    this.logger.info('Access console role revoked', {
      event: 'access_console_role_revoked',
      context: {
        action: 'revoke',
        userId: active.userId,
        roleId: active.roleId,
        convergent: already,
        variant: active.variant,
      },
    });
    if (!already) this.revoked.emit(propagationFor('revoke'));
    this.store.loadAssignments();
    this.assignmentsChanged.emit();
    if (active.userId === this.profile.userId()) {
      this.ownAccessChanged(active.variant === 'self');
      return;
    }
    this.toast.success(
      already ? RbacErrorMessages.ROLE_ASSIGNMENT_NOT_FOUND.body : CONSOLE_COPY.revoke.success,
    );
  }

  /**
   * The caller's own access changed. The profile re-read renews the session through the
   * interceptor if the epoch moved; nothing here refreshes it (RC-65). The toast and the navigation
   * wait for that read to settle (design §6.3 order), so the shared refresh has already updated
   * `AuthStore`, and with it nav, when the dashboard opens.
   */
  private ownAccessChanged(leave: boolean): void {
    this.profile.reload('own-access-change');
    // `settled`, not the state: a re-read keeps the last profile `ready` while it runs.
    toObservable(this.profile.settled, { injector: this.injector })
      .pipe(
        first((settled) => settled),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe(() => {
        this.toast.info(CONSOLE_COPY.save.ownAccess);
        if (leave) void this.router.navigateByUrl('/dashboard');
      });
  }

  /** Every other failure stays inline; nothing changed (design §11.4). */
  private failed(active: ActiveRevoke, ref: RevokeDialogRef | null, error: AppError): void {
    this.revoking.set(false);
    const view = resolveConsoleError(error, { area: 'assignments', action: 'revoke' });
    if (ref === null) {
      this.active.set(null);
      this.tabError.set(view);
    } else {
      ref.disableClose = false;
      this.dialogError.set(view);
    }
    this.logger.warn('Access console revoke failed', {
      event: 'access_console_action_failed',
      errorCode: error.code,
      correlationId: error.correlationId,
      context: {
        action: 'revoke',
        userId: active.userId,
        roleId: active.roleId,
        variant: active.variant,
        reason: error.reason,
        traceId: error.traceId,
      },
    });
    if (DENIED.has(error.code)) {
      // The live profile predicted this was allowed: read it again.
      this.profile.reload('denied-predicted-allowed');
    }
    if (view.showsWait) this.wait.start(view.retryAfterSeconds ?? DEFAULT_RETRY_AFTER_SECONDS);
  }

  /** The admin hint (Q17), or `null` while the role or the catalogue total is not loaded. */
  private adminHint(roleId: string): boolean | null {
    const roles = this.roles.state();
    const catalogue = this.catalogue.state();
    if (roles.status !== 'ready' || catalogue.status !== 'ready') return null;
    const role = roles.data.roles.find((entry) => entry.id === roleId);
    return role === undefined ? null : isAdminDefiningHint(role, catalogue.data.total);
  }

  private readLoss(roleId: string): void {
    const cached = this.losses().get(roleId);
    if (cached !== undefined && cached.status !== 'error') return;
    this.setLoss(roleId, { status: 'loading' });
    this.api
      .getRolePermissions(roleId)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (set) =>
          this.setLoss(roleId, { status: 'ready', data: set.permissions, loadedAt: Date.now() }),
        error: (error: unknown) => {
          const appError = toAppError(error);
          this.logger.warn('Access console could not read what a role grants', {
            event: 'access_console_load_failed',
            errorCode: appError.code,
            correlationId: appError.correlationId,
            context: { area: 'roles', action: 'revoke', roleId, traceId: appError.traceId },
          });
          this.setLoss(roleId, { status: 'error', error: appError, failedAt: Date.now() });
        },
      });
  }

  private setLoss(roleId: string, state: LoadState<readonly PermissionResponse[]>): void {
    const next = new Map(this.losses());
    next.set(roleId, state);
    this.losses.set(next);
  }
}

/**
 * The Remove button of one assignment row (design §12.8): `danger`, named with the role, off with
 * {@link RevokeDialogs.controlOff} and pointing at the wait while one holds it. Its own width in
 * the table; full width in the 320 px card layout.
 */
@Component({
  selector: 'app-revoke-button',
  imports: [NxButton],
  template: `
    <nx-button
      variant="danger"
      size="sm"
      leadingIcon="person_remove"
      [fullWidth]="true"
      [ariaLabel]="label()"
      [ariaDisabled]="dialogs().controlOff()"
      [ariaDescribedBy]="dialogs().controlDescribedBy()"
      (clicked)="dialogs().open(target())"
      >{{ copy.revoke.open }}</nx-button
    >
  `,
  styles: `
    :host {
      display: inline-block;
    }

    @media (max-width: 599px) {
      :host {
        display: block;
      }
    }
  `,
})
export class RevokeButton {
  readonly dialogs = input.required<RevokeDialogs>();
  readonly target = input.required<RevokeTarget>();
  /** The accessible name: "Remove {role}". */
  readonly label = input.required<string>();

  protected readonly copy = CONSOLE_COPY;
}

function toAppError(error: unknown): AppError {
  return isAppError(error)
    ? error
    : { code: 'UNEXPECTED_ERROR', message: 'The role could not be removed.' };
}
