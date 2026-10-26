import { DatePipe } from '@angular/common';
import {
  Component,
  DestroyRef,
  TemplateRef,
  computed,
  inject,
  signal,
  viewChild,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';
import { AuthStore } from '../../../core/auth/auth.store';
import { LoggerService } from '../../../core/logging/logger.service';
import {
  ButtonVariant,
  NxBanner,
  NxButton,
  NxDialog,
  NxEmptyState,
  NxSearchField,
  NxSkeleton,
  NxTable,
  NxTableCellDef,
  NxToast,
  TableColumn,
} from '../../../shared/ui';
import type { PermissionResponse, RoleResponse } from '../../../shared/types/api/rbac';
import { AppError, isAppError } from '../../../shared/types/app-error';
import { CONSOLE_COPY, RbacErrorMessages, format } from '../copy/console-copy';
import { permissionLabel } from '../copy/permission-labels';
import { propagationFor } from '../copy/propagation';
import { ConsoleErrorView, resolveConsoleError } from '../copy/resolve-console-error';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { CatalogueStore } from '../data/catalogue.store';
import { DirectoryCache } from '../data/directory-cache';
import type { LoadState } from '../data/load-state';
import { RbacApi } from '../data/rbac-api';
import { RolesStore } from '../data/roles.store';
import { ConsoleErrorPanel } from '../ui/console-error-panel';
import { SystemRoleBadge } from '../ui/system-role-badge';
import { TargetIdentity } from '../ui/target-identity';
import { UserText } from '../ui/user-text';
import {
  AssignAffordance,
  AssignButtonReason,
  AssignContext,
  AssignReason,
  PENDING_ADMIN_ROLE_BLOCK,
  assignButtonAffordance,
  assignConfirmKind,
  roleAssignAffordance,
} from '../util/affordances';
import { DEFAULT_RETRY_AFTER_SECONDS, createRetryCountdown } from '../util/retry-after';
import { UserDetailStore } from './user-detail.store';

/** Codes of a refused assignments read: shown as the "no user:read" state (design §7.1). */
const FORBIDDEN_CODES: ReadonlySet<string> = new Set(['RBAC_001', 'ACCESS_DENIED']);

/** One table row. It extends `Record<string, unknown>` to satisfy `NxTable`'s row constraint. */
interface AssignmentRow extends Record<string, unknown> {
  readonly roleId: string;
  readonly roleName: string;
  readonly assignedAt: string;
  /** The assigner's id; `null` where the server does not show it. */
  readonly assignedBy: string | null;
  /** The assigner's address, only when the directory cache already holds it. */
  readonly assignedByEmail: string | null;
  /** From the roles join; `null` when the role's details are not available. */
  readonly isSystemRole: boolean | null;
}

/** What the tab shows. */
type RolesTabView = 'no-user-read' | 'loading' | 'error' | 'empty' | 'table';

/** Codes of a 403 the live profile predicted would be allowed (design §2.2). */
const DENIED: ReadonlySet<string> = new Set(['RBAC_001', 'ACCESS_DENIED']);

const ASSIGN_TITLE_ID = 'assign-dialog-title';
const ASSIGN_WAIT_ID = 'assign-dialog-wait';
const ASSIGN_BUTTON_REASON_ID = 'user-roles-assign-reason';
const ASSIGN_SELECTED_REASON_ID = 'assign-dialog-selected-reason';

const [ASSIGN_TITLE_BEFORE, ASSIGN_TITLE_AFTER = ''] = CONSOLE_COPY.assign.title.split('{person}');

const ASSIGN_REASON_COPY: Readonly<
  Record<Exclude<AssignReason, 'role-needs-more-access'>, string>
> = {
  'already-assigned': CONSOLE_COPY.disabledReason.alreadyAssigned,
  'admin-only-directory': CONSOLE_COPY.disabledReason.adminOnlyDirectory,
  'pending-admin-role': CONSOLE_COPY.disabledReason.pendingAdminRole,
};

const ASSIGN_BUTTON_REASON_COPY: Readonly<Record<AssignButtonReason, string | null>> = {
  // While the profile loads the button is simply busy; there is nothing to explain yet.
  'profile-loading': null,
  'profile-unavailable': CONSOLE_COPY.disabledReason.profileUnavailable,
  'self-assign': CONSOLE_COPY.disabledReason.selfAssign,
  'no-role-read': CONSOLE_COPY.disabledReason.noRoleRead,
};

/** One role offered in the Assign dialog's picker. */
interface Candidate {
  readonly role: RoleResponse;
  readonly countText: string;
  /** The visible reason of a role that cannot be chosen, or `null`. */
  readonly reason: string | null;
  /** The radio is off: a reason applies, or an assign is running. */
  readonly disabled: boolean;
  readonly reasonId: string;
}

/** The selected-role panel (design §12.9). */
type SelectedView =
  | { readonly kind: 'none' }
  | { readonly kind: 'loading' }
  | { readonly kind: 'error' }
  | {
      readonly kind: 'ready';
      readonly grants: string;
      readonly reason: string | null;
      readonly hint: string | null;
    };

type AssignDialogRef = ReturnType<NxDialog['openTemplate']>;

const BASE_COLUMNS: readonly TableColumn[] = [
  { key: 'role', header: CONSOLE_COPY.userRoles.columns.role, type: 'custom' },
  { key: 'type', header: CONSOLE_COPY.userRoles.columns.type, type: 'custom' },
  { key: 'assigned', header: CONSOLE_COPY.userRoles.columns.assigned, type: 'custom' },
];
const ASSIGNED_BY_COLUMN: TableColumn = {
  key: 'assignedBy',
  header: CONSOLE_COPY.userRoles.columns.assignedBy,
  type: 'custom',
};

/**
 * The roles a person holds (US-020 design §6.1, §6.5 "User page", §12.8; Q19, FR-C2, FR-X5).
 * The {@link UserDetailPage} loads the user and the assignments; this tab renders them and adds
 * the roles join.
 *
 * - **Without `user:read`** (JWT), or when the server refuses the read (403): the empty state
 *   "You need permission to read users' roles to see this." The assignments are never requested
 *   without it, and neither is the join.
 * - **Roles join** (`role:read` only): {@link RolesStore}'s fetch-all, reused when already
 *   `ready`, gives each row its System or Custom badge, and the role name becomes a link. Without
 *   `role:read` there is no request, no link, a dash for Type and the note "Role details are
 *   hidden…". A failed join keeps the table and offers Retry beside it.
 * - **Assigned by** is shown only for a non-null value: the address when the
 *   {@link DirectoryCache} already holds it (never fetched for this), otherwise the id. The column
 *   appears only when some row has one.
 * - **States:** loading, zero roles ("No roles assigned"), the flag off ("Role assignment isn't
 *   enabled"), error and 503 through the console error panel, whose Retry re-reads the
 *   assignments only.
 * - Role names and addresses render through {@link UserText} by interpolation only.
 *
 * **Assign** (T-017; design §8.3, §12.9; RC-68, RC-69, H-2, D-4; FR-C3, FR-C4, FR-G5, FR-G6):
 * - **"Assign role"** follows the live profile (ADR-0028): hidden without `user:role:assign`; off
 *   with its reason on the caller's own page for a non-administrator (by user id), without
 *   `role:read` (the picker needs it), and while the profile cannot be read.
 * - **The dialog** (`NxDialog.openTemplate`, at most one open) is titled with the address through
 *   {@link UserText} and shows {@link TargetIdentity} under the title, so status, Verified and
 *   hidden-character badges are visible at the moment of choice. A PENDING target adds the RC-69
 *   risk warning (`role=alert`) and the "Assign to unverified account" (`danger`) confirm.
 * - **Picker:** the {@link RolesStore} list (opening sends nothing), filtered by a search; each
 *   role that cannot be chosen keeps its visible reason (`roleAssignAffordance`). Choosing one reads
 *   `GET /roles/{id}/permissions` once, cached for the dialog's life; the pigeonhole pre-check and
 *   the other static rules decide without a request.
 * - **H-2 / D-4:** for a PENDING target an admin-looking role, or every role while the catalogue
 *   total is unknown, is disabled. The catalogue total is read from {@link CatalogueStore} only if
 *   it is already loaded; this tab never requests it. The block is the code constant
 *   `PENDING_ADMIN_ROLE_BLOCK`; nothing at run time switches it.
 * - **Confirm:** one `POST` (re-sent once on `RBAC_012` in `RbacApi`). A 201 or `RBAC_004`
 *   (convergent) closes the dialog with a toast, shows the grant propagation line on the tab and
 *   re-reads the list. Every other failure stays inline with the dialog open; a 403 also re-reads
 *   the profile, and a 429 holds the confirm for the wait with a countdown (no automatic retry).
 *   An administrator assigning to themself re-reads the live profile ("own access").
 * - **PII:** the address is never in a toast, a log or `document.title`; logs carry ids and codes.
 *
 * Revoke arrives in T-018.
 *
 * @security UX only. The server decides every request.
 */
@Component({
  selector: 'app-user-roles-tab',
  imports: [
    DatePipe,
    RouterLink,
    NxButton,
    NxEmptyState,
    NxSkeleton,
    NxTable,
    NxTableCellDef,
    NxBanner,
    NxSearchField,
    ConsoleErrorPanel,
    SystemRoleBadge,
    TargetIdentity,
    UserText,
  ],
  templateUrl: './user-roles.tab.html',
  styleUrl: './user-roles.tab.scss',
})
export class UserRolesTab {
  private readonly store = inject(UserDetailStore);
  private readonly roles = inject(RolesStore);
  private readonly cache = inject(DirectoryCache);
  private readonly authStore = inject(AuthStore);
  private readonly profile = inject(AuthorizationProfileStore);
  private readonly catalogue = inject(CatalogueStore);
  private readonly api = inject(RbacApi);
  private readonly dialog = inject(NxDialog);
  private readonly toast = inject(NxToast);
  private readonly logger = inject(LoggerService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly copy = CONSOLE_COPY;
  protected readonly skeletonRows = [0, 1, 2];
  protected readonly assignTitleId = ASSIGN_TITLE_ID;
  protected readonly assignTitleBefore = ASSIGN_TITLE_BEFORE;
  protected readonly assignTitleAfter = ASSIGN_TITLE_AFTER;
  protected readonly assignWaitId = ASSIGN_WAIT_ID;
  protected readonly assignButtonReasonId = ASSIGN_BUTTON_REASON_ID;
  protected readonly selectedReasonId = ASSIGN_SELECTED_REASON_ID;

  private readonly assignTemplate = viewChild.required<TemplateRef<unknown>>('assignDialog');
  private assignRef: AssignDialogRef | null = null;
  private permissionReads: Subscription[] = [];

  /**
   * The H-2 block (D-4): always {@link PENDING_ADMIN_ROLE_BLOCK}. Nothing in the application writes
   * it; only a spec sets it off, to pin the post-F-4 typed confirm.
   */
  private readonly pendingAdminRoleBlock = signal(PENDING_ADMIN_ROLE_BLOCK);

  /** The picker's search text (in memory only). */
  protected readonly assignSearch = signal('');
  protected readonly selectedRoleId = signal<string | null>(null);
  /** Each chosen role's permissions, for the dialog's life (design §6.5). */
  private readonly permissionCache = signal<
    ReadonlyMap<string, LoadState<readonly PermissionResponse[]>>
  >(new Map());
  protected readonly assigning = signal(false);
  protected readonly assignError = signal<ConsoleErrorView | null>(null);
  /** The grant propagation line after an assign (design §9.3), shown on the tab. */
  protected readonly propagation = signal<readonly string[]>([]);

  /** Holds the confirm after a 429 or 503 until the wait is over (design §7.4). */
  private readonly wait = createRetryCountdown(this.destroyRef);
  protected readonly waiting = this.wait.active;
  protected readonly waitText = computed(() =>
    format(CONSOLE_COPY.assign.wait, { n: this.wait.remaining() }),
  );

  /** The JWT holds `role:read`: the join is requested and role names link. UX only. */
  protected readonly canReadRoles = computed(() =>
    this.authStore.permissions().includes('role:read'),
  );

  private readonly failure = computed(() => {
    const state = this.store.assignments();
    return state.status === 'error' ? state : null;
  });

  protected readonly view = computed<RolesTabView>(() => {
    if (!this.store.canReadAssignments()) return 'no-user-read';
    const state = this.store.assignments();
    switch (state.status) {
      case 'error':
        return FORBIDDEN_CODES.has(state.error.code) ? 'no-user-read' : 'error';
      case 'ready':
        return state.data.assignments.length === 0 ? 'empty' : 'table';
      default:
        return 'loading';
    }
  });

  protected readonly errorView = computed(() => {
    const failure = this.failure();
    return failure === null
      ? null
      : resolveConsoleError(failure.error, { area: 'assignments', action: 'load' });
  });

  protected readonly failedAt = computed(() => this.failure()?.failedAt);

  private readonly joined = computed<ReadonlyMap<string, RoleResponse> | null>(() => {
    if (!this.canReadRoles()) return null;
    const state = this.roles.state();
    return state.status === 'ready'
      ? new Map(state.data.roles.map((role) => [role.id, role]))
      : null;
  });

  protected readonly joinFailed = computed(
    () => this.canReadRoles() && this.roles.state().status === 'error',
  );

  protected readonly rows = computed<AssignmentRow[]>(() => {
    const state = this.store.assignments();
    if (state.status !== 'ready') return [];
    const joined = this.joined();
    return state.data.assignments.map((assignment) => ({
      roleId: assignment.roleId,
      roleName: assignment.roleName,
      assignedAt: assignment.assignedAt,
      assignedBy: assignment.assignedBy,
      assignedByEmail:
        assignment.assignedBy === null ? null : this.cache.email(assignment.assignedBy),
      isSystemRole: joined?.get(assignment.roleId)?.isSystemRole ?? null,
    }));
  });

  protected readonly columns = computed<TableColumn[]>(() =>
    this.rows().some((row) => row.assignedBy !== null)
      ? [...BASE_COLUMNS, ASSIGNED_BY_COLUMN]
      : [...BASE_COLUMNS],
  );

  /** The person the page is about, once read. */
  protected readonly target = computed(() => {
    const state = this.store.state();
    return state.status === 'ready' ? state.data : null;
  });

  protected readonly targetIsPending = computed(() => this.target()?.status === 'PENDING');

  /** The "Assign role" button, from the live profile (ADR-0028); JWT only while it loads. */
  protected readonly assignButton = computed(() => {
    const status = this.profile.state().status;
    const ready = status === 'ready';
    const self = this.profile.userId();
    return assignButtonAffordance({
      profileStatus: status,
      canAssign: ready
        ? this.profile.can('user:role:assign')
        : this.authStore.permissions().includes('user:role:assign'),
      canReadRoles: ready && this.profile.can('role:read'),
      isSelf: self !== null && self === this.store.userId(),
      isAdministrator: ready && this.profile.isAdministrator(),
    });
  });

  protected readonly assignButtonReason = computed(() => {
    const button = this.assignButton();
    return button.kind === 'disabled' ? ASSIGN_BUTTON_REASON_COPY[button.reason] : null;
  });

  protected readonly assignShown = computed(() => this.assignButton().kind !== 'hidden');
  protected readonly assignOff = computed(() => this.assignButton().kind !== 'enabled');
  /** Off without a reason: the live profile is still loading. */
  protected readonly assignBusy = computed(
    () => this.assignButton().kind === 'disabled' && this.assignButtonReason() === null,
  );
  protected readonly assignDescribedBy = computed(() =>
    this.assignButtonReason() === null ? '' : ASSIGN_BUTTON_REASON_ID,
  );

  private readonly assignContext = computed<AssignContext>(() => {
    const assignments = this.store.assignments();
    const catalogue = this.catalogue.state();
    return {
      held: this.profile.permissions(),
      isAdministrator: this.profile.isAdministrator(),
      assignedRoleIds: new Set(
        assignments.status === 'ready'
          ? assignments.data.assignments.map((entry) => entry.roleId)
          : [],
      ),
      // Read only when already loaded (design §6.5: opening the dialog sends nothing). Unknown
      // means `null`, which D-4 treats as "every role looks like an administrator role" for a
      // PENDING target.
      catalogueTotal: catalogue.status === 'ready' ? catalogue.data.total : null,
      targetIsPending: this.targetIsPending(),
    };
  });

  /** The roles the picker can offer, from the console's roles list. */
  protected readonly rolesView = computed<'loading' | 'error' | 'ready'>(() => {
    const status = this.roles.state().status;
    return status === 'ready' || status === 'error' ? status : 'loading';
  });

  private readonly allRoles = computed<readonly RoleResponse[]>(() => {
    const state = this.roles.state();
    return state.status === 'ready' ? state.data.roles : [];
  });

  protected readonly candidates = computed<readonly Candidate[]>(() => {
    const query = this.assignSearch().trim().toLocaleLowerCase();
    const ctx = this.assignContext();
    const block = this.pendingAdminRoleBlock();
    const assigning = this.assigning();
    return this.allRoles()
      .filter((role) => query === '' || role.name.toLocaleLowerCase().includes(query))
      .map((role) => {
        const reason = reasonText(roleAssignAffordance(role, ctx, null, block));
        return {
          role,
          countText: format(
            role.permissionCount === 1
              ? CONSOLE_COPY.assign.permissionCountOne
              : CONSOLE_COPY.assign.permissionCount,
            { n: role.permissionCount },
          ),
          reason,
          disabled: reason !== null || assigning,
          reasonId: `assign-role-reason-${role.id}`,
        };
      });
  });

  private readonly selectedRole = computed(() => {
    const id = this.selectedRoleId();
    return id === null ? null : (this.allRoles().find((role) => role.id === id) ?? null);
  });

  private readonly selectedPermissions = computed(() => {
    const role = this.selectedRole();
    return role === null ? undefined : this.permissionCache().get(role.id);
  });

  private readonly selectedAffordance = computed<AssignAffordance | null>(() => {
    const role = this.selectedRole();
    if (role === null) return null;
    const load = this.selectedPermissions();
    const codes = load?.status === 'ready' ? load.data.map((entry) => entry.name) : null;
    return roleAssignAffordance(role, this.assignContext(), codes, this.pendingAdminRoleBlock());
  });

  /** (c) The selected role looks administrator-defining to a non-administrator (Q17: a hint). */
  private readonly selectedHasAdminHint = computed(() => {
    const role = this.selectedRole();
    if (role === null) return false;
    const decided = roleAssignAffordance(
      role,
      this.assignContext(),
      null,
      this.pendingAdminRoleBlock(),
    );
    return decided.kind === 'enabled' && decided.adminHint;
  });

  protected readonly selectedView = computed<SelectedView>(() => {
    const affordance = this.selectedAffordance();
    if (affordance === null) return { kind: 'none' };
    const load = this.selectedPermissions();
    if (load?.status === 'error') return { kind: 'error' };
    if (load?.status !== 'ready') {
      // A role decided without a request still shows why.
      const reason = reasonText(affordance);
      return reason === null
        ? { kind: 'loading' }
        : { kind: 'ready', grants: '', reason, hint: null };
    }
    const labels = load.data.map((entry) => permissionLabel(entry.name) ?? entry.name);
    return {
      kind: 'ready',
      grants:
        labels.length === 0
          ? CONSOLE_COPY.assign.grantsNothing
          : format(CONSOLE_COPY.assign.grants, {
              labels: labels.join(CONSOLE_COPY.save.listSeparator),
            }),
      reason: reasonText(affordance),
      // The hint comes from the rules before the load: a whole-catalogue role also carries
      // `user:directory:read`, so for a non-administrator the PII reason follows it.
      hint: this.selectedHasAdminHint() ? CONSOLE_COPY.hints.adminAssign : null,
    };
  });

  protected readonly canConfirm = computed(() => {
    const affordance = this.selectedAffordance();
    return (
      affordance?.kind === 'enabled' && affordance.checked && !this.assigning() && !this.waiting()
    );
  });

  protected readonly confirmLabel = computed(() =>
    this.targetIsPending() ? CONSOLE_COPY.assign.confirmUnverified : CONSOLE_COPY.assign.confirm,
  );

  protected readonly confirmVariant = computed<ButtonVariant>(() =>
    this.targetIsPending() ? 'danger' : 'primary',
  );

  protected readonly confirmDescribedBy = computed(() => {
    if (this.waiting()) return ASSIGN_WAIT_ID;
    return this.selectedView().kind === 'ready' && reasonText(this.selectedAffordance()) !== null
      ? ASSIGN_SELECTED_REASON_ID
      : '';
  });

  constructor() {
    // The join leaves together with the assignments read, and only where a table can show it.
    if (this.store.canReadAssignments() && this.canReadRoles()) this.roles.loadAll();
    this.destroyRef.onDestroy(() => {
      this.cancelPermissionReads();
      this.assignRef?.close();
    });
  }

  /** The row behind a table cell. The rows are this tab's own {@link AssignmentRow}s. */
  protected row(cell: Record<string, unknown>): AssignmentRow {
    return cell as AssignmentRow;
  }

  protected retry(): void {
    this.store.loadAssignments();
  }

  protected retryJoin(): void {
    this.roles.loadAll();
  }

  /** Opens the Assign dialog, at most once at a time (FR-G5). Opening sends no request. */
  protected openAssign(): void {
    if (this.assignButton().kind !== 'enabled' || this.assignRef !== null) return;
    this.assignSearch.set('');
    this.selectedRoleId.set(null);
    this.permissionCache.set(new Map());
    this.assignError.set(null);
    this.propagation.set([]);
    this.wait.stop();
    // A no-op when the list is ready or loading; reads it only if this page never needed it.
    this.roles.loadAll();
    const ref = this.dialog.openTemplate<void>(this.assignTemplate(), {
      ariaLabelledBy: ASSIGN_TITLE_ID,
      autoFocus: `#${ASSIGN_TITLE_ID}`,
    });
    this.assignRef = ref;
    ref
      .afterClosed()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(() => {
        this.assignRef = null;
        this.cancelPermissionReads();
        this.permissionCache.set(new Map());
        this.selectedRoleId.set(null);
        this.wait.stop();
      });
  }

  protected closeAssign(): void {
    if (this.assigning()) return;
    this.assignRef?.close();
  }

  protected retryRoles(): void {
    this.roles.loadAll();
  }

  /** Chooses a role; reads what it grants once per dialog, unless a rule already decides it. */
  protected selectRole(roleId: string): void {
    if (this.assigning()) return;
    const role = this.allRoles().find((entry) => entry.id === roleId);
    if (role === undefined) return;
    this.selectedRoleId.set(roleId);
    this.assignError.set(null);
    const decided = roleAssignAffordance(
      role,
      this.assignContext(),
      null,
      this.pendingAdminRoleBlock(),
    );
    if (decided.kind === 'disabled') return;
    const cached = this.permissionCache().get(roleId);
    if (cached !== undefined && cached.status !== 'error') return;
    this.readPermissions(roleId);
  }

  protected retryPermissions(): void {
    const roleId = this.selectedRoleId();
    if (roleId !== null) this.readPermissions(roleId);
  }

  /**
   * The confirm. A PENDING target with a role treated as administrator-defining needs the typed
   * confirm with the role name first (reachable only once F-4 lifts the H-2 block). Ignored while
   * a request runs (no double submit) or while the selection is not assignable.
   */
  protected confirmAssign(): void {
    const role = this.selectedRole();
    const userId = this.store.userId();
    const ref = this.assignRef;
    if (!this.canConfirm() || role === null || userId === null || ref === null) return;
    if (assignConfirmKind(role, this.assignContext()) !== 'typed-unverified') {
      this.sendAssign(ref, userId, role.id);
      return;
    }
    this.dialog
      .confirmTyped({
        title: format(CONSOLE_COPY.assign.typedTitle, { role: role.name }),
        message: CONSOLE_COPY.assign.pendingWarning,
        expectedText: role.name,
        confirmLabel: CONSOLE_COPY.assign.confirmUnverified,
        cancelLabel: CONSOLE_COPY.assign.cancel,
      })
      .afterClosed()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((confirmed) => {
        if (confirmed === true && this.assignRef === ref) this.sendAssign(ref, userId, role.id);
      });
  }

  private sendAssign(ref: AssignDialogRef, userId: string, roleId: string): void {
    if (this.assigning()) return;
    this.assigning.set(true);
    ref.disableClose = true;
    this.assignError.set(null);
    this.wait.stop();
    this.api
      .assignRole(userId, roleId)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => this.assigned(ref, userId, roleId, false),
        error: (error: unknown) => {
          const appError = toAppError(error);
          if (appError.code === 'RBAC_004') {
            this.assigned(ref, userId, roleId, true);
            return;
          }
          this.assignFailed(ref, userId, roleId, appError);
        },
      });
  }

  /** A 201, or `RBAC_004`: the person holds the role now (FR-G3 convergence). */
  private assigned(ref: AssignDialogRef, userId: string, roleId: string, already: boolean): void {
    this.assigning.set(false);
    ref.disableClose = false;
    ref.close();
    this.logger.info('Access console role assigned', {
      event: 'access_console_role_assigned',
      context: { action: 'assign', userId, roleId, convergent: already },
    });
    this.propagation.set(propagationFor('assign'));
    this.store.loadAssignments();
    if (userId === this.profile.userId()) {
      // The caller's own access changed. The re-read renews the session through the interceptor
      // if the epoch moved; nothing here refreshes it (RC-65).
      this.profile.reload('own-access-change');
      this.toast.info(CONSOLE_COPY.save.ownAccess);
      return;
    }
    this.toast.success(already ? RbacErrorMessages.RBAC_004.body : CONSOLE_COPY.assign.success);
  }

  /** Every other failure stays in the dialog, which stays open (design §12.9). */
  private assignFailed(
    ref: AssignDialogRef,
    userId: string,
    roleId: string,
    error: AppError,
  ): void {
    this.assigning.set(false);
    ref.disableClose = false;
    const view = resolveConsoleError(error, { area: 'assignments', action: 'assign' });
    this.assignError.set(view);
    this.logger.warn('Access console assign failed', {
      event: 'access_console_action_failed',
      errorCode: error.code,
      correlationId: error.correlationId,
      context: { action: 'assign', userId, roleId, reason: error.reason, traceId: error.traceId },
    });
    if (DENIED.has(error.code)) {
      // The live profile predicted this was allowed: read it again.
      this.profile.reload('denied-predicted-allowed');
    }
    if (view.showsWait) this.wait.start(view.retryAfterSeconds ?? DEFAULT_RETRY_AFTER_SECONDS);
  }

  private readPermissions(roleId: string): void {
    this.setPermissions(roleId, { status: 'loading' });
    const read = this.api
      .getRolePermissions(roleId)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (set) =>
          this.setPermissions(roleId, {
            status: 'ready',
            data: set.permissions,
            loadedAt: Date.now(),
          }),
        error: (error: unknown) => {
          const appError = toAppError(error);
          this.logger.warn('Access console could not read what a role grants', {
            event: 'access_console_load_failed',
            errorCode: appError.code,
            correlationId: appError.correlationId,
            context: { area: 'roles', action: 'assign', roleId, traceId: appError.traceId },
          });
          this.setPermissions(roleId, {
            status: 'error',
            error: appError,
            failedAt: Date.now(),
          });
        },
      });
    this.permissionReads.push(read);
  }

  private setPermissions(roleId: string, state: LoadState<readonly PermissionResponse[]>): void {
    const next = new Map(this.permissionCache());
    next.set(roleId, state);
    this.permissionCache.set(next);
  }

  private cancelPermissionReads(): void {
    for (const read of this.permissionReads) read.unsubscribe();
    this.permissionReads = [];
  }
}

/** The visible reason of a disabled candidate, or `null` when it can be chosen. */
function reasonText(affordance: AssignAffordance | null): string | null {
  if (affordance === null || affordance.kind === 'enabled') return null;
  if (affordance.reason !== 'role-needs-more-access') return ASSIGN_REASON_COPY[affordance.reason];
  return affordance.missing.length === 0
    ? CONSOLE_COPY.disabledReason.roleNeedsMoreAccessUnlisted
    : format(CONSOLE_COPY.disabledReason.roleNeedsMoreAccess, {
        labels: affordance.missing
          .map((code) => permissionLabel(code) ?? code)
          .join(CONSOLE_COPY.save.listSeparator),
      });
}

function toAppError(error: unknown): AppError {
  return isAppError(error)
    ? error
    : { code: 'UNEXPECTED_ERROR', message: 'The role could not be assigned.' };
}
