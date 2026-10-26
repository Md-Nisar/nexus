import { DatePipe } from '@angular/common';
import { Component, computed, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthStore } from '../../../core/auth/auth.store';
import {
  NxButton,
  NxEmptyState,
  NxSkeleton,
  NxTable,
  NxTableCellDef,
  TableColumn,
} from '../../../shared/ui';
import type { RoleResponse } from '../../../shared/types/api/rbac';
import { CONSOLE_COPY } from '../copy/console-copy';
import { resolveConsoleError } from '../copy/resolve-console-error';
import { DirectoryCache } from '../data/directory-cache';
import { RolesStore } from '../data/roles.store';
import { ConsoleErrorPanel } from '../ui/console-error-panel';
import { SystemRoleBadge } from '../ui/system-role-badge';
import { UserText } from '../ui/user-text';
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
 * Assign and Revoke arrive in T-017 and T-018.
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
    ConsoleErrorPanel,
    SystemRoleBadge,
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

  protected readonly copy = CONSOLE_COPY;
  protected readonly skeletonRows = [0, 1, 2];

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

  constructor() {
    // The join leaves together with the assignments read, and only where a table can show it.
    if (this.store.canReadAssignments() && this.canReadRoles()) this.roles.loadAll();
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
}
