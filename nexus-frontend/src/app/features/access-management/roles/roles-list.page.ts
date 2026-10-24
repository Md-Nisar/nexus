import { DatePipe } from '@angular/common';
import { Component, OnInit, computed, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AuthStore } from '../../../core/auth/auth.store';
import {
  NxBanner,
  NxButton,
  NxEmptyState,
  NxPageHeader,
  NxSearchField,
  NxSelect,
  NxSkeleton,
  NxTable,
  NxTableCellDef,
  SelectOption,
  TableColumn,
} from '../../../shared/ui';
import { CONSOLE_COPY, format } from '../copy/console-copy';
import { resolveConsoleError } from '../copy/resolve-console-error';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { RolesStore } from '../data/roles.store';
import { ConsoleErrorPanel } from '../ui/console-error-panel';
import { SystemRoleBadge } from '../ui/system-role-badge';
import { UserText } from '../ui/user-text';
import { ROLE_PAGE_SIZE, parseRoleFilter, queryRoles } from '../util/role-list-query';

/** One table row. It extends `Record<string, unknown>` to satisfy `NxTable`'s row constraint. */
interface RoleRow extends Record<string, unknown> {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly isSystemRole: boolean;
  readonly permissionCount: number;
  readonly memberCount: number;
  readonly createdAt: string;
}

/** A positive whole number in the URL, or the first page. The URL is 1-based; this is 0-based. */
function pageIndexFromParam(raw: string | null): number {
  return raw !== null && /^[1-9]\d{0,8}$/.test(raw) ? Number(raw) - 1 : 0;
}

/**
 * The roles list (US-020 design §12.2): every role of the tenant, searchable, filterable and
 * paged in the browser.
 *
 * - **Data:** {@link RolesStore.loadAll} fetches every page once per console session; this page
 *   only reads it, so a repeat visit sends no request (§6.5).
 * - **URL is the state (FR-G1):** `q`, `filter` and `page` (1-based, omitted on the first page)
 *   live in the query string, so Back, Forward and reload restore the view. The page derives
 *   everything from the URL; the controls only navigate.
 * - **User text:** names and descriptions render through {@link UserText}, by interpolation only.
 *   Each name links to its role detail page.
 * - **Create role** is shown from the live profile (`role:write`), not the JWT. When the profile
 *   could not be read it stays visible, off, with the reason. The server decides.
 * - **Logging:** this page logs nothing; search text and role names never leave the page.
 */
@Component({
  selector: 'app-roles-list-page',
  imports: [
    DatePipe,
    FormsModule,
    RouterLink,
    NxBanner,
    NxButton,
    NxEmptyState,
    NxPageHeader,
    NxSearchField,
    NxSelect,
    NxSkeleton,
    NxTable,
    NxTableCellDef,
    ConsoleErrorPanel,
    SystemRoleBadge,
    UserText,
  ],
  templateUrl: './roles-list.page.html',
  styleUrl: './roles-list.page.scss',
})
export class RolesListPage implements OnInit {
  private readonly store = inject(RolesStore);
  private readonly profile = inject(AuthorizationProfileStore);
  private readonly authStore = inject(AuthStore);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  protected readonly copy = CONSOLE_COPY;
  protected readonly pageSize = ROLE_PAGE_SIZE;
  protected readonly pageSizeOptions = [ROLE_PAGE_SIZE];
  protected readonly createReasonId = 'roles-create-reason';
  protected readonly skeletonRows = [0, 1, 2, 3, 4, 5];

  protected readonly filterOptions: SelectOption<string>[] = [
    { label: CONSOLE_COPY.roles.filterAll, value: 'all' },
    { label: CONSOLE_COPY.roles.filterSystem, value: 'system' },
    { label: CONSOLE_COPY.roles.filterCustom, value: 'custom' },
  ];

  protected readonly columns: TableColumn[] = [
    { key: 'name', header: CONSOLE_COPY.roles.columns.name, type: 'custom' },
    { key: 'type', header: CONSOLE_COPY.roles.columns.type, type: 'custom' },
    { key: 'description', header: CONSOLE_COPY.roles.columns.description, type: 'custom' },
    { key: 'permissions', header: CONSOLE_COPY.roles.columns.permissions, type: 'custom' },
    { key: 'members', header: CONSOLE_COPY.roles.columns.members, type: 'custom' },
    { key: 'created', header: CONSOLE_COPY.roles.columns.created, type: 'custom' },
  ];

  private readonly params = toSignal(this.route.queryParamMap, { requireSync: true });
  protected readonly q = computed(() => this.params().get('q') ?? '');
  protected readonly filter = computed(() => parseRoleFilter(this.params().get('filter')));
  private readonly requestedPage = computed(() => pageIndexFromParam(this.params().get('page')));

  protected readonly status = computed(() => this.store.state().status);

  private readonly data = computed(() => {
    const state = this.store.state();
    return state.status === 'ready' ? state.data : null;
  });

  private readonly result = computed(() =>
    queryRoles(this.data()?.roles ?? [], {
      q: this.q(),
      filter: this.filter(),
      page: this.requestedPage(),
      size: ROLE_PAGE_SIZE,
    }),
  );

  protected readonly rows = computed<RoleRow[]>(() =>
    this.result().rows.map((role) => ({
      id: role.id,
      name: role.name,
      description: role.description,
      isSystemRole: role.isSystemRole,
      permissionCount: role.permissionCount,
      memberCount: role.memberCount,
      createdAt: role.createdAt,
    })),
  );

  protected readonly total = computed(() => this.result().total);
  protected readonly page = computed(() => this.result().page);
  protected readonly pageCount = computed(() => this.result().pageCount);

  protected readonly countText = computed(() =>
    this.total() === 1
      ? CONSOLE_COPY.roles.resultCountOne
      : format(CONSOLE_COPY.roles.resultCount, { n: this.total() }),
  );

  protected readonly truncated = computed(() => this.data()?.truncated === true);
  protected readonly truncatedText = computed(() =>
    format(CONSOLE_COPY.roles.truncated, { n: this.data()?.roles.length ?? 0 }),
  );

  protected readonly loadingText = computed(() => {
    const progress = this.store.progress();
    return progress === null
      ? CONSOLE_COPY.roles.loadingUnknown
      : format(CONSOLE_COPY.roles.loadingCount, {
          loaded: progress.loaded,
          total: progress.total,
        });
  });

  /** Why the list is empty: nothing matched, or there is no custom role at all. */
  protected readonly emptyKind = computed<'search' | 'custom'>(() =>
    this.q().trim() !== '' || this.filter() === 'system' ? 'search' : 'custom',
  );

  private readonly failure = computed(() => {
    const state = this.store.state();
    return state.status === 'error' ? state : null;
  });
  protected readonly errorView = computed(() => {
    const failure = this.failure();
    return failure === null
      ? null
      : resolveConsoleError(failure.error, { area: 'roles', action: 'load' });
  });
  protected readonly failedAt = computed(() => this.failure()?.failedAt);

  /**
   * "Create role" from the live profile: shown with `role:write`; kept, but off with a reason,
   * when the profile could not be read although the JWT holds `role:write`; otherwise hidden.
   */
  protected readonly createState = computed<'enabled' | 'disabled' | 'hidden'>(() => {
    if (this.profile.can('role:write')) return 'enabled';
    const unreadable = this.profile.state().status === 'error';
    return unreadable && this.authStore.permissions().includes('role:write')
      ? 'disabled'
      : 'hidden';
  });

  ngOnInit(): void {
    this.store.loadAll();
  }

  /** The row behind a table cell. The rows are this page's own {@link RoleRow}s. */
  protected row(cell: Record<string, unknown>): RoleRow {
    return cell as RoleRow;
  }

  protected retry(): void {
    this.store.loadAll();
  }

  protected create(): void {
    if (this.createState() !== 'enabled') return;
    void this.router.navigate(['/admin/access/roles/new']);
  }

  protected onSearch(q: string): void {
    this.navigate({ q: q === '' ? null : q, page: null });
  }

  protected onSearchCleared(): void {
    this.navigate({ q: null, page: null });
  }

  protected onFilter(value: string | string[]): void {
    const filter = parseRoleFilter(typeof value === 'string' ? value : null);
    this.navigate({ filter: filter === 'all' ? null : filter, page: null });
  }

  protected onPageChange(event: { readonly pageIndex: number }): void {
    this.navigate({ page: event.pageIndex === 0 ? null : String(event.pageIndex + 1) });
  }

  private navigate(params: Record<string, string | null>): void {
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: params,
      queryParamsHandling: 'merge',
    });
  }
}
