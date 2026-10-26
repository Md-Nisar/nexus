import { DatePipe } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed, toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, ParamMap, Router, RouterLink } from '@angular/router';
import { distinctUntilChanged, map } from 'rxjs';
import {
  BadgeVariant,
  NxBadge,
  NxButton,
  NxEmptyState,
  NxIcon,
  NxPageHeader,
  NxSearchField,
  NxSelect,
  NxSkeleton,
  NxTable,
  NxTableCellDef,
  SelectOption,
  TableColumn,
} from '../../../shared/ui';
import type { UserDirectoryEntry, UserStatus } from '../../../shared/types/api/user-directory';
import { CONSOLE_COPY, format } from '../copy/console-copy';
import { resolveConsoleError } from '../copy/resolve-console-error';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { ConsoleErrorPanel } from '../ui/console-error-panel';
import { UserStatusBadge } from '../ui/user-status-badge';
import { UserText } from '../ui/user-text';
import { UsersListStore, UsersQuery } from './users-list.store';

/** Rows per page offered; the server allows 1 to 100. The first is not the default. */
const PAGE_SIZES: readonly number[] = [10, 20, 50, 100];
const DEFAULT_PAGE_SIZE = 20;
const STATUSES: readonly UserStatus[] = ['ACTIVE', 'PENDING', 'LOCKED', 'DISABLED'];
/** The status filter's "All" option; never sent and never in the URL. */
const ALL = 'ALL';

/** One table row. It extends `Record<string, unknown>` to satisfy `NxTable`'s row constraint. */
interface UserRow extends Record<string, unknown> {
  readonly userId: string;
  readonly email: string;
  readonly status: UserStatus;
  readonly emailVerified: boolean;
  readonly createdAt: string;
  /** The caller's own row, by profile user id; never by address (FR-G8). */
  readonly isSelf: boolean;
  readonly verified: {
    readonly label: string;
    readonly icon: string;
    readonly variant: BadgeVariant;
  };
}

/** What the content area shows below the toolbar. */
type UsersView =
  | 'loading'
  | 'list'
  | 'empty'
  | 'past-the-end'
  | 'error'
  | 'lookup-loading'
  | 'lookup-hit'
  | 'lookup-miss';

const VERIFIED = {
  label: CONSOLE_COPY.badges.verified,
  icon: 'verified',
  variant: 'success',
} as const;
const UNVERIFIED = {
  label: CONSOLE_COPY.badges.unverified,
  icon: 'unpublished',
  variant: 'warning',
} as const;

/**
 * The query in the URL (FR-G1): `page` 1-based and omitted on the first page, `size` one of
 * {@link PAGE_SIZES} and omitted at the default, `status` lower case and omitted for "All".
 * Anything else gives the default, so a hand-edited link is always a valid view.
 */
function queryFromParams(params: ParamMap): UsersQuery {
  const rawPage = params.get('page');
  const rawSize = Number(params.get('size'));
  const rawStatus = params.get('status')?.toUpperCase() ?? '';
  return {
    page: rawPage !== null && /^[1-9]\d{0,8}$/.test(rawPage) ? Number(rawPage) - 1 : 0,
    size: PAGE_SIZES.includes(rawSize) ? rawSize : DEFAULT_PAGE_SIZE,
    status: STATUSES.find((status) => status === rawStatus) ?? null,
  };
}

function sameQuery(a: UsersQuery, b: UsersQuery): boolean {
  return a.page === b.page && a.size === b.size && a.status === b.status;
}

/**
 * The users list (US-020 design §12.7): the tenant's directory page by page, filtered by status,
 * and an exact-email lookup.
 *
 * - **URL is the state (FR-G1):** `page`, `size` and `status` live in the query string; each
 *   change of them is one page view and one `GET` (§6.5). The controls only navigate.
 * - **The lookup text never enters the URL** (SD-13): the field is a submit-mode search with no
 *   `<form>`; Enter or "Find" sends one `POST` with the address in the body. Clear returns to the
 *   list. A 429 shows its countdown on "Find", which stays focusable but off until zero, with no
 *   automatic retry (§7.4).
 * - **Addresses** render through {@link UserText} in `email` mode: hidden characters show as
 *   tokens with the badge (RC-68, D-1). "(you)" is chosen by the profile's user id.
 * - **Opening a user:** the address links to `users/:userId`, and a row click goes there too.
 * - **Logging:** this page logs nothing; addresses and the lookup text never leave it.
 */
@Component({
  selector: 'app-users-list-page',
  imports: [
    DatePipe,
    FormsModule,
    RouterLink,
    NxBadge,
    NxButton,
    NxEmptyState,
    NxIcon,
    NxPageHeader,
    NxSearchField,
    NxSelect,
    NxSkeleton,
    NxTable,
    NxTableCellDef,
    ConsoleErrorPanel,
    UserStatusBadge,
    UserText,
  ],
  templateUrl: './users-list.page.html',
  styleUrl: './users-list.page.scss',
})
export class UsersListPage {
  private readonly store = inject(UsersListStore);
  private readonly profile = inject(AuthorizationProfileStore);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  protected readonly copy = CONSOLE_COPY;
  protected readonly pageSizeOptions = [...PAGE_SIZES];
  protected readonly skeletonRows = [0, 1, 2, 3, 4, 5];
  protected readonly hintId = 'users-lookup-hint';
  protected readonly waitId = 'users-lookup-wait';

  protected readonly statusOptions: SelectOption<string>[] = [
    { label: CONSOLE_COPY.users.statusAll, value: ALL },
    ...STATUSES.map((status) => ({ label: CONSOLE_COPY.badges.status[status], value: status })),
  ];

  protected readonly columns: TableColumn[] = [
    { key: 'email', header: CONSOLE_COPY.users.columns.email, type: 'custom' },
    { key: 'status', header: CONSOLE_COPY.users.columns.status, type: 'custom' },
    { key: 'verified', header: CONSOLE_COPY.users.columns.verified, type: 'custom' },
    { key: 'joined', header: CONSOLE_COPY.users.columns.joined, type: 'custom' },
  ];

  /** The text in the lookup field, held in memory only, for the "Find" button. */
  protected readonly lookupText = signal('');

  private readonly params = toSignal(this.route.queryParamMap, { requireSync: true });
  protected readonly query = computed(() => queryFromParams(this.params()));
  protected readonly statusValue = computed(() => this.query().status ?? ALL);

  protected readonly status = computed(() => this.store.state().status);
  /** The loaded page, or the previous one while the next loads. */
  private readonly page = this.store.shown;
  /** A new page is on its way while the previous one stays on screen. */
  protected readonly refreshing = computed(() => this.status() === 'loading');

  protected readonly rows = computed<UserRow[]>(() =>
    (this.page()?.data ?? []).map((entry) => this.toRow(entry)),
  );
  protected readonly total = computed(() => this.page()?.page.totalElements ?? 0);
  protected readonly pageable = computed(() => this.total() > this.query().size);

  private readonly failure = computed(() => {
    const state = this.store.state();
    return state.status === 'error' ? state : null;
  });
  /** A 400 on a list load: the page is beyond the 10,000 offset or out of range (§14.1). */
  protected readonly pastTheEnd = computed(
    () => this.failure()?.error.code === 'VALIDATION_FAILED',
  );
  protected readonly errorView = computed(() => {
    const failure = this.failure();
    return failure === null
      ? null
      : resolveConsoleError(failure.error, { area: 'users', action: 'load' });
  });
  protected readonly failedAt = computed(() => this.failure()?.failedAt);

  protected readonly lookup = computed(() => this.store.lookupState());
  protected readonly lookupRows = computed<UserRow[]>(() => {
    const lookup = this.lookup();
    return lookup.status === 'hit' ? [this.toRow(lookup.entry)] : [];
  });

  /** A lookup that runs or has an answer replaces the list; Clear brings the list back. */
  protected readonly view = computed<UsersView>(() => {
    switch (this.lookup().status) {
      case 'loading':
        return 'lookup-loading';
      case 'hit':
        return 'lookup-hit';
      case 'miss':
        return 'lookup-miss';
      default:
        break;
    }
    switch (this.status()) {
      case 'ready':
        return this.rows().length === 0 ? 'empty' : 'list';
      case 'error':
        return this.pastTheEnd() ? 'past-the-end' : 'error';
      default:
        return this.rows().length > 0 ? 'list' : 'loading';
    }
  });
  protected readonly tableShown = computed(() => {
    const view = this.view();
    return view === 'list' || view === 'lookup-hit';
  });
  protected readonly isLookupTable = computed(() => this.view() === 'lookup-hit');
  protected readonly tableRows = computed(() =>
    this.isLookupTable() ? this.lookupRows() : this.rows(),
  );
  protected readonly tableCaption = computed(() =>
    this.isLookupTable() ? CONSOLE_COPY.users.lookupCaption : CONSOLE_COPY.users.caption,
  );
  protected readonly tablePageable = computed(() => !this.isLookupTable() && this.pageable());
  protected readonly tableBusy = computed(() => !this.isLookupTable() && this.refreshing());

  protected readonly lookupError = computed(() => {
    const lookup = this.lookup();
    return lookup.status === 'error'
      ? resolveConsoleError(lookup.error, { area: 'users', action: 'lookup' })
      : null;
  });

  protected readonly waiting = this.store.lookupWait.active;
  protected readonly waitText = computed(() => {
    const seconds = this.store.lookupWait.remaining();
    return seconds === 1
      ? CONSOLE_COPY.users.lookupWaitOne
      : format(CONSOLE_COPY.users.lookupWait, { n: seconds });
  });
  protected readonly lookupBusy = computed(() => this.lookup().status === 'loading');
  protected readonly lookupDescribedBy = computed(() =>
    this.waiting() ? this.waitId : this.hintId,
  );

  constructor() {
    // Router events are a stream; each distinct query in the URL is one page view.
    this.route.queryParamMap
      .pipe(map(queryFromParams), distinctUntilChanged(sameQuery), takeUntilDestroyed())
      .subscribe((query) => this.store.load(query));
  }

  /** The row behind a table cell. The rows are this page's own {@link UserRow}s. */
  protected row(cell: Record<string, unknown>): UserRow {
    return cell as UserRow;
  }

  protected retry(): void {
    this.store.load(this.query());
  }

  protected firstPage(): void {
    this.navigate({ page: null });
  }

  protected onStatus(value: string | string[]): void {
    const status = STATUSES.find((candidate) => candidate === value);
    this.navigate({ status: status === undefined ? null : status.toLowerCase(), page: null });
  }

  protected onPageChange(event: { readonly pageIndex: number; readonly pageSize: number }): void {
    const sizeChanged = event.pageSize !== this.query().size;
    const pageIndex = sizeChanged ? 0 : event.pageIndex;
    this.navigate({
      page: pageIndex === 0 ? null : String(pageIndex + 1),
      size: event.pageSize === DEFAULT_PAGE_SIZE ? null : String(event.pageSize),
    });
  }

  protected onLookupInput(text: string): void {
    this.lookupText.set(text);
  }

  protected submitLookup(text: string = this.lookupText()): void {
    this.store.lookup(text);
  }

  protected clearLookup(): void {
    this.lookupText.set('');
    this.store.clearLookup();
  }

  protected openUser(cell: Record<string, unknown>): void {
    const { userId } = this.row(cell);
    void this.router.navigate(['/admin/access/users', userId]);
  }

  private toRow(entry: UserDirectoryEntry): UserRow {
    const self = this.profile.userId();
    return {
      userId: entry.userId,
      email: entry.email,
      status: entry.status,
      emailVerified: entry.emailVerified,
      createdAt: entry.createdAt,
      isSelf: self !== null && entry.userId === self,
      verified: entry.emailVerified ? VERIFIED : UNVERIFIED,
    };
  }

  private navigate(params: Record<string, string | null>): void {
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: params,
      queryParamsHandling: 'merge',
    });
  }
}
