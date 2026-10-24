import { Component, LOCALE_ID, OnInit, computed, inject } from '@angular/core';
import { takeUntilDestroyed, toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, NavigationEnd, Router, RouterLink, RouterOutlet } from '@angular/router';
import { distinctUntilChanged, filter, interval, map } from 'rxjs';
import { AuthStore } from '../../../core/auth/auth.store';
import {
  BreadcrumbItem,
  NavTab,
  NxBanner,
  NxBreadcrumb,
  NxButton,
  NxSkeleton,
  NxTabs,
} from '../../../shared/ui';
import { CONSOLE_COPY, RbacErrorMessages, format } from '../copy/console-copy';
import { resolveConsoleError } from '../copy/resolve-console-error';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { CatalogueStore } from '../data/catalogue.store';
import { ConsoleErrorPanel } from '../ui/console-error-panel';
import { SystemRoleBadge } from '../ui/system-role-badge';
import { UserText } from '../ui/user-text';
import { formatRelativeTime } from '../util/relative-time';
import { RoleDetailStore } from './role-detail.store';

/** How often "Updated {relative time}" is recomputed; the text has minute precision. */
const CLOCK_TICK_MS = 60_000;

/** Codes shown as "This role no longer exists": gone, or an id that is not a role (design §7.1). */
const NOT_FOUND_CODES: ReadonlySet<string> = new Set(['ROLE_NOT_FOUND', 'VALIDATION_FAILED']);

/** A write action as the live profile allows it (design §2.2, §12.0). */
type WriteAccess = 'enabled' | 'disabled' | 'hidden';

/** A visible reason beside an `aria-disabled` control, linked through `aria-describedby`. */
interface DisabledReason {
  readonly id: string;
  readonly text: string;
}

/**
 * One role: header, actions and the Permissions tab (US-020 design §6.1, §12.3; FR-A5, FR-B7,
 * FR-G2, FR-G3, FR-X1).
 *
 * - **Loads:** the role and its permission set through {@link RoleDetailStore} (in parallel, on
 *   entry and whenever the `roleId` parameter changes), and the catalogue once per console session
 *   through {@link CatalogueStore}. Moving between this role's tabs reads nothing.
 * - **Header:** breadcrumb, `h1` with the name, type badge, description, counts, "Updated {relative
 *   time}" and Refresh (Q24: role and set together). The `h1` exists from the first render, so
 *   route focus lands on it, and its text becomes the name when the role arrives.
 * - **Actions** follow the live profile (`role:write`), not the JWT. A system role renders no
 *   edit control at all, only the banner and Clone (FR-B7). When the version tag is weak or
 *   missing, "Edit permissions" stays visible and focusable but `aria-disabled`, with the reason as
 *   visible text, and a banner explains it with the read's reference (design §7.2). The read view
 *   is never hidden.
 * - **Editor:** the `edit` child renders in the same outlet, so this page and its store stay
 *   mounted and entering the editor reads nothing; "Edit permissions" is hidden while it is open.
 * - **User text:** the name and description render through {@link UserText} by interpolation
 *   only, in `<bdi>` or a `dir="auto"` block. Route titles are static, so the name never reaches
 *   `document.title`, and nothing here logs.
 *
 * @security UX only. The server decides every request.
 */
@Component({
  selector: 'app-role-detail-page',
  imports: [
    RouterLink,
    RouterOutlet,
    NxBanner,
    NxBreadcrumb,
    NxButton,
    NxSkeleton,
    NxTabs,
    ConsoleErrorPanel,
    SystemRoleBadge,
    UserText,
  ],
  templateUrl: './role-detail.page.html',
  styleUrl: './role-detail.page.scss',
})
export class RoleDetailPage implements OnInit {
  private readonly store = inject(RoleDetailStore);
  private readonly catalogue = inject(CatalogueStore);
  private readonly profile = inject(AuthorizationProfileStore);
  private readonly authStore = inject(AuthStore);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly locale = inject(LOCALE_ID);

  protected readonly copy = CONSOLE_COPY;
  protected readonly skeletonRows = [0, 1, 2, 3];
  protected readonly cloneReasonId = 'role-clone-reason';

  private readonly now = toSignal(interval(CLOCK_TICK_MS).pipe(map(() => Date.now())), {
    initialValue: Date.now(),
  });

  /** The editor (`edit` child) is open: the page stays mounted and shows no Edit action. */
  private readonly editing = toSignal(
    this.router.events.pipe(
      filter((event) => event instanceof NavigationEnd),
      map(() => this.editorOpen()),
    ),
    { initialValue: this.editorOpen() },
  );

  protected readonly status = computed(() => this.store.state().status);

  private readonly data = computed(() => {
    const state = this.store.state();
    return state.status === 'ready' ? state : null;
  });

  protected readonly role = computed(() => this.data()?.data.role ?? null);

  private readonly failure = computed(() => {
    const state = this.store.state();
    return state.status === 'error' ? state : null;
  });

  protected readonly notFound = computed(() => {
    const failure = this.failure();
    return failure !== null && NOT_FOUND_CODES.has(failure.error.code);
  });

  protected readonly notFoundCopy = RbacErrorMessages.ROLE_NOT_FOUND;

  protected readonly errorView = computed(() => {
    const failure = this.failure();
    return failure === null || this.notFound()
      ? null
      : resolveConsoleError(failure.error, { area: 'roles', action: 'load' });
  });

  protected readonly failedAt = computed(() => this.failure()?.failedAt);

  /** The `h1` text until the role is shown. */
  protected readonly fallbackTitle = computed(() => {
    if (this.notFound()) return this.notFoundCopy.title;
    return this.failure() === null
      ? CONSOLE_COPY.roleDetail.loadingTitle
      : CONSOLE_COPY.roleDetail.fallbackTitle;
  });

  protected readonly crumbs = computed<readonly BreadcrumbItem[]>(() => [
    { label: CONSOLE_COPY.roleDetail.breadcrumbRoot, path: '/admin/access' },
    { label: CONSOLE_COPY.roleDetail.breadcrumbRoles, path: '/admin/access/roles' },
    { label: this.role()?.name ?? this.fallbackTitle() },
  ]);

  protected readonly tabs = computed<readonly NavTab[]>(() => {
    const role = this.role();
    return role === null
      ? []
      : [
          {
            label: CONSOLE_COPY.roleDetail.tabPermissions,
            path: `/admin/access/roles/${role.id}/permissions`,
            testId: 'role-tab-permissions',
          },
        ];
  });

  protected readonly countsText = computed(() => {
    const ready = this.data();
    if (ready === null) return '';
    // The set the matrix shows, read with the version tag, rather than the role's own count.
    const permissions = ready.data.permissions.length;
    const members = ready.data.role.memberCount;
    const { roleDetail } = CONSOLE_COPY;
    return [
      permissions === 1
        ? roleDetail.permissionCountOne
        : format(roleDetail.permissionCount, { n: permissions }),
      members === 1 ? roleDetail.memberCountOne : format(roleDetail.memberCount, { n: members }),
    ].join(roleDetail.countSeparator);
  });

  protected readonly updatedIso = computed(() => {
    const ready = this.data();
    return ready === null ? null : new Date(ready.loadedAt).toISOString();
  });

  protected readonly updatedText = computed(() => {
    const ready = this.data();
    return ready === null
      ? ''
      : format(CONSOLE_COPY.roleDetail.updated, {
          time: formatRelativeTime(ready.loadedAt, this.now(), this.locale),
        });
  });

  protected readonly refreshing = this.store.refreshing;

  protected readonly refreshErrorView = computed(() => {
    const error = this.store.refreshError();
    return error === null ? null : resolveConsoleError(error, { area: 'roles', action: 'load' });
  });

  /**
   * A write action from the live profile: shown with `role:write`; kept, but off with a reason,
   * when the profile could not be read although the JWT holds `role:write`; otherwise hidden.
   */
  private readonly writeAccess = computed<WriteAccess>(() => {
    if (this.profile.can('role:write')) return 'enabled';
    const unreadable = this.profile.state().status === 'error';
    return unreadable && this.authStore.permissions().includes('role:write')
      ? 'disabled'
      : 'hidden';
  });

  protected readonly cloneState = computed<WriteAccess>(() =>
    this.role() === null ? 'hidden' : this.writeAccess(),
  );

  protected readonly etagUnusable = computed(
    () => this.data()?.data.saveAvailability === 'etag-unusable',
  );

  /** Why "Edit permissions" is off, in display order; empty when it is enabled. */
  protected readonly editReasons = computed<readonly DisabledReason[]>(() => {
    const reasons: DisabledReason[] = [];
    if (this.writeAccess() === 'disabled') {
      reasons.push({
        id: 'role-edit-reason-profile',
        text: CONSOLE_COPY.disabledReason.profileUnavailable,
      });
    }
    if (this.etagUnusable()) {
      reasons.push({ id: 'role-edit-reason-etag', text: CONSOLE_COPY.disabledReason.etagUnusable });
    }
    return reasons;
  });

  /** "Edit permissions": custom roles only, never on a system role (FR-B7). */
  private readonly editAccess = computed<WriteAccess>(() => {
    const role = this.role();
    if (role === null || role.isSystemRole || this.writeAccess() === 'hidden') return 'hidden';
    return this.editReasons().length > 0 ? 'disabled' : 'enabled';
  });

  /** The Edit action as shown: hidden while the editor is open. */
  protected readonly editState = computed<WriteAccess>(() =>
    this.editing() ? 'hidden' : this.editAccess(),
  );

  protected readonly editDescribedBy = computed(() =>
    this.editReasons()
      .map((reason) => reason.id)
      .join(' '),
  );

  /** The "Saving is unavailable" banner, shown where an Edit control is shown. */
  protected readonly showEtagBanner = computed(
    () => this.etagUnusable() && this.editAccess() !== 'hidden',
  );

  protected readonly etagReference = computed(() => this.data()?.data.correlationId ?? null);

  constructor() {
    this.route.paramMap
      .pipe(
        map((params) => params.get('roleId')),
        filter((roleId): roleId is string => roleId !== null),
        distinctUntilChanged(),
        takeUntilDestroyed(),
      )
      .subscribe((roleId) => this.store.load(roleId));
  }

  ngOnInit(): void {
    this.catalogue.load();
  }

  private editorOpen(): boolean {
    return this.route.firstChild?.routeConfig?.path === 'edit';
  }

  protected refresh(): void {
    if (this.refreshing()) return;
    this.store.refresh();
  }

  protected retry(): void {
    const roleId = this.store.roleId();
    if (roleId !== null) this.store.load(roleId);
  }

  protected edit(): void {
    const role = this.role();
    if (role === null || this.editState() !== 'enabled') return;
    void this.router.navigate(['/admin/access/roles', role.id, 'edit']);
  }

  protected clone(): void {
    const role = this.role();
    if (role === null || this.cloneState() !== 'enabled') return;
    void this.router.navigate(['/admin/access/roles/new'], { queryParams: { from: role.id } });
  }
}
