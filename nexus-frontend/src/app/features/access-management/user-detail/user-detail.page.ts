import { formatDate } from '@angular/common';
import { Component, LOCALE_ID, computed, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ActivatedRoute, RouterLink, RouterOutlet } from '@angular/router';
import { distinctUntilChanged, filter, map } from 'rxjs';
import {
  BadgeVariant,
  BreadcrumbItem,
  NavTab,
  NxBadge,
  NxBanner,
  NxBreadcrumb,
  NxIcon,
  NxSkeleton,
  NxTabs,
} from '../../../shared/ui';
import type { UserStatus } from '../../../shared/types/api/user-directory';
import { CONSOLE_COPY, RbacErrorMessages, format } from '../copy/console-copy';
import { resolveConsoleError } from '../copy/resolve-console-error';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { ConsoleErrorPanel } from '../ui/console-error-panel';
import { UserStatusBadge } from '../ui/user-status-badge';
import { UserText } from '../ui/user-text';
import { UserDetailStore } from './user-detail.store';

/** Codes shown as "We couldn't find this person": missing, foreign, or not a user id (SD-20). */
const NOT_FOUND_CODES: ReadonlySet<string> = new Set(['USER_NOT_FOUND', 'VALIDATION_FAILED']);

/** Statuses that get an info banner (design §12.8); ACTIVE has none. */
type NotedStatus = Exclude<UserStatus, 'ACTIVE'>;

function isNoted(status: UserStatus): status is NotedStatus {
  return status !== 'ACTIVE';
}

interface VerifiedLook {
  readonly label: string;
  readonly icon: string;
  readonly variant: BadgeVariant;
}

const VERIFIED: VerifiedLook = {
  label: CONSOLE_COPY.badges.verified,
  icon: 'verified',
  variant: 'success',
};
const UNVERIFIED: VerifiedLook = {
  label: CONSOLE_COPY.badges.unverified,
  icon: 'unpublished',
  variant: 'warning',
};

/**
 * One person: who they are, their status, and their tabs (US-020 design §6.1, §12.8; FR-C2,
 * FR-G2, FR-G8).
 *
 * - **Loads** through {@link UserDetailStore} on entry and whenever `userId` changes: the
 *   directory entry, and the assignments when `user:read` is held. Moving between tabs reads
 *   nothing.
 * - **Header:** breadcrumb (its last crumb is static), `h1` with the address through
 *   {@link UserText} in `email` mode, so hidden characters show as tokens with their badge
 *   (RC-68); "(you)" when the id equals the live profile's user id, never by address (FR-G8);
 *   status and Verified badges; "Joined {date}". The `h1` exists from the first render, so route
 *   focus lands on it. LOCKED, DISABLED and PENDING add an info banner.
 * - **Not found:** a missing, foreign or malformed id is one "We couldn't find this person" page
 *   with a link back to Users (SD-20). Other failures use the console error panel (error, 503,
 *   flag off).
 * - **PII:** the route titles are static and this page logs nothing, so the address never reaches
 *   `document.title`, history or a log.
 *
 * @security UX only. The server decides every request.
 */
@Component({
  selector: 'app-user-detail-page',
  imports: [
    RouterLink,
    RouterOutlet,
    NxBadge,
    NxBanner,
    NxBreadcrumb,
    NxIcon,
    NxSkeleton,
    NxTabs,
    ConsoleErrorPanel,
    UserStatusBadge,
    UserText,
  ],
  templateUrl: './user-detail.page.html',
  styleUrl: './user-detail.page.scss',
})
export class UserDetailPage {
  private readonly store = inject(UserDetailStore);
  private readonly profile = inject(AuthorizationProfileStore);
  private readonly route = inject(ActivatedRoute);
  private readonly locale = inject(LOCALE_ID);

  protected readonly copy = CONSOLE_COPY;
  protected readonly notFoundCopy = RbacErrorMessages.USER_NOT_FOUND;
  protected readonly skeletonRows = [0, 1, 2];

  protected readonly status = computed(() => this.store.state().status);

  protected readonly user = computed(() => {
    const state = this.store.state();
    return state.status === 'ready' ? state.data : null;
  });

  private readonly failure = computed(() => {
    const state = this.store.state();
    return state.status === 'error' ? state : null;
  });

  protected readonly notFound = computed(() => {
    const failure = this.failure();
    return failure !== null && NOT_FOUND_CODES.has(failure.error.code);
  });

  protected readonly errorView = computed(() => {
    const failure = this.failure();
    return failure === null || this.notFound()
      ? null
      : resolveConsoleError(failure.error, { area: 'users', action: 'load' });
  });

  protected readonly failedAt = computed(() => this.failure()?.failedAt);

  /** The `h1` text until the address is shown. */
  protected readonly fallbackTitle = computed(() => {
    if (this.notFound()) return this.notFoundCopy.title;
    return this.failure() === null
      ? CONSOLE_COPY.userDetail.loadingTitle
      : CONSOLE_COPY.userDetail.fallbackTitle;
  });

  protected readonly crumbs: readonly BreadcrumbItem[] = [
    { label: CONSOLE_COPY.userDetail.breadcrumbRoot, path: '/admin/access' },
    { label: CONSOLE_COPY.userDetail.breadcrumbUsers, path: '/admin/access/users' },
    { label: CONSOLE_COPY.userDetail.breadcrumbCurrent },
  ];

  /** The caller's own page, by live profile user id; never by address (FR-G8). */
  protected readonly isSelf = computed(() => {
    const user = this.user();
    const self = this.profile.userId();
    return user !== null && self !== null && user.userId === self;
  });

  protected readonly verified = computed(() =>
    this.user()?.emailVerified ? VERIFIED : UNVERIFIED,
  );

  protected readonly joinedIso = computed(() => this.user()?.createdAt ?? null);

  protected readonly joinedText = computed(() => {
    const user = this.user();
    return user === null
      ? ''
      : format(CONSOLE_COPY.userDetail.joined, {
          date: formatDate(user.createdAt, 'mediumDate', this.locale),
        });
  });

  protected readonly statusNote = computed(() => {
    const user = this.user();
    return user !== null && isNoted(user.status)
      ? { status: user.status, text: CONSOLE_COPY.userDetail.statusNotes[user.status] }
      : null;
  });

  protected readonly tabs = computed<readonly NavTab[]>(() => {
    const user = this.user();
    return user === null
      ? []
      : [
          {
            label: CONSOLE_COPY.userDetail.tabRoles,
            path: `/admin/access/users/${user.userId}/roles`,
            testId: 'user-tab-roles',
          },
        ];
  });

  constructor() {
    this.route.paramMap
      .pipe(
        map((params) => params.get('userId')),
        filter((userId): userId is string => userId !== null),
        distinctUntilChanged(),
        takeUntilDestroyed(),
      )
      .subscribe((userId) => this.store.load(userId));
  }

  protected retry(): void {
    const userId = this.store.userId();
    if (userId !== null) this.store.load(userId);
  }
}
