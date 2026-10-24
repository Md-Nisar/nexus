import { DOCUMENT } from '@angular/common';
import {
  Component,
  DestroyRef,
  Renderer2,
  RendererStyleFlags2,
  TemplateRef,
  computed,
  inject,
  signal,
  viewChild,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import type { PermissionResponse } from '../../../shared/types/api/rbac';
import { NxBanner, NxButton, NxDialog, NxSkeleton } from '../../../shared/ui';
import { CONSOLE_COPY, format } from '../copy/console-copy';
import { permissionLabel } from '../copy/permission-labels';
import { resolveConsoleError } from '../copy/resolve-console-error';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { CatalogueStore, PermissionGroup } from '../data/catalogue.store';
import { RoleDetailStore } from '../role-detail/role-detail.store';
import { ConsoleErrorPanel } from '../ui/console-error-panel';
import { MatrixGroupToggle, MatrixToggle, PermissionMatrix } from '../ui/permission-matrix';
import { SensitiveBadge } from '../ui/sensitive-badge';
import { UserText } from '../ui/user-text';
import { isAdminDefiningHint } from '../util/admin-defining-hint';
import { Affordance, permissionAffordance } from '../util/affordances';
import {
  CatalogueIndex,
  EMPTY_INTENT,
  StagedIntent,
  diffPermissions,
  normaliseIntent,
  toggle,
  toggleGroup,
} from '../util/diff-permissions';
import { withGrantedExtras } from '../util/granted-extras';
import { HasUnsavedChanges, beforeUnloadWhileDirty } from './unsaved-changes.guard';

/** How the Review dialog was closed. `save` is handled by the save flow (T-011). */
export type ReviewOutcome = 'save' | 'cancel';

/** Why the editor offers no control at all for this role. */
type Blocked = 'system-role' | 'etag-unusable' | 'no-write';

/** One line of the Review lists. */
interface ReviewItem {
  readonly id: string;
  readonly label: string;
  readonly isSensitive: boolean;
}

const DIRECTORY_READ = 'user:directory:read';
const REVIEW_TITLE_ID = 'role-review-title';
const COUNTS_ID = 'role-editor-counts';

/**
 * Space kept clear at the bottom of the scrolling page for the sticky footer, so a focused row is
 * never hidden under it (WCAG 2.4.11). Covers the two-row narrow footer.
 */
const FOOTER_CLEARANCE = 'calc(var(--nx-space-24) + var(--nx-space-12))';

const [REVIEW_TITLE_BEFORE, REVIEW_TITLE_AFTER = ''] = CONSOLE_COPY.review.title.split('{role}');

/**
 * The role editor (US-020 design §4.8, §8, §12.4; FR-A6, FR-B3, FR-B6, FR-G5): stages permission
 * changes on a custom role and reviews them. It is the `edit` child of the role page, so the page
 * header stays and the role, its set and its version tag come from {@link RoleDetailStore}:
 * entering the editor sends **no request** (design §6.5). The catalogue comes from
 * {@link CatalogueStore}, read by the page.
 *
 * - **Staging:** an intent (`add`, `remove`) relative to the set as read, through the pure engine
 *   in `util/diff-permissions.ts`. A Refresh that brings a staged change from elsewhere drops it
 *   (`normaliseIntent`), so the intent always keeps its invariant. Nothing is sent from here; the
 *   save (one PUT with `If-Match`) is T-011.
 * - **Affordances** follow the live profile (`util/affordances.ts`, mirroring the server): a row the
 *   caller cannot change is disabled with its reason as visible text. A group checkbox changes only
 *   its enabled members. No row of a system role is ever offered (FR-B7); a weak or missing version
 *   tag, or a live profile without `role:write`, offers nothing to stage (design §7.2).
 * - **Footer:** "{n} to add, {m} to remove" in a polite status, Discard (drops the work and returns
 *   to the permissions tab) and "Review changes", `aria-disabled` until something is staged.
 * - **Review dialog:** `NxDialog.openTemplate` with `ariaLabelledBy`, no `mat-dialog-*`
 *   directives; at most one open (FR-G5). It lists what will be added and removed, who holds the
 *   role, the empty-result warning and the hints (admin demotion, whole catalogue), and confirms
 *   with "Grant sensitive access" (`danger`) when any add is sensitive.
 * - **Leaving:** `unsavedChangesGuard` asks while there are unsaved changes, and the browser asks on
 *   unload only while dirty.
 * - **User text:** the role name renders through {@link UserText} only. Nothing here logs.
 *
 * @security UX only. The server decides every request.
 */
@Component({
  selector: 'app-role-editor-page',
  imports: [
    RouterLink,
    NxBanner,
    NxButton,
    NxSkeleton,
    ConsoleErrorPanel,
    PermissionMatrix,
    SensitiveBadge,
    UserText,
  ],
  templateUrl: './role-editor.page.html',
  styleUrl: './role-editor.page.scss',
})
export class RoleEditorPage implements HasUnsavedChanges {
  private readonly detail = inject(RoleDetailStore);
  private readonly catalogue = inject(CatalogueStore);
  private readonly profile = inject(AuthorizationProfileStore);
  private readonly dialog = inject(NxDialog);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly copy = CONSOLE_COPY;
  protected readonly skeletonRows = [0, 1, 2, 3];
  protected readonly reviewTitleId = REVIEW_TITLE_ID;
  protected readonly reviewTitleBefore = REVIEW_TITLE_BEFORE;
  protected readonly reviewTitleAfter = REVIEW_TITLE_AFTER;
  protected readonly countsId = COUNTS_ID;

  private readonly reviewTemplate = viewChild.required<TemplateRef<unknown>>('reviewDialog');
  private reviewRef: ReturnType<NxDialog['openTemplate']> | null = null;

  /** The staged intent and the role it belongs to; another role starts clean. */
  private readonly staged = signal<{
    readonly roleId: string | null;
    readonly intent: StagedIntent;
  }>({ roleId: null, intent: EMPTY_INTENT });

  private readonly data = computed(() => {
    const state = this.detail.state();
    return state.status === 'ready' ? state.data : null;
  });

  protected readonly role = computed(() => this.data()?.role ?? null);

  private readonly catalogueData = computed(() => {
    const state = this.catalogue.state();
    return state.status === 'ready' ? state.data : null;
  });

  /** The set as read, by id. */
  private readonly base = computed<ReadonlySet<string>>(
    () => new Set((this.data()?.permissions ?? []).map((entry) => entry.id)),
  );

  /** The staged intent for this role, kept consistent with the current base. */
  protected readonly intent = computed<StagedIntent>(() => {
    const { roleId, intent } = this.staged();
    return roleId === null || roleId !== this.role()?.id
      ? EMPTY_INTENT
      : normaliseIntent(intent, this.base());
  });

  protected readonly groups = computed<readonly PermissionGroup[]>(() => {
    const catalogue = this.catalogueData();
    if (catalogue === null) return [];
    return withGrantedExtras(catalogue.groups, catalogue.byId, this.data()?.permissions ?? []);
  });

  /** Every permission the matrix shows, by id: the catalogue plus granted extras. */
  private readonly shown = computed<ReadonlyMap<string, PermissionResponse>>(
    () =>
      new Map(
        this.groups().flatMap((group) => group.permissions.map((entry) => [entry.id, entry])),
      ),
  );

  private readonly index = computed<CatalogueIndex>(() => ({
    order: (this.catalogueData()?.groups ?? []).flatMap((group) =>
      group.permissions.map((entry) => entry.id),
    ),
    sensitive: new Set(
      [...this.shown().values()].filter((entry) => entry.isSensitive).map((entry) => entry.id),
    ),
  }));

  protected readonly diff = computed(() =>
    diffPermissions(this.base(), this.intent(), this.index()),
  );

  /** The role carries as many permissions as the catalogue: a hint only (Q17). */
  protected readonly adminDefining = computed(() => {
    const role = this.role();
    const catalogue = this.catalogueData();
    return role !== null && catalogue !== null && isAdminDefiningHint(role, catalogue.total);
  });

  protected readonly blocked = computed<Blocked | null>(() => {
    const data = this.data();
    if (data === null) return null;
    if (data.role.isSystemRole) return 'system-role';
    if (data.saveAvailability === 'etag-unusable') return 'etag-unusable';
    if (this.profile.state().status === 'ready' && !this.profile.can('role:write')) {
      return 'no-write';
    }
    return null;
  });

  protected readonly blockedReason = computed(() => {
    switch (this.blocked()) {
      case 'etag-unusable':
        return CONSOLE_COPY.disabledReason.etagUnusable;
      case 'no-write':
        return CONSOLE_COPY.editor.noWrite;
      default:
        // A system role: the page already shows the system-role banner.
        return '';
    }
  });

  /** What the editor shows below the page header. */
  protected readonly view = computed<'none' | 'blocked' | 'loading' | 'error' | 'ready'>(() => {
    if (this.data() === null) return 'none';
    if (this.blocked() !== null) return 'blocked';
    const profile = this.profile.state().status;
    if (profile === 'idle' || profile === 'loading') return 'loading';
    const catalogue = this.catalogue.state().status;
    if (catalogue === 'error') return 'error';
    return catalogue === 'ready' ? 'ready' : 'loading';
  });

  protected readonly affordances = computed<ReadonlyMap<string, Affordance>>(() => {
    const role = this.role();
    const catalogue = this.catalogueData();
    if (role === null || catalogue === null) return new Map();
    const held = new Set<string>();
    for (const name of this.profile.permissions()) {
      const entry = catalogue.byName.get(name);
      if (entry !== undefined) held.add(entry.id);
    }
    const ctx = {
      held,
      isAdministrator: this.profile.isAdministrator(),
      roleSet: this.base(),
      isSystemRole: role.isSystemRole,
      mutationsEnabled: this.profile.mutationsEnabled(),
      directoryReadId: catalogue.byName.get(DIRECTORY_READ)?.id ?? null,
      adminDefiningHint: this.adminDefining(),
    };
    return new Map([...this.shown().keys()].map((id) => [id, permissionAffordance(id, ctx)]));
  });

  protected readonly countsText = computed(() =>
    format(CONSOLE_COPY.editor.footerCounts, {
      n: this.diff().added.length,
      m: this.diff().removed.length,
    }),
  );

  protected readonly canReview = computed(() => !this.diff().isEmpty);

  protected readonly catalogueError = computed(() => {
    const state = this.catalogue.state();
    return state.status === 'error'
      ? resolveConsoleError(state.error, { area: 'permissions', action: 'load' })
      : null;
  });

  protected readonly catalogueFailedAt = computed(() => {
    const state = this.catalogue.state();
    return state.status === 'error' ? state.failedAt : undefined;
  });

  /** The Review dialog's content. */
  protected readonly review = computed(() => {
    const diff = this.diff();
    const shown = this.shown();
    const item = (id: string): ReviewItem => {
      const entry = shown.get(id);
      const code = entry?.name ?? id;
      return {
        id,
        label: permissionLabel(code) ?? code,
        isSensitive: entry?.isSensitive ?? false,
      };
    };
    const members = this.role()?.memberCount ?? 0;
    const { review, hints } = CONSOLE_COPY;
    const hintTexts: string[] = [];
    if (this.adminDefining() && diff.removed.length > 0) hintTexts.push(hints.adminDemotion);
    if (diff.resultIsWholeCatalogue && diff.added.length > 0) hintTexts.push(hints.wholeCatalogue);
    return {
      added: diff.added.map(item),
      removed: diff.removed.map(item),
      addingTitle: format(review.adding, { n: diff.added.length }),
      removingTitle: format(review.removing, { n: diff.removed.length }),
      membersText:
        members === 0
          ? review.membersNone
          : members === 1
            ? review.membersOne
            : format(review.members, { n: members }),
      emptyResult: diff.resultIsEmpty,
      hints: hintTexts,
      sensitive: diff.addsSensitive,
    };
  });

  constructor() {
    beforeUnloadWhileDirty(() => this.hasUnsavedChanges());

    const renderer = inject(Renderer2);
    const root = inject(DOCUMENT).documentElement;
    renderer.setStyle(
      root,
      'scroll-padding-bottom',
      FOOTER_CLEARANCE,
      RendererStyleFlags2.DashCase,
    );
    this.destroyRef.onDestroy(() => {
      renderer.removeStyle(root, 'scroll-padding-bottom', RendererStyleFlags2.DashCase);
      this.reviewRef?.close();
    });
  }

  hasUnsavedChanges(): boolean {
    return !this.diff().isEmpty;
  }

  protected onToggle(event: MatrixToggle): void {
    if (this.affordances().get(event.permissionId)?.kind !== 'enabled') return;
    this.stage(toggle(this.base(), this.intent(), event.permissionId, event.next));
  }

  protected onToggleGroup(event: MatrixGroupToggle): void {
    const group = this.groups().find((candidate) => candidate.resource === event.resource);
    if (group === undefined) return;
    const affordances = this.affordances();
    this.stage(
      toggleGroup(
        this.base(),
        this.intent(),
        group.permissions.map((entry) => entry.id),
        event.next,
        (id) => affordances.get(id)?.kind === 'enabled',
      ),
    );
  }

  /** Drops the staged work and returns to the permissions tab; nothing is left to ask about. */
  protected discard(): void {
    this.staged.set({ roleId: null, intent: EMPTY_INTENT });
    void this.router.navigate(['..', 'permissions'], { relativeTo: this.route });
  }

  /** Opens the Review dialog, at most once at a time (FR-G5). */
  protected openReview(): void {
    if (!this.canReview() || this.reviewRef !== null) return;
    const ref = this.dialog.openTemplate<ReviewOutcome>(this.reviewTemplate(), {
      ariaLabelledBy: REVIEW_TITLE_ID,
      autoFocus: `#${REVIEW_TITLE_ID}`,
    });
    this.reviewRef = ref;
    ref
      .afterClosed()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(() => {
        this.reviewRef = null;
      });
  }

  protected closeReview(outcome: ReviewOutcome): void {
    this.reviewRef?.close(outcome);
  }

  private stage(intent: StagedIntent): void {
    this.staged.set({ roleId: this.role()?.id ?? null, intent });
  }

  protected retryCatalogue(): void {
    this.catalogue.load();
  }
}
