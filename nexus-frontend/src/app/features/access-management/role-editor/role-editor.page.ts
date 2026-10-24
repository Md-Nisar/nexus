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
import { LoggerService } from '../../../core/logging/logger.service';
import type { PermissionResponse } from '../../../shared/types/api/rbac';
import { AppError, isAppError } from '../../../shared/types/app-error';
import { NxAnnouncer, NxBanner, NxButton, NxDialog, NxSkeleton, NxToast } from '../../../shared/ui';
import { CONSOLE_COPY, RbacErrorMessages, format } from '../copy/console-copy';
import { permissionLabel } from '../copy/permission-labels';
import { propagationFor } from '../copy/propagation';
import { ConsoleErrorView, resolveConsoleError } from '../copy/resolve-console-error';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { CatalogueStore, PermissionGroup } from '../data/catalogue.store';
import { RbacApi, VersionedPermissionSet } from '../data/rbac-api';
import { RolesStore } from '../data/roles.store';
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
  rebase,
  toggle,
  toggleGroup,
} from '../util/diff-permissions';
import { withGrantedExtras } from '../util/granted-extras';
import { DEFAULT_RETRY_AFTER_SECONDS, createRetryCountdown } from '../util/retry-after';
import { HasUnsavedChanges, beforeUnloadWhileDirty } from './unsaved-changes.guard';

/** How the Review dialog was closed: after a save attempt finished, or cancelled. */
export type ReviewOutcome = 'save' | 'cancel';

/** Why the editor offers no control at all for this role. */
type Blocked = 'system-role' | 'etag-unusable' | 'no-write';

/**
 * What the last save left to show (design §11.1, §12.4). `deleted` and `system` end editing: the
 * server says the role is gone or is a system role, so nothing could ever be saved.
 */
type SaveFeedback =
  | { readonly kind: 'error'; readonly view: ConsoleErrorView }
  | {
      readonly kind: 'conflict';
      readonly upstreamAdded: readonly string[];
      readonly upstreamRemoved: readonly string[];
      readonly inPlace: readonly string[];
      readonly allInPlace: boolean;
    }
  | { readonly kind: 'deleted'; readonly view: ConsoleErrorView }
  | { readonly kind: 'system'; readonly view: ConsoleErrorView };

type ReviewDialogRef = ReturnType<NxDialog['openTemplate']>;

/** Codes of a 403 the live profile predicted would be allowed (design §2.2). */
const DENIED: ReadonlySet<string> = new Set(['RBAC_001', 'ACCESS_DENIED']);

/** One line of the Review lists. */
interface ReviewItem {
  readonly id: string;
  readonly label: string;
  readonly isSensitive: boolean;
}

const DIRECTORY_READ = 'user:directory:read';
const REVIEW_TITLE_ID = 'role-review-title';
const COUNTS_ID = 'role-editor-counts';
const WAIT_ID = 'role-editor-wait';

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
 *   (`normaliseIntent`), so the intent always keeps its invariant.
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
 * - **Saving** (T-011; design §7.2, §7.3, §11.1): one `PUT` of the resulting set with the strong
 *   tag verbatim as `If-Match`. The Review stays open while it runs (confirm `loading`, Cancel
 *   disabled, `disableClose`), and a second confirm is ignored. A 200 replaces the store's set and
 *   tag (no re-read), is announced, invalidates the roles list, and on a role the caller holds
 *   re-reads the profile with a toast. A 412 re-reads the set once, rebases the intent and shows
 *   what changed; it never resubmits, so a new Review is needed. Every refusal keeps the staged
 *   work: 428 shows the defect copy (error log), a 403 the reason copy and a profile re-read,
 *   `RBAC_003` and `ROLE_NOT_FOUND` end editing, and a 429 or 503 holds Review for the wait. The
 *   one retry (`RBAC_012`) is in `RbacApi`.
 * - **Leaving:** `unsavedChangesGuard` asks while there are unsaved changes, and the browser asks on
 *   unload only while dirty.
 * - **User text:** the role name renders through {@link UserText} only. Logs carry the role id,
 *   counts and codes only; never the name or description. The session is never refreshed here
 *   (RC-65): a re-read after an own-access change renews through the interceptor.
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
  private readonly roles = inject(RolesStore);
  private readonly api = inject(RbacApi);
  private readonly dialog = inject(NxDialog);
  private readonly announcer = inject(NxAnnouncer);
  private readonly toast = inject(NxToast);
  private readonly logger = inject(LoggerService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly copy = CONSOLE_COPY;
  protected readonly skeletonRows = [0, 1, 2, 3];
  protected readonly reviewTitleId = REVIEW_TITLE_ID;
  protected readonly reviewTitleBefore = REVIEW_TITLE_BEFORE;
  protected readonly reviewTitleAfter = REVIEW_TITLE_AFTER;
  protected readonly countsId = COUNTS_ID;
  protected readonly waitId = WAIT_ID;

  private readonly reviewTemplate = viewChild.required<TemplateRef<unknown>>('reviewDialog');
  private reviewRef: ReviewDialogRef | null = null;

  /** The staged intent and the role it belongs to; another role starts clean. */
  private readonly staged = signal<{
    readonly roleId: string | null;
    readonly intent: StagedIntent;
  }>({ roleId: null, intent: EMPTY_INTENT });

  /** What the last save left to show, for the role it belongs to. */
  private readonly feedback = signal<{
    readonly roleId: string | null;
    readonly value: SaveFeedback | null;
  }>({ roleId: null, value: null });

  /** A save (and, after a 412, its re-read) is running. */
  protected readonly saving = signal(false);

  /** Holds Review after a 429 or 503 until the wait is over (design §7.4). */
  private readonly wait = createRetryCountdown(this.destroyRef);
  protected readonly waiting = this.wait.active;

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

  protected readonly saveFeedback = computed<SaveFeedback | null>(() => {
    const { roleId, value } = this.feedback();
    return roleId !== null && roleId === this.role()?.id ? value : null;
  });

  protected readonly saveError = computed(() => {
    const feedback = this.saveFeedback();
    return feedback?.kind === 'error' ? feedback.view : null;
  });

  /** The server ended editing: the role is gone, or it is a system role after all. */
  protected readonly ended = computed(() => {
    const feedback = this.saveFeedback();
    return feedback?.kind === 'deleted' || feedback?.kind === 'system' ? feedback : null;
  });

  /** The conflict banner's lines after a 412 rebase (design §12.4, §14.2). */
  protected readonly conflict = computed(() => {
    const feedback = this.saveFeedback();
    if (feedback?.kind !== 'conflict') return null;
    const { save } = CONSOLE_COPY;
    const labels = (ids: readonly string[]): string =>
      ids.map((id) => this.labelOf(id)).join(save.listSeparator);
    const parts = [
      ...(feedback.upstreamAdded.length > 0
        ? [format(save.conflictAdded, { labels: labels(feedback.upstreamAdded) })]
        : []),
      ...(feedback.upstreamRemoved.length > 0
        ? [format(save.conflictRemoved, { labels: labels(feedback.upstreamRemoved) })]
        : []),
    ];
    return {
      title: RbacErrorMessages.PRECONDITION_FAILED.title,
      body: RbacErrorMessages.PRECONDITION_FAILED.body,
      changed:
        parts.length > 0
          ? format(save.conflictChanged, { changes: parts.join(save.conflictPartSeparator) })
          : null,
      inPlace:
        feedback.inPlace.length > 0
          ? format(save.conflictInPlace, { labels: labels(feedback.inPlace) })
          : null,
      allInPlace: feedback.allInPlace ? save.alreadyInPlace : null,
    };
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
  protected readonly view = computed<'none' | 'ended' | 'blocked' | 'loading' | 'error' | 'ready'>(
    () => {
      if (this.data() === null) return 'none';
      if (this.ended() !== null) return 'ended';
      if (this.blocked() !== null) return 'blocked';
      const profile = this.profile.state().status;
      if (profile === 'idle' || profile === 'loading') return 'loading';
      const catalogue = this.catalogue.state().status;
      if (catalogue === 'error') return 'error';
      return catalogue === 'ready' ? 'ready' : 'loading';
    },
  );

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

  protected readonly canReview = computed(() => !this.diff().isEmpty && !this.waiting());

  /** Why Review is unavailable: the wait countdown, or the counts while nothing is staged. */
  protected readonly reviewDescribedBy = computed(() => {
    if (this.waiting()) return WAIT_ID;
    return this.diff().isEmpty ? COUNTS_ID : '';
  });

  protected readonly waitText = computed(() =>
    format(CONSOLE_COPY.save.wait, { n: this.wait.remaining() }),
  );

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
    const item = (id: string): ReviewItem => ({
      id,
      label: this.labelOf(id),
      isSensitive: shown.get(id)?.isSensitive ?? false,
    });
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
      propagation: propagationFor({ added: diff.added.length, removed: diff.removed.length }),
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
    // A role the server says is gone or a system role leaves nothing that could be saved.
    return !this.diff().isEmpty && this.ended() === null;
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
    if (!this.canReview() || this.saving() || this.reviewRef !== null) return;
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
    if (this.saving()) return;
    this.reviewRef?.close(outcome);
  }

  /**
   * The Review's confirm: one PUT of the resulting set with the strong tag the set was read at.
   * Ignored while a save runs (no double submit) and when there is nothing to save.
   */
  protected confirmSave(): void {
    const data = this.data();
    const ref = this.reviewRef;
    const diff = this.diff();
    if (this.saving() || data === null || ref === null || diff.isEmpty) return;
    // The editor offers nothing without a strong tag (`blocked`); this keeps the type honest.
    if (data.etag.kind !== 'strong') return;

    const roleId = data.role.id;
    const oldBase = this.base();
    const intent = this.intent();
    this.saving.set(true);
    ref.disableClose = true;
    this.feedback.set({ roleId, value: null });
    this.wait.stop();

    this.api
      .replaceRolePermissions(roleId, diff.resulting, data.etag.value)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (set) => {
          this.finishSave(ref);
          this.applySaved(roleId, oldBase, set);
        },
        error: (error: unknown) => {
          const appError = toAppError(error);
          if (appError.code === 'PRECONDITION_FAILED') {
            this.rebaseAfterConflict(ref, roleId, oldBase, intent);
            return;
          }
          this.finishSave(ref);
          this.reportFailure(roleId, appError);
        },
      });
  }

  /** Ends the in-flight state and closes the Review (design §12.4: it closes on every outcome). */
  private finishSave(ref: ReviewDialogRef): void {
    this.saving.set(false);
    ref.disableClose = false;
    ref.close('save');
  }

  /** A 200, applied or no-op: the server's set and tag become the base. */
  private applySaved(
    roleId: string,
    oldBase: ReadonlySet<string>,
    set: VersionedPermissionSet,
  ): void {
    const newBase = idsOf(set.permissions);
    const added = [...newBase].filter((id) => !oldBase.has(id)).length;
    const removed = [...oldBase].filter((id) => !newBase.has(id)).length;
    this.detail.applySet(roleId, set);
    this.staged.set({ roleId: null, intent: EMPTY_INTENT });
    this.roles.invalidate();
    const { save } = CONSOLE_COPY;
    void this.announcer.announce(
      added === 0 && removed === 0 ? save.noop : format(save.success, { n: added, m: removed }),
      'polite',
    );
    if (this.profile.roleIds().has(roleId)) {
      // The caller's own access changed. The re-read renews the session through the interceptor
      // if the epoch moved; nothing here refreshes it (RC-65).
      this.profile.reload('own-access-change');
      this.toast.info(save.ownAccess);
    }
  }

  /**
   * A 412: someone else changed the set. One GET of the current set, the intent rebased onto it,
   * and the banner says what changed. Nothing is resubmitted (SD-9).
   */
  private rebaseAfterConflict(
    ref: ReviewDialogRef,
    roleId: string,
    oldBase: ReadonlySet<string>,
    intent: StagedIntent,
  ): void {
    this.api
      .getRolePermissions(roleId)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (set) => {
          this.finishSave(ref);
          const result = rebase(intent, idsOf(set.permissions), oldBase);
          const upstream = result.upstream ?? { added: [], removed: [] };
          this.detail.applySet(roleId, set);
          this.staged.set({ roleId, intent: result.intent });
          this.logger.info('Access console save met a concurrent change; staged work rebased', {
            event: 'access_console_conflict_rebased',
            context: {
              roleId,
              droppedCount: result.droppedAsAlreadyApplied.length,
              upstreamAdded: upstream.added.length,
              upstreamRemoved: upstream.removed.length,
            },
          });
          this.feedback.set({
            roleId,
            value: {
              kind: 'conflict',
              upstreamAdded: upstream.added,
              upstreamRemoved: upstream.removed,
              inPlace: result.droppedAsAlreadyApplied,
              allInPlace: result.intent.add.size === 0 && result.intent.remove.size === 0,
            },
          });
        },
        error: (error: unknown) => {
          this.finishSave(ref);
          this.reportFailure(roleId, toAppError(error));
        },
      });
  }

  /** Every refusal but a 412 keeps the staged work and says why (design §11.1, §14.1). */
  private reportFailure(roleId: string, error: AppError): void {
    const view = resolveConsoleError(error, { area: 'roles', action: 'save' });
    if (error.code === 'PRECONDITION_REQUIRED') {
      // The console only ever sends one strong tag, so a 428 means the edge or the client is wrong.
      this.logger.error('Access console save was refused for a missing precondition', {
        event: 'access_console_precondition_required',
        errorCode: error.code,
        context: { roleId, traceId: error.traceId },
      });
      this.feedback.set({ roleId, value: { kind: 'error', view } });
      return;
    }
    this.logger.warn('Access console save failed', {
      event: 'access_console_action_failed',
      errorCode: error.code,
      context: { action: 'save', roleId, reason: error.reason, traceId: error.traceId },
    });
    if (error.code === 'ROLE_NOT_FOUND') {
      this.roles.invalidate();
      this.feedback.set({ roleId, value: { kind: 'deleted', view } });
      return;
    }
    if (error.code === 'RBAC_003') {
      this.feedback.set({ roleId, value: { kind: 'system', view } });
      return;
    }
    this.feedback.set({ roleId, value: { kind: 'error', view } });
    if (DENIED.has(error.code)) {
      // The live profile predicted this was allowed: read it again; the work stays.
      this.profile.reload('denied-predicted-allowed');
    }
    if (view.showsWait) this.wait.start(view.retryAfterSeconds ?? DEFAULT_RETRY_AFTER_SECONDS);
  }

  /** The label shown for a permission id: its catalogue label, else its code, else the id. */
  private labelOf(id: string): string {
    const code = this.shown().get(id)?.name ?? id;
    return permissionLabel(code) ?? code;
  }

  private stage(intent: StagedIntent): void {
    this.staged.set({ roleId: this.role()?.id ?? null, intent });
  }

  protected retryCatalogue(): void {
    this.catalogue.load();
  }
}

function idsOf(permissions: readonly PermissionResponse[]): ReadonlySet<string> {
  return new Set(permissions.map((entry) => entry.id));
}

function toAppError(error: unknown): AppError {
  return isAppError(error)
    ? error
    : { code: 'UNEXPECTED_ERROR', message: 'The permission set could not be saved.' };
}
