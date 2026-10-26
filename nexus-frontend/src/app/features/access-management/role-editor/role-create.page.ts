import {
  Component,
  DestroyRef,
  ElementRef,
  Injector,
  OnInit,
  afterNextRender,
  computed,
  inject,
  signal,
  viewChild,
} from '@angular/core';
import { takeUntilDestroyed, toSignal } from '@angular/core/rxjs-interop';
import { ReactiveFormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { finalize, forkJoin, switchMap, throwError } from 'rxjs';
import { AuthStore } from '../../../core/auth/auth.store';
import { LoggerService } from '../../../core/logging/logger.service';
import type { PermissionResponse, RoleResponse } from '../../../shared/types/api/rbac';
import { AppError, isAppError } from '../../../shared/types/app-error';
import {
  NxBanner,
  NxButton,
  NxInput,
  NxPageHeader,
  NxSkeleton,
  NxTextarea,
  NxToast,
} from '../../../shared/ui';
import { CONSOLE_COPY, RbacErrorMessages, format } from '../copy/console-copy';
import { permissionLabel } from '../copy/permission-labels';
import { propagationFor } from '../copy/propagation';
import { ConsoleErrorView, resolveConsoleError } from '../copy/resolve-console-error';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { CatalogueStore, PermissionGroup } from '../data/catalogue.store';
import { CloneSource, CloneSourceCache } from '../data/clone-source';
import { RbacApi } from '../data/rbac-api';
import { RolesStore } from '../data/roles.store';
import { DraftStorage } from '../drafts/draft-storage';
import { ConsoleErrorPanel } from '../ui/console-error-panel';
import {
  AFFORDANCE_REASON_TEXT,
  MatrixGroupToggle,
  MatrixToggle,
  PermissionMatrix,
} from '../ui/permission-matrix';
import { Affordance, permissionAffordance } from '../util/affordances';
import { EMPTY_INTENT, StagedIntent, toggle, toggleGroup } from '../util/diff-permissions';
import { DEFAULT_RETRY_AFTER_SECONDS, createRetryCountdown } from '../util/retry-after';
import {
  ROLE_DESCRIPTION_MAX,
  ROLE_NAME_MAX,
  cloneName,
  createRoleForm,
  descriptionError,
  nameError,
} from './role-form';
import { HasUnsavedChanges, beforeUnloadWhileDirty } from './unsaved-changes.guard';

/** Where the Clone source stands; `none` on a plain create. */
type SourceState =
  | { readonly kind: 'none' }
  | { readonly kind: 'loading'; readonly roleId: string }
  | { readonly kind: 'ready'; readonly source: CloneSource }
  | { readonly kind: 'gone' }
  | {
      readonly kind: 'error';
      readonly roleId: string;
      readonly view: ConsoleErrorView;
      readonly failedAt: number;
    };

/** Why the new role's permissions were not saved, as the partial banner shows it. */
interface PartialFailure {
  readonly title: string;
  readonly body: string;
  readonly reference?: string;
}

/**
 * The three-call create (design §11.3). From the 201 on, the role exists: the form is locked and
 * nothing can post again; only the GET and PUT of its permissions can be re-run.
 */
type Phase =
  | { readonly kind: 'editing' }
  | { readonly kind: 'creating' }
  | {
      readonly kind: 'partial';
      readonly role: RoleResponse;
      readonly ids: readonly string[];
      readonly failure: PartialFailure;
      readonly retrying: boolean;
    }
  | { readonly kind: 'done' };

type Field = 'name' | 'description';

interface SummaryItem {
  /** The field the message is about; `null` for a field the form does not have. */
  readonly field: Field | null;
  readonly message: string;
}

/** The new role's set came back with a weak or missing tag: it cannot be saved (design §7.2). */
interface EtagUnusable {
  readonly etagUnusable: true;
  readonly correlationId: string | null;
}

/** Codes of a 403 the live profile predicted would be allowed (design §2.2). */
const DENIED: ReadonlySet<string> = new Set(['RBAC_001', 'ACCESS_DENIED']);
/** Codes that mean the Clone source is gone, or the id is not a role. */
const GONE: ReadonlySet<string> = new Set(['ROLE_NOT_FOUND', 'VALIDATION_FAILED']);
const FIELDS: ReadonlySet<string> = new Set<Field>(['name', 'description']);
const DIRECTORY_READ = 'user:directory:read';
const NO_IDS: ReadonlySet<string> = new Set<string>();
/** How long a create in flight may refuse a leave before the user is let go. */
const LEAVE_REFUSAL_MS = 15_000;

const NAME_ID = 'role-create-name';
const NAME_COUNTER_ID = 'role-create-name-counter';
const NAME_ERROR_ID = 'role-create-name-error';
const DESCRIPTION_ID = 'role-create-description';
const SUBMIT_REASON_ID = 'role-create-submit-reason';
const WAIT_ID = 'role-create-wait';

function isEtagUnusable(error: unknown): error is EtagUnusable {
  return typeof error === 'object' && error !== null && 'etagUnusable' in error;
}

function toAppError(error: unknown, message: string): AppError {
  return isAppError(error) ? error : { code: 'UNEXPECTED_ERROR', message };
}

/**
 * Create and Clone a custom role (US-020 design §6.6, §11.3, §12.5; FR-B1, FR-B2, FR-B5, FR-F3).
 *
 * - **Form:** name (`NxInput`, hint and counter "{n} of 64") and description (`nx-textarea`,
 *   counter "{n} of 255"), validated as `CreateRoleRequest` does (`role-form.ts`). Field errors
 *   show once a field is left or on submit; a submit with errors shows a focused error summary
 *   (`role=alert`) whose links move focus to the field. Nothing is sent while anything is invalid.
 * - **Permissions** (optional): the matrix in edit mode against an empty base, with the editor's
 *   affordances (every row is an add). What is staged is always filtered by the current
 *   affordances, so a row the caller cannot grant is never shown or sent as staged.
 * - **Create:** `POST /roles`; with permissions, then `GET` of the new role's set and one `PUT` with
 *   its strong tag verbatim (`RbacApi` retries `RBAC_012` once). Success toasts "Role created."
 *   (with the grant line when permissions were saved), invalidates the roles list and opens the
 *   role. Any failure after the 201 shows the partial banner with Retry (GET and PUT again, with a
 *   fresh tag) and "Open role", and writes a draft of the chosen ids for the new role, which the
 *   editor offers (T-012). The role exists by then, so the form is locked: no second POST.
 * - **Refusals of the POST:** `RBAC_006`/`RBAC_007` at the name; `RBAC_008` a banner with copy only;
 *   `VALIDATION_FAILED` `details[]` by field; a 403 inline with a profile re-read; a 429 or 503 holds
 *   the submit for the wait.
 * - **Clone** (`?from=`): the source from the role page ({@link CloneSourceCache}) or one read of
 *   the role and its set; "Copy of {name}" cut to 64; the source permissions the caller cannot
 *   grant are left out and listed under "Not copied" with the reason (grant-subset, FR-B5).
 * - **Gating:** the live profile, not the JWT. Without `role:write` there is no form; while the
 *   profile is unavailable, Create is `aria-disabled` with the reason and every row is disabled.
 * - **User text** renders by interpolation only. Logs carry ids, counts and codes, never the name
 *   or description. The session is never refreshed here (RC-65).
 *
 * @security UX only. The server decides every request.
 */
@Component({
  selector: 'app-role-create-page',
  imports: [
    ReactiveFormsModule,
    RouterLink,
    NxBanner,
    NxButton,
    NxInput,
    NxPageHeader,
    NxSkeleton,
    NxTextarea,
    ConsoleErrorPanel,
    PermissionMatrix,
  ],
  templateUrl: './role-create.page.html',
  styleUrl: './role-create.page.scss',
})
export class RoleCreatePage implements OnInit, HasUnsavedChanges {
  private readonly api = inject(RbacApi);
  private readonly catalogue = inject(CatalogueStore);
  private readonly profile = inject(AuthorizationProfileStore);
  private readonly roles = inject(RolesStore);
  private readonly auth = inject(AuthStore);
  private readonly drafts = inject(DraftStorage);
  private readonly cloneSources = inject(CloneSourceCache);
  private readonly toast = inject(NxToast);
  private readonly logger = inject(LoggerService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly destroyRef = inject(DestroyRef);
  private readonly injector = inject(Injector);

  protected readonly copy = CONSOLE_COPY;
  protected readonly skeletonRows = [0, 1, 2];
  protected readonly nameId = NAME_ID;
  protected readonly nameCounterId = NAME_COUNTER_ID;
  protected readonly nameErrorId = NAME_ERROR_ID;
  protected readonly descriptionId = DESCRIPTION_ID;
  protected readonly descriptionMax = ROLE_DESCRIPTION_MAX;
  protected readonly submitReasonId = SUBMIT_REASON_ID;
  protected readonly waitId = WAIT_ID;
  /** A new role's base: it grants nothing yet. */
  protected readonly noIds = NO_IDS;

  protected readonly form = createRoleForm();

  private readonly nameField = viewChild(NxInput);
  private readonly descriptionField = viewChild(NxTextarea);
  private readonly summaryRef = viewChild<ElementRef<HTMLElement>>('summaryBox');

  /** Re-evaluates what reads the form's state (value, touched, pristine, status). */
  private readonly formEvents = toSignal(this.form.events, { initialValue: null });
  private readonly nameValue = toSignal(this.form.controls.name.valueChanges, {
    initialValue: '',
  });

  protected readonly phase = signal<Phase>({ kind: 'editing' });
  private busySince = 0;
  private readonly source = signal<SourceState>({ kind: 'none' });
  /** Ids the user (or the Clone) staged; shown and sent only while their row is enabled. */
  private readonly staged = signal<ReadonlySet<string>>(NO_IDS);
  /** The user changed the staged permissions (a Clone's prefill alone is not unsaved work). */
  private readonly matrixTouched = signal(false);
  private readonly submitted = signal(false);
  private readonly summaryShown = signal(false);
  /** The server's verdict on a field, until the field changes. */
  private readonly serverFieldErrors = signal<ReadonlyMap<Field, string>>(new Map());
  /** Server messages about fields the form does not have. */
  private readonly otherErrors = signal<readonly string[]>([]);
  /** A refusal of the POST shown inline (`role=alert`). */
  protected readonly failure = signal<ConsoleErrorView | null>(null);
  /** `RBAC_008`: the role limit banner. */
  protected readonly limit = signal<ConsoleErrorView | null>(null);

  /** Holds the submit or Retry after a 429 or 503 until the wait is over (design §7.4). */
  private readonly wait = createRetryCountdown(this.destroyRef);
  protected readonly waiting = this.wait.active;
  protected readonly waitText = computed(() =>
    format(CONSOLE_COPY.save.wait, { n: this.wait.remaining() }),
  );

  private readonly catalogueData = computed(() => {
    const state = this.catalogue.state();
    return state.status === 'ready' ? state.data : null;
  });

  protected readonly groups = computed<readonly PermissionGroup[]>(
    () => this.catalogueData()?.groups ?? [],
  );

  /** Catalogue order of every id, for lists. */
  private readonly order = computed(() => {
    const ids = this.groups().flatMap((group) => group.permissions.map((entry) => entry.id));
    return new Map(ids.map((id, index) => [id, index]));
  });

  /** Every permission this page may show by id: the catalogue and the Clone source. */
  private readonly known = computed<ReadonlyMap<string, PermissionResponse>>(() => {
    const state = this.source();
    const sourcePermissions = state.kind === 'ready' ? state.source.permissions : [];
    return new Map(
      [...sourcePermissions, ...(this.catalogueData()?.permissions ?? [])].map((entry) => [
        entry.id,
        entry,
      ]),
    );
  });

  /** Each permission's affordance on a new role: every row is an add (design §8.3). */
  protected readonly affordances = computed<ReadonlyMap<string, Affordance>>(() => {
    const catalogue = this.catalogueData();
    if (catalogue === null) return new Map();
    const held = new Set<string>();
    for (const name of this.profile.permissions()) {
      const entry = catalogue.byName.get(name);
      if (entry !== undefined) held.add(entry.id);
    }
    const ctx = {
      held,
      isAdministrator: this.profile.isAdministrator(),
      roleSet: NO_IDS,
      isSystemRole: false,
      mutationsEnabled: this.profile.mutationsEnabled(),
      directoryReadId: catalogue.byName.get(DIRECTORY_READ)?.id ?? null,
      adminDefiningHint: false,
    };
    return new Map([...this.known().keys()].map((id) => [id, permissionAffordance(id, ctx)]));
  });

  /** The staged ids whose row is enabled, in catalogue order: what is shown and sent. */
  protected readonly chosen = computed<readonly string[]>(() => {
    const affordances = this.affordances();
    return this.inOrder([...this.staged()].filter((id) => affordances.get(id)?.kind === 'enabled'));
  });

  protected readonly intent = computed<StagedIntent>(() => ({
    add: new Set(this.chosen()),
    remove: EMPTY_INTENT.remove,
  }));

  /** From the 201 on the matrix is read-only, showing what the role is meant to grant. */
  protected readonly lockedIds = computed<ReadonlySet<string> | null>(() => {
    const phase = this.phase();
    return phase.kind === 'partial' ? new Set(phase.ids) : null;
  });

  protected readonly matrixRole = computed(
    () => this.nameValue().trim() || CONSOLE_COPY.createRole.unnamedRole,
  );

  protected readonly propagation = computed(() =>
    this.phase().kind === 'partial'
      ? []
      : propagationFor({ added: this.chosen().length, removed: 0 }),
  );

  protected readonly view = computed<
    'loading' | 'blocked' | 'gone' | 'source-error' | 'error' | 'ready'
  >(() => {
    const source = this.source();
    if (source.kind === 'gone') return 'gone';
    if (source.kind === 'error') return 'source-error';
    const profile = this.profile.state().status;
    if (profile === 'idle' || profile === 'loading') return 'loading';
    if (profile === 'ready' && !this.profile.can('role:write')) return 'blocked';
    const catalogue = this.catalogue.state().status;
    if (catalogue === 'error') return 'error';
    if (catalogue !== 'ready' || source.kind === 'loading') return 'loading';
    return 'ready';
  });

  protected readonly loadingText = computed(() =>
    this.source().kind === 'loading'
      ? CONSOLE_COPY.createRole.loadingSource
      : CONSOLE_COPY.createRole.loading,
  );

  protected readonly catalogueError = computed(() => {
    const state = this.catalogue.state();
    return state.status === 'error'
      ? {
          view: resolveConsoleError(state.error, { area: 'permissions', action: 'load' }),
          failedAt: state.failedAt,
        }
      : null;
  });

  protected readonly sourceError = computed(() => {
    const state = this.source();
    return state.kind === 'error' ? state : null;
  });

  protected readonly notFoundCopy = RbacErrorMessages.ROLE_NOT_FOUND;

  /** "Not copied": the Clone source's permissions the caller cannot grant, with the reason. */
  protected readonly notCopied = computed(() => {
    const state = this.source();
    if (state.kind !== 'ready' || this.view() !== 'ready' || this.phase().kind === 'partial') {
      return null;
    }
    const affordances = this.affordances();
    const items = this.inOrder(state.source.permissions.map((entry) => entry.id)).flatMap((id) => {
      const affordance = affordances.get(id);
      if (affordance?.kind !== 'disabled') return [];
      const label = this.labelOf(id);
      const reason = AFFORDANCE_REASON_TEXT[affordance.reason];
      return [
        { id, label, text: format(CONSOLE_COPY.createRole.notCopiedItem, { label, reason }) },
      ];
    });
    if (items.length === 0) return null;
    return {
      title: format(CONSOLE_COPY.createRole.notCopied, {
        labels: items.map((item) => item.label).join(CONSOLE_COPY.save.listSeparator),
      }),
      items,
    };
  });

  protected readonly nameCounter = computed(() =>
    format(CONSOLE_COPY.createRole.counter, { n: this.nameValue().length, max: ROLE_NAME_MAX }),
  );

  protected readonly nameErrorText = computed(() => this.fieldError('name'));
  protected readonly descriptionErrorText = computed(() => this.fieldError('description'));

  protected readonly nameDescribedBy = computed(() =>
    [NAME_COUNTER_ID, this.nameErrorText() === null ? '' : NAME_ERROR_ID].filter(Boolean).join(' '),
  );

  protected readonly summary = computed<readonly SummaryItem[]>(() => {
    if (!this.summaryShown()) return [];
    const items: SummaryItem[] = [];
    const name = this.nameErrorText();
    if (name !== null) items.push({ field: 'name', message: name });
    const description = this.descriptionErrorText();
    if (description !== null) items.push({ field: 'description', message: description });
    for (const message of this.otherErrors()) items.push({ field: null, message });
    return items;
  });

  protected readonly creating = computed(() => this.phase().kind === 'creating');

  /** Create is off: the live profile is unavailable, or a wait is running. */
  protected readonly submitBlocked = computed(
    () => !this.profile.mutationsEnabled() || this.waiting(),
  );

  protected readonly submitDescribedBy = computed(() => {
    if (!this.profile.mutationsEnabled()) return SUBMIT_REASON_ID;
    return this.waiting() ? WAIT_ID : '';
  });

  protected readonly partial = computed(() => {
    const phase = this.phase();
    return phase.kind === 'partial' ? phase : null;
  });

  private readonly dirty = computed(() => {
    this.formEvents();
    const kind = this.phase().kind;
    return (kind === 'editing' || kind === 'creating') && (this.form.dirty || this.matrixTouched());
  });

  constructor() {
    beforeUnloadWhileDirty(() => this.dirty());

    // A new name or description replaces the server's verdict on the old one.
    for (const field of FIELDS as ReadonlySet<Field>) {
      this.form.controls[field].valueChanges
        .pipe(takeUntilDestroyed())
        .subscribe(() => this.clearServerError(field));
    }

    const from = this.route.snapshot.queryParamMap.get('from');
    if (from !== null && from !== '') {
      const cached = this.cloneSources.take(from);
      if (cached === null) this.loadSource(from);
      else this.seed(cached);
    }
  }

  ngOnInit(): void {
    this.catalogue.load();
  }

  hasUnsavedChanges(): boolean {
    return this.dirty();
  }

  leaveMessage(): string {
    return CONSOLE_COPY.createRole.leaveMessage;
  }

  /**
   * MJ-4: a create in flight (or a partial-create Retry) cannot be abandoned: the server may
   * already hold the role, and leaving would drop the permissions write and the list refresh.
   */
  leaveBlockedMessage(): string | null {
    const phase = this.phase();
    const busy = phase.kind === 'creating' || (phase.kind === 'partial' && phase.retrying);
    // Bounded: the app has no HTTP timeout, so a request that never answers must not trap the user.
    // Past the bound leaving is allowed; destroying the page cancels the request and refreshes the list.
    return busy && Date.now() - this.busySince < LEAVE_REFUSAL_MS
      ? CONSOLE_COPY.createRole.stillCreating
      : null;
  }

  protected onToggle(event: MatrixToggle): void {
    if (this.phase().kind !== 'editing') return;
    if (this.affordances().get(event.permissionId)?.kind !== 'enabled') return;
    this.applyIntent(toggle(NO_IDS, this.intent(), event.permissionId, event.next));
  }

  protected onToggleGroup(event: MatrixGroupToggle): void {
    if (this.phase().kind !== 'editing') return;
    const group = this.groups().find((candidate) => candidate.resource === event.resource);
    if (group === undefined) return;
    const affordances = this.affordances();
    this.applyIntent(
      toggleGroup(
        NO_IDS,
        this.intent(),
        group.permissions.map((entry) => entry.id),
        event.next,
        (id) => affordances.get(id)?.kind === 'enabled',
      ),
    );
  }

  /** Moves focus from an error-summary link to its field, without navigating. */
  protected focusField(event: Event, field: Field): void {
    event.preventDefault();
    if (field === 'name') this.nameField()?.focus();
    else this.descriptionField()?.focus();
  }

  protected cancel(): void {
    void this.router.navigate(['/admin/access/roles']);
  }

  /** Validates, then runs the create (design §11.3). Ignored while one runs or is held. */
  protected submit(): void {
    if (this.phase().kind !== 'editing' || this.submitBlocked()) return;
    this.submitted.set(true);
    this.form.markAllAsTouched();
    this.failure.set(null);
    this.limit.set(null);
    if (this.form.invalid) {
      this.showSummary();
      return;
    }
    this.summaryShown.set(false);
    this.otherErrors.set([]);
    this.serverFieldErrors.set(new Map());

    const ids = this.chosen();
    const { name, description } = this.form.getRawValue();
    this.busySince = Date.now();
    this.phase.set({ kind: 'creating' });
    this.api
      .createRole({ name, description })
      .pipe(
        takeUntilDestroyed(this.destroyRef),
        // However the POST ends, including the page going away before it answers, the server may
        // hold a new role: the console's list must be read again.
        finalize(() => this.roles.invalidate()),
      )
      .subscribe({
        next: (role) => {
          this.roles.invalidate();
          if (ids.length === 0) this.finish(role, 0);
          else this.applyPermissions(role, ids);
        },
        error: (error: unknown) => {
          this.phase.set({ kind: 'editing' });
          this.reportCreateFailure(toAppError(error, 'The role could not be created.'));
        },
      });
  }

  /** The partial banner's Retry: the new role's set is read again and the PUT re-sent. */
  protected retry(): void {
    const phase = this.phase();
    if (phase.kind !== 'partial' || phase.retrying || this.waiting()) return;
    this.busySince = Date.now();
    this.phase.set({ ...phase, retrying: true });
    this.applyPermissions(phase.role, phase.ids);
  }

  /** "Open role": the editor of the new role, which offers the draft written for it. */
  protected openRole(): void {
    const phase = this.phase();
    if (phase.kind !== 'partial') return;
    void this.router.navigate(['/admin/access/roles', phase.role.id, 'edit']);
  }

  protected retrySource(): void {
    const state = this.source();
    if (state.kind === 'error') this.loadSource(state.roleId);
  }

  protected retryCatalogue(): void {
    this.catalogue.load();
  }

  /**
   * `GET` of the new role's set, then one `PUT` with its strong tag verbatim. A weak or missing
   * tag cannot be saved, so it fails without a PUT (design §7.2).
   */
  private applyPermissions(role: RoleResponse, ids: readonly string[]): void {
    let baseEtag: string | null = null;
    this.api
      .getRolePermissions(role.id)
      .pipe(
        switchMap((set) => {
          if (set.etag.kind !== 'strong') {
            const unusable: EtagUnusable = { etagUnusable: true, correlationId: set.correlationId };
            return throwError(() => unusable);
          }
          baseEtag = set.etag.value;
          return this.api.replaceRolePermissions(role.id, ids, set.etag.value);
        }),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: () => this.finish(role, ids.length),
        error: (error: unknown) => this.enterPartial(role, ids, baseEtag, error),
      });
  }

  /** The role exists with what was chosen: say so and open it. */
  private finish(role: RoleResponse, permissionCount: number): void {
    this.phase.set({ kind: 'done' });
    const userId = this.userId();
    if (userId !== null) this.drafts.clear(userId, role.id);
    if (permissionCount > 0) this.roles.invalidate();
    this.logger.info('Access console created a role', {
      event: 'access_console_role_created',
      context: { roleId: role.id, permissionCount },
    });
    this.toast.success(
      [
        CONSOLE_COPY.createRole.success,
        ...propagationFor({ added: permissionCount, removed: 0 }),
      ].join(' '),
    );
    void this.router.navigate(['/admin/access/roles', role.id, 'permissions']);
  }

  /**
   * The role was created but its permissions were not saved (design §11.3): the banner, the
   * locked form and a draft of the chosen ids for the new role, so "Open role" can restore them.
   */
  private enterPartial(
    role: RoleResponse,
    ids: readonly string[],
    baseEtag: string | null,
    error: unknown,
  ): void {
    let failure: PartialFailure;
    let appError: AppError | null = null;
    if (isEtagUnusable(error)) {
      const { etagUnusable } = CONSOLE_COPY.roleDetail;
      failure = {
        title: etagUnusable.title,
        body: etagUnusable.body,
        ...(error.correlationId === null ? {} : { reference: error.correlationId }),
      };
    } else {
      appError = toAppError(error, 'The new role permissions could not be saved.');
      const view = resolveConsoleError(appError, { area: 'roles', action: 'save' });
      failure = {
        title: view.title,
        body: view.body,
        ...(view.reference === undefined ? {} : { reference: view.reference }),
      };
      if (view.showsWait) this.wait.start(view.retryAfterSeconds ?? DEFAULT_RETRY_AFTER_SECONDS);
      if (DENIED.has(appError.code)) this.profile.reload('denied-predicted-allowed');
    }
    this.logger.warn('Access console created a role but could not save its permissions', {
      event: 'access_console_create_partial',
      errorCode: appError?.code ?? 'ETAG_UNUSABLE',
      context: { roleId: role.id, permissionCount: ids.length, traceId: appError?.traceId },
    });
    const userId = this.userId();
    if (userId !== null) {
      this.drafts.write(userId, role.id, {
        add: [...ids],
        remove: [],
        baseEtag,
        savedAt: Date.now(),
      });
    }
    this.form.disable();
    this.phase.set({ kind: 'partial', role, ids, failure, retrying: false });
  }

  /** A refusal of the POST: nothing was created, so the details stay editable (design §12.5). */
  private reportCreateFailure(error: AppError): void {
    this.logger.warn('Access console role create failed', {
      event: 'access_console_action_failed',
      errorCode: error.code,
      context: { action: 'create', reason: error.reason, traceId: error.traceId },
    });
    const view = resolveConsoleError(error, { area: 'roles', action: 'create' });
    switch (error.code) {
      case 'RBAC_006':
      case 'RBAC_007':
        this.serverFieldErrors.set(new Map([['name', view.body]]));
        this.showSummary();
        return;
      case 'RBAC_008':
        this.limit.set(view);
        return;
      case 'VALIDATION_FAILED':
        this.mapFieldErrors(view);
        return;
      default:
        this.failure.set(view);
        if (DENIED.has(error.code)) this.profile.reload('denied-predicted-allowed');
        if (view.showsWait) this.wait.start(view.retryAfterSeconds ?? DEFAULT_RETRY_AFTER_SECONDS);
    }
  }

  /**
   * `VALIDATION_FAILED` `details[]` by field (design §9.2): a form field shows the form's own copy
   * when one of its rules fails, else the server's message (by interpolation); a field the form
   * does not have shows in the summary only.
   */
  private mapFieldErrors(view: ConsoleErrorView): void {
    const fields = new Map<Field, string>();
    const others: string[] = [];
    for (const { field, message } of view.fieldErrors ?? []) {
      if (FIELDS.has(field)) fields.set(field as Field, message);
      else others.push(message);
    }
    if (fields.size === 0 && others.length === 0) {
      this.failure.set(view);
      return;
    }
    this.serverFieldErrors.set(fields);
    this.otherErrors.set(others);
    this.showSummary();
  }

  private fieldError(field: Field): string | null {
    this.formEvents();
    const control = this.form.controls[field];
    const client = field === 'name' ? nameError(control) : descriptionError(control);
    if (client !== null && (this.submitted() || control.touched)) return client;
    return this.serverFieldErrors().get(field) ?? null;
  }

  private clearServerError(field: Field): void {
    if (!this.serverFieldErrors().has(field)) return;
    const next = new Map(this.serverFieldErrors());
    next.delete(field);
    this.serverFieldErrors.set(next);
  }

  /** Shows the error summary and moves focus to it once it is rendered. */
  private showSummary(): void {
    this.summaryShown.set(true);
    afterNextRender(() => this.summaryRef()?.nativeElement.focus(), { injector: this.injector });
  }

  /** Reads the Clone source: the role and its set, together (design §6.5 "Create"). */
  private loadSource(roleId: string): void {
    this.source.set({ kind: 'loading', roleId });
    forkJoin([this.api.getRole(roleId), this.api.getRolePermissions(roleId)])
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: ([role, set]) => this.seed({ role, permissions: set.permissions }),
        error: (error: unknown) => {
          const appError = toAppError(error, 'The role to copy could not be read.');
          this.logger.warn('Access console could not read the role to copy', {
            event: 'access_console_load_failed',
            errorCode: appError.code,
            context: { area: 'roles', action: 'clone', roleId, traceId: appError.traceId },
          });
          this.source.set(
            GONE.has(appError.code)
              ? { kind: 'gone' }
              : {
                  kind: 'error',
                  roleId,
                  view: resolveConsoleError(appError, { area: 'roles', action: 'load' }),
                  failedAt: Date.now(),
                },
          );
        },
      });
  }

  /** Starts the form from the Clone source: its name prefixed, its permissions staged. */
  private seed(source: CloneSource): void {
    this.source.set({ kind: 'ready', source });
    this.form.controls.name.setValue(cloneName(source.role.name));
    this.staged.set(new Set(source.permissions.map((entry) => entry.id)));
  }

  private applyIntent(intent: StagedIntent): void {
    this.matrixTouched.set(true);
    this.staged.set(new Set(intent.add));
  }

  private inOrder(ids: readonly string[]): string[] {
    const order = this.order();
    const rank = (id: string): number => order.get(id) ?? Number.MAX_SAFE_INTEGER;
    return [...ids].sort((a, b) => rank(a) - rank(b) || (a < b ? -1 : a > b ? 1 : 0));
  }

  /** The label shown for a permission id: its label, else its code, else the id. */
  private labelOf(id: string): string {
    const code = this.known().get(id)?.name ?? id;
    return permissionLabel(code) ?? code;
  }

  private userId(): string | null {
    return this.auth.currentUser()?.userId ?? null;
  }
}
