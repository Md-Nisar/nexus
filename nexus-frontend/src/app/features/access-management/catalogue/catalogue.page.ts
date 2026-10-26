import { Component, OnInit, computed, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { NxEmptyState, NxPageHeader, NxSearchField, NxSkeleton } from '../../../shared/ui';
import type { PermissionResponse } from '../../../shared/types/api/rbac';
import { CONSOLE_COPY, format } from '../copy/console-copy';
import { permissionLabel } from '../copy/permission-labels';
import { resolveConsoleError } from '../copy/resolve-console-error';
import { CatalogueStore, PermissionGroup } from '../data/catalogue.store';
import { ConsoleErrorPanel } from '../ui/console-error-panel';
import { SensitiveBadge } from '../ui/sensitive-badge';

/** One permission as shown: its label is `null` when the code is outside the known catalogue. */
interface PermissionRow {
  readonly id: string;
  readonly code: string;
  readonly label: string | null;
  readonly description: string;
  readonly isSensitive: boolean;
}

interface GroupView {
  readonly resource: string;
  readonly label: string;
  readonly rows: readonly PermissionRow[];
}

function toRow(entry: PermissionResponse): PermissionRow {
  return {
    id: entry.id,
    code: entry.name,
    label: permissionLabel(entry.name) ?? null,
    description: entry.description,
    isSensitive: entry.isSensitive,
  };
}

/**
 * The permission catalogue (US-020 design §12.6): every permission Nexus can grant, grouped by
 * resource, searchable.
 *
 * - **Data:** {@link CatalogueStore.load} reads the catalogue once per console session; this page
 *   only reads it.
 * - **URL is the state (FR-G1):** `q` lives in the query string; the search field only navigates.
 *   The search is a case-folded substring match over label, code and description, never a regex.
 * - **Sensitive:** the badge sits beside the permission, and the definition is visible text in a
 *   disclosure at the top, so it does not depend on hover.
 * - **Unlabelled:** a code the app has no label for shows its raw code and an "Unlabelled" badge.
 *   The store logs it once.
 * - **Text:** descriptions are server text and render by interpolation only.
 */
@Component({
  selector: 'app-catalogue-page',
  imports: [
    FormsModule,
    NxEmptyState,
    NxPageHeader,
    NxSearchField,
    NxSkeleton,
    ConsoleErrorPanel,
    SensitiveBadge,
  ],
  templateUrl: './catalogue.page.html',
  styleUrl: './catalogue.page.scss',
})
export class CataloguePage implements OnInit {
  private readonly store = inject(CatalogueStore);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  protected readonly copy = CONSOLE_COPY;
  protected readonly skeletonRows = [0, 1, 2, 3, 4, 5];

  private readonly params = toSignal(this.route.queryParamMap, { requireSync: true });
  protected readonly q = computed(() => this.params().get('q') ?? '');

  protected readonly status = computed(() => this.store.state().status);

  private readonly groups = computed<readonly PermissionGroup[]>(() => {
    const state = this.store.state();
    return state.status === 'ready' ? state.data.groups : [];
  });

  protected readonly total = computed(() => {
    const state = this.store.state();
    return state.status === 'ready' ? state.data.permissions.length : 0;
  });

  protected readonly visibleGroups = computed<readonly GroupView[]>(() => {
    const needle = this.q().trim().toLowerCase();
    const views: GroupView[] = [];
    for (const group of this.groups()) {
      const rows = group.permissions
        .map(toRow)
        .filter(
          (row) =>
            needle === '' ||
            row.code.toLowerCase().includes(needle) ||
            row.description.toLowerCase().includes(needle) ||
            (row.label?.toLowerCase().includes(needle) ?? false),
        );
      if (rows.length > 0) views.push({ resource: group.resource, label: group.label, rows });
    }
    return views;
  });

  protected readonly matchCount = computed(() =>
    this.visibleGroups().reduce((sum, group) => sum + group.rows.length, 0),
  );

  protected readonly countText = computed(() =>
    this.matchCount() === 1
      ? CONSOLE_COPY.catalogue.resultCountOne
      : format(CONSOLE_COPY.catalogue.resultCount, { n: this.matchCount() }),
  );

  protected readonly emptyText = computed(() =>
    this.total() === 0 ? CONSOLE_COPY.catalogue.emptyAll : CONSOLE_COPY.catalogue.emptySearch,
  );

  private readonly failure = computed(() => {
    const state = this.store.state();
    return state.status === 'error' ? state : null;
  });
  protected readonly errorView = computed(() => {
    const failure = this.failure();
    return failure === null
      ? null
      : resolveConsoleError(failure.error, { area: 'permissions', action: 'load' });
  });
  protected readonly failedAt = computed(() => this.failure()?.failedAt);

  ngOnInit(): void {
    this.store.load();
  }

  protected retry(): void {
    this.store.load();
  }

  protected onSearch(q: string): void {
    this.navigate(q === '' ? null : q);
  }

  protected onSearchCleared(): void {
    this.navigate(null);
  }

  private navigate(q: string | null): void {
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { q },
      queryParamsHandling: 'merge',
    });
  }
}
