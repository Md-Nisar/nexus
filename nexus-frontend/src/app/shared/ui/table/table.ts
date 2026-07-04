import { ChangeDetectionStrategy, Component, input, output } from '@angular/core';
import { MatTableModule } from '@angular/material/table';
import { MatSortModule, Sort } from '@angular/material/sort';
import { MatPaginatorModule, PageEvent } from '@angular/material/paginator';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { NxBadge, BadgeVariant } from '../badge/badge';

/**
 * Cell rendering type.
 * - `text`: Plain text (default)
 * - `badge`: Colored status badge with semantic variant
 * - `mono`: Monospace font (IDs, tokens, hashes)
 */
export type CellType = 'text' | 'badge' | 'mono';

/**
 * Column definition for `NxTable`.
 *
 * @property {string} key - Unique identifier and data accessor (object key)
 * @property {string} header - Display label in the header row
 * @property {boolean} [sortable=false] - If true, column header becomes clickable to trigger sort
 * @property {string} [width='auto'] - CSS width (e.g. '200px', '30%'); applied via inline style
 * @property {CellType} [type='text'] - Cell rendering style (text, badge, or mono)
 * @property {(value: unknown) => BadgeVariant} [badgeVariant] - Function to derive badge color from cell value;
 *   required when `type === 'badge'`. Receives the row object's value at `[key]` and returns a variant
 *   ('success' | 'error' | 'warning' | 'neutral' | 'primary').
 */
export interface TableColumn {
  readonly key: string;
  readonly header: string;
  readonly sortable?: boolean;
  readonly width?: string;
  readonly type?: CellType;
  readonly badgeVariant?: (value: unknown) => BadgeVariant;
}

/**
 * Data table component for rendering tabular data with sorting, pagination, and flexible cell types.
 *
 * `<nx-table>` displays structured data in a Material Design 3 table with:
 * - Sortable column headers (opt-in per column)
 * - Built-in pagination with customizable page sizes
 * - Three cell rendering modes: plain text, status badges, and monospace (for IDs)
 * - Loading state with progress bar
 * - Clickable rows with emit event
 * - Responsive scrolling for mobile screens
 * - Full keyboard and screen reader support
 *
 * ## Features
 * - **Flexible column types**: text, badge (with semantic color), mono (code/IDs)
 * - **Optional sorting**: Mark `sortable: true` on columns to enable column header clicks
 * - **Pagination**: Enable with `pageable` input; customize `pageSize` and `pageSizeOptions`
 * - **Loading state**: `loading` input shows progress bar while fetching data
 * - **Row selection**: `clickable` input enables hover/click styles and emits `rowClick` events
 * - **Empty state slot**: Use `[slot=empty]` named slot for custom empty message
 * - **Responsive**: Wrapper scrolls horizontally on mobile; table always takes 100% width
 * - **Accessible**: ARIA labels on progress bar and paginator; semantic table markup
 *
 * @example
 * // Basic table with text columns
 * ```typescript
 * users = signal<User[]>([
 *   { id: '1', name: 'Alice', email: 'alice@example.com' },
 *   { id: '2', name: 'Bob', email: 'bob@example.com' },
 * ]);
 *
 * columns: TableColumn[] = [
 *   { key: 'name', header: 'Full Name' },
 *   { key: 'email', header: 'Email', width: '40%' },
 * ];
 * ```
 *
 * ```html
 * <nx-table
 *   [columns]="columns"
 *   [rows]="users()"
 *   (rowClick)="openUserDetail($event)"
 *   clickable
 * />
 * ```
 *
 * @example
 * // Table with sortable columns, pagination, and status badges
 * ```typescript
 * columns: TableColumn[] = [
 *   { key: 'id', header: 'ID', sortable: true, width: '120px', type: 'mono' },
 *   { key: 'name', header: 'Name', sortable: true },
 *   {
 *     key: 'status',
 *     header: 'Status',
 *     sortable: true,
 *     type: 'badge',
 *     badgeVariant: (value) => {
 *       const status = value as 'active' | 'inactive' | 'pending';
 *       return status === 'active' ? 'success' : status === 'inactive' ? 'error' : 'warning';
 *     }
 *   },
 * ];
 * ```
 *
 * ```html
 * <nx-table
 *   [columns]="columns"
 *   [rows]="items()"
 *   [loading]="isLoading()"
 *   [pageable]="true"
 *   [totalCount]="totalItems()"
 *   [pageSize]="pageSize()"
 *   [pageSizeOptions]="[10, 25, 50]"
 *   (sortChange)="onSort($event)"
 *   (pageChange)="onPageChange($event)"
 * >
 *   <div slot="empty">
 *     <nx-empty-state
 *       title="No items found"
 *       description="Try adjusting your filters or search."
 *     />
 *   </div>
 * </nx-table>
 * ```
 *
 * @example
 * // Monospace cells for IDs or tokens
 * ```html
 * <nx-table
 *   [columns]="[
 *     { key: 'tokenId', header: 'Token', type: 'mono', width: '300px' },
 *     { key: 'createdAt', header: 'Created' },
 *   ]"
 *   [rows]="tokens()"
 * />
 * ```
 * Monospace text displays with `--nx-font-family-mono` for better readability of codes/IDs.
 *
 * @design-system
 * Uses design tokens for styling:
 * - `--nx-radius-sm` — border-radius for table wrapper
 * - `--nx-color-outline-variant` — table borders and divider lines
 * - `--nx-color-surface-variant` — header background; clickable row hover
 * - `--nx-color-on-surface` / `--nx-color-on-surface-muted` — text colors
 * - `--nx-text-sm` / `--nx-text-base` — header/cell typography
 * - `--nx-space-3`, `--nx-space-4`, `--nx-space-12` — padding and spacing
 * - `--nx-font-family-mono` — monospace cell rendering
 * - `--nx-duration-fast`, `--nx-easing-standard` — row hover transition
 *
 * @accessibility
 * - Root wrapper has `data-testid="nx-table"` for test selection
 * - Progress bar (loading state) has `aria-label="Loading table data"`
 * - Paginator has `aria-label="Paginate results"`
 * - Sort headers are native `<mat-sort-header>` with ARIA attributes
 * - Table uses semantic `<table>`, `<th>`, `<td>` elements
 * - Empty state slot uses native semantic elements (prefer `<nx-empty-state>`)
 * - Keyboard: sort via Enter/Space on header; paginate via arrow keys in paginator
 * - Screen readers announce: table structure, sortable state, current page, total items
 * - **No focus trap**: Clickable rows do not consume keyboard focus; use for visual affordance only
 * - Badge cells use `<nx-badge>` which announces status changes via `aria-live`
 *
 * @event sortChange - Emits `Sort` object when column header is clicked; includes `active` (column key) and `direction` ('asc'|'desc'|'')
 * @event rowClick - Emits full row data object when row is clicked (only if `clickable=true`)
 * @event pageChange - Emits `PageEvent` object when pagination controls are used; includes `pageIndex`, `pageSize`, `length`
 */

@Component({
  selector: 'nx-table',
  standalone: true,
  imports: [MatTableModule, MatSortModule, MatPaginatorModule, MatProgressBarModule, NxBadge],
  template: `
    <div class="nx-table-wrapper" data-testid="nx-table">
      @if (loading()) {
        <mat-progress-bar mode="indeterminate" aria-label="Loading table data" />
      }
      <table
        mat-table
        matSort
        [dataSource]="rows()"
        class="nx-table"
        (matSortChange)="sortChange.emit($event)"
      >
        @for (col of columns(); track col.key) {
          <ng-container [matColumnDef]="col.key">
            <th
              mat-header-cell
              *matHeaderCellDef
              [mat-sort-header]="col.sortable ? col.key : ''"
              [disabled]="!col.sortable"
              [style.width]="col.width || 'auto'"
            >
              {{ col.header }}
            </th>
            <td mat-cell *matCellDef="let row">
              @switch (col.type) {
                @case ('badge') {
                  <nx-badge
                    [variant]="col.badgeVariant ? col.badgeVariant(row[col.key]) : 'neutral'"
                  >
                    {{ row[col.key] }}
                  </nx-badge>
                }
                @case ('mono') {
                  <span class="nx-table__mono">{{ row[col.key] }}</span>
                }
                @default {
                  {{ row[col.key] }}
                }
              }
            </td>
          </ng-container>
        }
        <tr mat-header-row *matHeaderRowDef="columnKeys()"></tr>
        <tr
          mat-row
          *matRowDef="let row; columns: columnKeys()"
          class="nx-table__row"
          [class.nx-table__row--clickable]="clickable()"
          (click)="rowClick.emit(row)"
        ></tr>
        <tr *matNoDataRow>
          <td [attr.colspan]="columns().length" class="nx-table__empty">
            <ng-content select="[slot=empty]">No data available.</ng-content>
          </td>
        </tr>
      </table>
      @if (pageable()) {
        <mat-paginator
          [length]="totalCount()"
          [pageSize]="pageSize()"
          [pageSizeOptions]="pageSizeOptions()"
          showFirstLastButtons
          (page)="pageChange.emit($event)"
          aria-label="Paginate results"
        />
      }
    </div>
  `,
  styleUrl: './table.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NxTable<T extends Record<string, unknown> = Record<string, unknown>> {
  /**
   * Array of column definitions describing how to render each column.
   * Each column specifies a data key, header label, and optional sorting/styling.
   * @default []
   * @see {@link TableColumn} for structure
   * @example
   * ```typescript
   * [
   *   { key: 'id', header: 'ID', sortable: true, type: 'mono', width: '120px' },
   *   { key: 'name', header: 'Name', sortable: true },
   * ]
   * ```
   */
  readonly columns = input<TableColumn[]>([]);

  /**
   * Array of row objects to display in the table. Each object must contain
   * keys matching the `key` property of columns for proper data binding.
   * @default []
   * @example
   * ```typescript
   * [
   *   { id: '123e4567', name: 'Alice', status: 'active' },
   *   { id: '789a0123', name: 'Bob', status: 'inactive' },
   * ]
   * ```
   */
  readonly rows = input<T[]>([]);

  /**
   * If true, displays a progress bar above the table to indicate data is loading.
   * Used when fetching rows asynchronously; automatically hidden when rows are populated.
   * @default false
   */
  readonly loading = input(false);

  /**
   * If true, enables pagination controls below the table with page navigation.
   * When enabled, `totalCount`, `pageSize`, and `pageSizeOptions` should be set.
   * Emits `pageChange` events when user navigates.
   * @default false
   * @see {@link totalCount}
   * @see {@link pageSize}
   */
  readonly pageable = input(false);

  /**
   * If true, applies hover and click styles to rows, and emits `rowClick` events
   * when a row is clicked. Use this for selectable/interactive tables.
   * Hint: Cursor changes to pointer on hover when enabled.
   * @default false
   * @see {@link rowClick}
   */
  readonly clickable = input(false);

  /**
   * Total number of rows available across all pages (used for pagination).
   * Required when `pageable=true` to calculate total number of pages.
   * @default 0
   * @example totalCount=150 with pageSize=20 renders 8 pages (0–7)
   */
  readonly totalCount = input(0);

  /**
   * Number of rows displayed per page (for pagination).
   * Only used when `pageable=true`.
   * @default 20
   */
  readonly pageSize = input(20);

  /**
   * Array of page size options shown in the paginator dropdown.
   * User can click to change the page size; triggers `pageChange` event.
   * @default [10, 20, 50]
   * @example [5, 10, 25, 100] for fine-grained page size control
   */
  readonly pageSizeOptions = input<number[]>([10, 20, 50]);

  /**
   * Emits when a row is clicked. Only fired when `clickable=true`.
   * Value is the full row object (T).
   * @example (rowClick)="onRowSelect($event)" → $event is the clicked row data
   */
  readonly rowClick = output<T>();

  /**
   * Emits when a sortable column header is clicked.
   * Value is Material `Sort` object containing:
   * - `active`: column key that was clicked
   * - `direction`: sort direction ('asc' | 'desc' | '')
   * @example (sortChange)="onSort($event)" → $event.active='name', $event.direction='asc'
   */
  readonly sortChange = output<Sort>();

  /**
   * Emits when user interacts with pagination (page number, page size change).
   * Value is Material `PageEvent` containing:
   * - `pageIndex`: zero-based current page
   * - `pageSize`: rows per page
   * - `length`: total count (from `totalCount` input)
   * @example (pageChange)="loadPage($event.pageIndex, $event.pageSize)"
   */
  readonly pageChange = output<PageEvent>();

  protected columnKeys(): string[] {
    return this.columns().map((c) => c.key);
  }
}
