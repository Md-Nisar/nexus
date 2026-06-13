import { ChangeDetectionStrategy, Component, input, output } from '@angular/core';
import { MatTableModule } from '@angular/material/table';
import { MatSortModule, Sort } from '@angular/material/sort';
import { MatPaginatorModule, PageEvent } from '@angular/material/paginator';
import { MatProgressBarModule } from '@angular/material/progress-bar';

export interface TableColumn {
  readonly key: string;
  readonly header: string;
  readonly sortable?: boolean;
  readonly width?: string;
}

@Component({
  selector: 'nx-table',
  standalone: true,
  imports: [MatTableModule, MatSortModule, MatPaginatorModule, MatProgressBarModule],
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
            <td mat-cell *matCellDef="let row">{{ row[col.key] }}</td>
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
  readonly columns = input<TableColumn[]>([]);
  readonly rows = input<T[]>([]);
  readonly loading = input(false);
  readonly pageable = input(false);
  readonly clickable = input(false);
  readonly totalCount = input(0);
  readonly pageSize = input(20);
  readonly pageSizeOptions = input<number[]>([10, 20, 50]);

  readonly rowClick = output<T>();
  readonly sortChange = output<Sort>();
  readonly pageChange = output<PageEvent>();

  protected columnKeys(): string[] {
    return this.columns().map((c) => c.key);
  }
}
