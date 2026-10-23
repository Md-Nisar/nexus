import { Component, input, output } from '@angular/core';
import { MatChip, MatChipRemove, MatChipSet } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
import type { BadgeVariant } from '../badge/badge';

/**
 * Compact label, optionally removable, wrapping `MatChip`.
 *
 * The label text carries the meaning; the variant colour is decoration only. The remove
 * button is named `Remove {label}` and emits `removed`.
 */
@Component({
  selector: 'nx-chip',
  imports: [MatChipSet, MatChip, MatChipRemove, MatIconModule],
  template: `
    <mat-chip-set role="presentation">
      <mat-chip
        class="nx-chip"
        data-testid="nx-chip"
        [class]="'nx-chip nx-chip--' + variant()"
        role="presentation"
      >
        {{ label() }}
        @if (removable()) {
          <button
            type="button"
            matChipRemove
            class="nx-chip__remove"
            data-testid="nx-chip-remove"
            [attr.aria-label]="'Remove ' + label()"
            (click)="removed.emit()"
          >
            <mat-icon aria-hidden="true">close</mat-icon>
          </button>
        }
      </mat-chip>
    </mat-chip-set>
  `,
  styleUrl: './chip.scss',
})
export class NxChip {
  readonly label = input.required<string>();
  readonly variant = input<BadgeVariant>('neutral');
  readonly removable = input(false);

  /** Emits when the remove button is activated. */
  readonly removed = output<void>();
}
