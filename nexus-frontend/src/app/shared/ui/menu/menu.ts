import { Component, input, output } from '@angular/core';
import { MatIconButton } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatMenuModule } from '@angular/material/menu';

/** One entry of an {@link NxMenu}. */
export interface MenuItem {
  readonly id: string;
  readonly label: string;
  readonly icon?: string;
  /** Destructive action: rendered with an icon and text, never colour alone. */
  readonly danger?: boolean;
  readonly disabled?: boolean;
  /** Visible reason shown for a disabled item; the item stays focusable and announces it. */
  readonly disabledReason?: string;
  /** Overrides the default `nx-menu-item-{id}` test id. */
  readonly testId?: string;
}

/**
 * Icon-triggered action menu wrapping `MatMenu`.
 *
 * Arrow-key navigation, Escape and focus return come from Material. The icon-only trigger
 * is named by the required `triggerLabel`. Choosing an enabled item emits its `id`.
 */
@Component({
  selector: 'nx-menu',
  imports: [MatIconButton, MatIconModule, MatMenuModule],
  template: `
    <button
      type="button"
      mat-icon-button
      class="nx-menu__trigger"
      data-testid="nx-menu-trigger"
      [matMenuTriggerFor]="menu"
      [attr.aria-label]="triggerLabel()"
    >
      <mat-icon aria-hidden="true">{{ triggerIcon() }}</mat-icon>
    </button>
    <mat-menu #menu="matMenu" class="nx-menu__panel">
      @for (item of items(); track item.id) {
        <button
          type="button"
          mat-menu-item
          class="nx-menu__item"
          [class.nx-menu__item--danger]="item.danger"
          [disabled]="item.disabled ?? false"
          [disabledInteractive]="!!item.disabledReason"
          [attr.aria-describedby]="item.disabledReason ? 'nx-menu-reason-' + item.id : null"
          [attr.data-testid]="item.testId ?? 'nx-menu-item-' + item.id"
          (click)="onItem(item)"
        >
          @if (item.icon ?? (item.danger ? 'warning' : null); as icon) {
            <mat-icon aria-hidden="true">{{ icon }}</mat-icon>
          }
          <span>{{ item.label }}</span>
          @if (item.disabledReason) {
            <span class="nx-menu__reason" [id]="'nx-menu-reason-' + item.id">{{
              item.disabledReason
            }}</span>
          }
        </button>
      }
    </mat-menu>
  `,
  styleUrl: './menu.scss',
})
export class NxMenu {
  readonly items = input.required<readonly MenuItem[]>();
  readonly triggerLabel = input.required<string>();
  readonly triggerIcon = input('more_vert');

  /** Emits the `id` of the chosen, enabled item. */
  readonly selected = output<string>();

  protected onItem(item: MenuItem): void {
    if (item.disabled) return;
    this.selected.emit(item.id);
  }
}
