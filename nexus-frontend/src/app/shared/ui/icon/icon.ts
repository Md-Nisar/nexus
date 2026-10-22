import { Component, input } from '@angular/core';
import { MatIcon } from '@angular/material/icon';

/**
 * Decorative icon wrapping `MatIcon`. Always `aria-hidden`; convey meaning with adjacent text.
 * Size and colour come from the host (`font-size`, `width`, `height`, `color`).
 */
@Component({
  selector: 'nx-icon',
  imports: [MatIcon],
  template: `<mat-icon aria-hidden="true">{{ name() }}</mat-icon>`,
  styles: `
    :host {
      display: inline-flex;
    }
    mat-icon {
      font-size: inherit;
      width: 100%;
      height: 100%;
    }
  `,
})
export class NxIcon {
  /** Material Symbols ligature name, e.g. `check_circle`. */
  readonly name = input.required<string>();
}
