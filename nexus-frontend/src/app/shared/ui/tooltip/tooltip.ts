import { Directive } from '@angular/core';
import { MatTooltip } from '@angular/material/tooltip';

/**
 * Supplementary hint on hover and keyboard focus, wrapping `MatTooltip`.
 *
 * Never the only carrier of information: a disabled reason or an error must also be visible
 * text (see `NxCheckbox` `disabledReason`). Apply to a focusable element so keyboard users
 * can reach it.
 *
 * @example
 * <button nxTooltip="Copy the link" nxTooltipPosition="below">Copy</button>
 */
@Directive({
  selector: '[nxTooltip]',
  hostDirectives: [
    {
      directive: MatTooltip,
      inputs: ['matTooltip: nxTooltip', 'matTooltipPosition: nxTooltipPosition'],
    },
  ],
})
export class NxTooltip {}
