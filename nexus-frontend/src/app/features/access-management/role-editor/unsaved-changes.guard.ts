import { DestroyRef, Renderer2, effect, inject } from '@angular/core';
import { CanDeactivateFn } from '@angular/router';
import { map } from 'rxjs';
import { NxDialog } from '../../../shared/ui';
import { CONSOLE_COPY } from '../copy/console-copy';

/** A page that can hold staged work the user has not saved. */
export interface HasUnsavedChanges {
  hasUnsavedChanges(): boolean;
}

/**
 * Asks before leaving a page with unsaved changes (US-020 design §4.8). A clean page leaves at
 * once; otherwise the leave prompt opens and the navigation follows the choice: "Leave" goes,
 * "Stay" or a dismissal stays. A navigation forced by a refresh failure passes through here too.
 */
export const unsavedChangesGuard: CanDeactivateFn<HasUnsavedChanges> = (component) => {
  if (!component.hasUnsavedChanges()) return true;
  const { leave } = CONSOLE_COPY;
  return inject(NxDialog)
    .open({
      title: leave.title,
      message: leave.message,
      confirmLabel: leave.confirm,
      cancelLabel: leave.cancel,
      variant: 'default',
    })
    .afterClosed()
    .pipe(map((choice) => choice === true));
};

/**
 * Registers a `beforeunload` listener only while `isDirty()` is true, so the browser asks before a
 * reload or tab close drops staged work, and a clean page never blocks the unload. The listener is
 * removed when the page becomes clean and when it is destroyed. Call in an injection context.
 */
export function beforeUnloadWhileDirty(isDirty: () => boolean): void {
  const renderer = inject(Renderer2);
  let unlisten: (() => void) | null = null;
  const stop = (): void => {
    unlisten?.();
    unlisten = null;
  };
  effect(() => {
    if (!isDirty()) {
      stop();
      return;
    }
    unlisten ??= renderer.listen('window', 'beforeunload', (event: BeforeUnloadEvent) => {
      event.preventDefault();
    });
  });
  inject(DestroyRef).onDestroy(stop);
}
