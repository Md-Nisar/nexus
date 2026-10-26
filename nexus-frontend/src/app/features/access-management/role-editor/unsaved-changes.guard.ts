import { DestroyRef, Renderer2, effect, inject } from '@angular/core';
import { CanDeactivateFn } from '@angular/router';
import { map } from 'rxjs';
import { AuthStore } from '../../../core/auth/auth.store';
import { NxDialog, NxToast } from '../../../shared/ui';
import { CONSOLE_COPY } from '../copy/console-copy';

/** A page that can hold staged work the user has not saved. */
export interface HasUnsavedChanges {
  hasUnsavedChanges(): boolean;
  /** What the leave prompt says is kept; the editor's draft message when absent. */
  leaveMessage?(): string;
  /**
   * Why leaving is refused right now (a request that cannot be abandoned is running), or `null`.
   * The guard shows it as a notice and keeps the page.
   */
  leaveBlockedMessage?(): string | null;
}

/**
 * Asks before leaving a page with unsaved changes (US-020 design §4.8). A clean page leaves at
 * once; otherwise the leave prompt opens and the navigation follows the choice: "Leave" goes,
 * "Stay" or a dismissal stays. A navigation forced by a refresh failure passes through here too.
 *
 * - **Signed out** (logout, or a session that could not be renewed): leaves without a prompt.
 *   Nothing on the page can be saved any more, logout has already deleted the drafts, and an
 *   expired session keeps the draft it wrote on every change, so the prompt could only offer a
 *   signed-out page or claim something untrue.
 * - **A request that cannot be abandoned** (`leaveBlockedMessage`): refused with that notice.
 */
export const unsavedChangesGuard: CanDeactivateFn<HasUnsavedChanges> = (component) => {
  if (inject(AuthStore).currentUser() === null) return true;
  const blocked = component.leaveBlockedMessage?.() ?? null;
  if (blocked !== null) {
    inject(NxToast).info(blocked);
    return false;
  }
  if (!component.hasUnsavedChanges()) return true;
  const { leave } = CONSOLE_COPY;
  return inject(NxDialog)
    .open({
      title: leave.title,
      message: component.leaveMessage?.() ?? leave.message,
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
