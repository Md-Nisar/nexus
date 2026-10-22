import { ActivatedRouteSnapshot, NavigationEnd, Router } from '@angular/router';
import { filter, skip } from 'rxjs';

function deepestChild(snapshot: ActivatedRouteSnapshot): ActivatedRouteSnapshot {
  let current = snapshot;
  while (current.firstChild) current = current.firstChild;
  return current;
}

/**
 * Moves focus to the routed page's `h1` (else `#main-content`) after every navigation except
 * the first, so screen-reader and keyboard users land on the new page. Routes with
 * `data.selfManagedFocus` are skipped because the page manages its own focus.
 *
 * Lives for the application's lifetime, so the subscription is never torn down.
 */
export function startRouteFocus(router: Router, doc: Document): void {
  router.events
    .pipe(
      filter((event): event is NavigationEnd => event instanceof NavigationEnd),
      skip(1),
    )
    .subscribe(() => {
      if (deepestChild(router.routerState.snapshot.root).data['selfManagedFocus'] === true) return;
      // Let the routed component render before looking for its heading.
      setTimeout(() => {
        const target =
          doc.querySelector<HTMLElement>('#main-content h1') ??
          doc.querySelector<HTMLElement>('h1') ??
          doc.getElementById('main-content');
        if (target && !target.hasAttribute('tabindex')) target.setAttribute('tabindex', '-1');
        target?.focus();
      });
    });
}
