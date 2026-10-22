import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { afterEach, describe, expect, it } from 'vitest';
import { DashboardComponent } from '../../features/dashboard/dashboard.component';
import { startRouteFocus } from './route-focus';

@Component({ template: '<h1 id="page-h1" tabindex="-1">Page</h1>' })
class WithHeading {}

@Component({ template: '<p>no heading</p>' })
class WithoutHeading {}

describe('startRouteFocus', () => {
  let host: HTMLElement;

  function setup() {
    host = document.createElement('main');
    host.id = 'main-content';
    host.tabIndex = -1;
    document.body.appendChild(host);
    TestBed.configureTestingModule({
      providers: [
        provideRouter([
          { path: 'a', component: WithHeading },
          { path: 'b', component: WithHeading },
          { path: 'plain', component: WithoutHeading },
          { path: 'own', component: WithHeading, data: { selfManagedFocus: true } },
        ]),
      ],
    });
    const router = TestBed.inject(Router);
    startRouteFocus(router, document);
    return router;
  }

  /** Mirrors the routed component into the host, as the shell's outlet does. */
  async function go(router: Router, url: string, content: 'h1' | 'none'): Promise<void> {
    host.replaceChildren();
    if (content === 'h1') {
      // The real dashboard markup: a bare h1 without tabindex.
      const dashboard = TestBed.createComponent(DashboardComponent);
      dashboard.detectChanges();
      host.appendChild(dashboard.nativeElement);
    }
    await router.navigateByUrl(url);
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  afterEach(() => host.remove());

  it('does not move focus on the first navigation', async () => {
    const router = setup();
    await go(router, '/a', 'h1');
    expect(document.activeElement).toBe(document.body);
  });

  it('focuses the h1 on the second navigation', async () => {
    const router = setup();
    await go(router, '/a', 'h1');
    await go(router, '/b', 'h1');
    expect(document.activeElement).toBe(host.querySelector('h1'));
  });

  it('falls back to #main-content when the page has no h1', async () => {
    const router = setup();
    await go(router, '/a', 'h1');
    await go(router, '/plain', 'none');
    expect(document.activeElement).toBe(host);
  });

  it('skips routes with data.selfManagedFocus', async () => {
    const router = setup();
    await go(router, '/a', 'h1');
    await go(router, '/own', 'h1');
    expect(document.activeElement).toBe(document.body);
  });
});
