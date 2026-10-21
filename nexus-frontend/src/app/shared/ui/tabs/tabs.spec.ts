import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../testing/axe';
import { NavTab, NxTabs } from './tabs';

@Component({ template: '<p>page</p>' })
class Blank {}

@Component({
  imports: [NxTabs],
  template: `<nx-tabs [tabs]="tabs" ariaLabel="Settings sections"
    ><p id="panel">Panel</p></nx-tabs
  >`,
})
class Host {
  readonly tabs: readonly NavTab[] = [
    { label: 'Profile', path: '/profile' },
    { label: 'Security', path: '/security', testId: 'security-tab' },
  ];
}

describe('NxTabs', () => {
  async function setup() {
    TestBed.configureTestingModule({
      imports: [Host],
      providers: [
        provideRouter([
          { path: 'profile', component: Blank },
          { path: 'security', component: Blank },
        ]),
      ],
    });
    const harness = await RouterTestingHarness.create();
    const fixture = TestBed.createComponent(Host);
    await fixture.whenStable();
    return { harness, fixture, el: fixture.nativeElement as HTMLElement };
  }

  it('labels the tab bar with ariaLabel and renders one link per tab', async () => {
    const { el } = await setup();
    expect(el.querySelector('[aria-label="Settings sections"]')).not.toBeNull();
    const links = Array.from(el.querySelectorAll('a[mat-tab-link]'));
    expect(links.map((a) => a.textContent?.trim())).toEqual(['Profile', 'Security']);
  });

  it('uses testId when given and a derived id otherwise', async () => {
    const { el } = await setup();
    expect(el.querySelector('[data-testid="security-tab"]')).not.toBeNull();
    expect(el.querySelector('[data-testid="nx-tab-profile"]')).not.toBeNull();
  });

  it('projects content into the tab panel', async () => {
    const { el } = await setup();
    expect(el.querySelector('mat-tab-nav-panel #panel')).not.toBeNull();
  });

  it('marks the tab matching the route active and follows navigation', async () => {
    const { harness, fixture, el } = await setup();
    const active = () =>
      Array.from(el.querySelectorAll('a[mat-tab-link]'))
        .filter((a) => a.classList.contains('mdc-tab--active'))
        .map((a) => a.textContent?.trim());
    await harness.navigateByUrl('/profile');
    fixture.detectChanges();
    await fixture.whenStable();
    expect(active()).toEqual(['Profile']);
    await TestBed.inject(Router).navigateByUrl('/security');
    fixture.detectChanges();
    await fixture.whenStable();
    expect(active()).toEqual(['Security']);
    expect(el.querySelector('[data-testid="security-tab"]')?.getAttribute('aria-selected')).toBe(
      'true',
    );
  });

  it('has no axe violations', async () => {
    const { harness, fixture, el } = await setup();
    await harness.navigateByUrl('/profile');
    fixture.detectChanges();
    await fixture.whenStable();
    await expectNoAxeViolations(el);
  });
});
