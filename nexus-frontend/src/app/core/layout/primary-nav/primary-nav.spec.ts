import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { Component } from '@angular/core';
import { describe, expect, it } from 'vitest';
import { NavItem } from '../nav.config';
import { PrimaryNav } from './primary-nav';

@Component({ template: '' })
class Blank {}

const ITEMS: readonly NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', path: '/dashboard', icon: 'dashboard', anyOf: null },
  { id: 'other', label: 'Other', path: '/other', icon: 'folder', anyOf: null },
];

describe('PrimaryNav', () => {
  async function setup(items: readonly NavItem[] = ITEMS) {
    TestBed.configureTestingModule({
      imports: [PrimaryNav],
      providers: [
        provideRouter([
          { path: 'dashboard', component: Blank },
          { path: 'other', component: Blank },
        ]),
      ],
    });
    const fixture = TestBed.createComponent(PrimaryNav);
    fixture.componentRef.setInput('items', items);
    await fixture.whenStable();
    return fixture;
  }

  it('renders one labelled primary nav landmark with a link per item', async () => {
    const fixture = await setup();
    const nav = fixture.nativeElement.querySelector('nav') as HTMLElement;
    expect(nav.id).toBe('primary-nav');
    expect(nav.getAttribute('aria-label')).toBe('Primary');
    const links = Array.from(nav.querySelectorAll('a'));
    expect(links.map((a) => a.textContent?.trim())).toEqual([
      'dashboard Dashboard',
      'folder Other',
    ]);
    expect(links[0].getAttribute('href')).toBe('/dashboard');
  });

  it('renders no links for an empty list', async () => {
    const fixture = await setup([]);
    expect(fixture.nativeElement.querySelectorAll('a').length).toBe(0);
  });

  it('marks only the active link with aria-current="page"', async () => {
    const fixture = await setup();
    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/other');
    fixture.detectChanges();
    const current = fixture.nativeElement.querySelectorAll('a[aria-current="page"]');
    expect(current.length).toBe(1);
    expect(current[0].getAttribute('data-testid')).toBe('nav-other');
  });
});
