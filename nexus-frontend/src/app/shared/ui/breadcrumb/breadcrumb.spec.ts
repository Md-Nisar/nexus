import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../testing/axe';
import { BreadcrumbItem, NxBreadcrumb } from './breadcrumb';

const ITEMS: readonly BreadcrumbItem[] = [
  { label: 'Home', path: '/dashboard' },
  { label: 'Users', path: '/users' },
  { label: 'Alice' },
];

describe('NxBreadcrumb', () => {
  let fixture: ComponentFixture<NxBreadcrumb>;
  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(async () => {
    TestBed.configureTestingModule({ providers: [provideRouter([])] });
    fixture = TestBed.createComponent(NxBreadcrumb);
    fixture.componentRef.setInput('items', ITEMS);
    await fixture.whenStable();
  });

  it('is a nav landmark named Breadcrumb containing an ordered list', () => {
    const nav = el().querySelector('nav');
    expect(nav?.getAttribute('aria-label')).toBe('Breadcrumb');
    expect(nav?.querySelectorAll('ol > li').length).toBe(3);
  });

  it('links the items that have a path', () => {
    const links = Array.from(el().querySelectorAll('a'));
    expect(links.map((a) => a.textContent?.trim())).toEqual(['Home', 'Users']);
    expect(links[0].getAttribute('href')).toBe('/dashboard');
  });

  it('renders the last item as text with aria-current="page", even when it has a path', async () => {
    const last = el().querySelector('[aria-current="page"]');
    expect(last?.textContent?.trim()).toBe('Alice');
    expect(last?.tagName).not.toBe('A');
    fixture.componentRef.setInput('items', [
      { label: 'Home', path: '/' },
      { label: 'End', path: '/e' },
    ]);
    await fixture.whenStable();
    expect(el().querySelectorAll('a').length).toBe(1);
    expect(el().querySelector('[aria-current="page"]')?.textContent?.trim()).toBe('End');
  });

  it('isolates every label in <bdi> and renders it as text, so a user-authored label cannot reorder the trail', async () => {
    const label = '<img src=x onerror=alert(1)>\u202Eevil';
    fixture.componentRef.setInput('items', [{ label: 'Home', path: '/' }, { label }]);
    await fixture.whenStable();

    const bdis = Array.from(el().querySelectorAll('li bdi'));
    expect(bdis.map((node) => node.textContent)).toEqual(['Home', label]);
    expect(el().querySelector('[aria-current="page"] bdi')?.textContent).toBe(label);
    expect(el().querySelector('img')).toBeNull();
  });

  it('renders nothing for an empty list', async () => {
    fixture.componentRef.setInput('items', []);
    await fixture.whenStable();
    expect(el().querySelector('nav')).toBeNull();
  });

  it('has no axe violations', async () => {
    await expect(expectNoAxeViolations(el())).resolves.toBeUndefined();
  });
});
