import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { DashboardComponent } from './dashboard.component';

describe('DashboardComponent', () => {
  function render(): HTMLElement {
    const fixture = TestBed.createComponent(DashboardComponent);
    fixture.detectChanges();
    return fixture.nativeElement;
  }

  it('renders the dashboard root section with its heading', () => {
    const root = render();
    const section = root.querySelector('[data-testid="dashboard-root"]');
    expect(section?.tagName).toBe('SECTION');
    expect(section?.querySelector('h1')?.textContent).toBe('Dashboard');
  });

  it('owns no landmark of its own (the shell provides main)', () => {
    const root = render();
    expect(root.querySelector('main, header, nav')).toBeNull();
  });

  it('no longer renders a logout button (it lives in the shell user menu)', () => {
    expect(render().querySelector('[data-testid="logout-button"]')).toBeNull();
  });
});
