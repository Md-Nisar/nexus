import { TestBed } from '@angular/core/testing';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { ShellHeader } from './shell-header';

describe('ShellHeader', () => {
  async function setup(navOpen = false) {
    TestBed.configureTestingModule({
      imports: [ShellHeader],
      providers: [provideRouter([]), provideAnimationsAsync()],
    });
    const fixture = TestBed.createComponent(ShellHeader);
    fixture.componentRef.setInput('productName', 'Nexus');
    fixture.componentRef.setInput('userLabel', 'ADMIN');
    fixture.componentRef.setInput('navOpen', navOpen);
    await fixture.whenStable();
    const root = fixture.nativeElement as HTMLElement;
    return { fixture, root };
  }

  it('renders one header with the wordmark and the user label', async () => {
    const { root } = await setup();
    expect(root.querySelectorAll('header').length).toBe(1);
    expect(root.querySelector('a')?.getAttribute('aria-label')).toBe('Nexus home');
    expect(root.textContent).toContain('ADMIN');
  });

  it('reflects navOpen in the menu button aria-expanded and controls the primary nav', async () => {
    const closed = await setup(false);
    const button = closed.root.querySelector('[data-testid="nav-toggle"]') as HTMLElement;
    expect(button.getAttribute('aria-expanded')).toBe('false');
    expect(button.getAttribute('aria-controls')).toBe('primary-nav');
    expect(button.getAttribute('aria-label')).toBe('Main menu');
  });

  it('shows aria-expanded true when the nav is open', async () => {
    const { root } = await setup(true);
    const button = root.querySelector('[data-testid="nav-toggle"]') as HTMLElement;
    expect(button.getAttribute('aria-expanded')).toBe('true');
  });

  it('emits toggleNav when the menu button is clicked', async () => {
    const { fixture, root } = await setup();
    let count = 0;
    fixture.componentInstance.toggleNav.subscribe(() => count++);
    (root.querySelector('[data-testid="nav-toggle"]') as HTMLElement).click();
    expect(count).toBe(1);
  });

  it('emits logout from the user menu item', async () => {
    const { fixture, root } = await setup();
    let count = 0;
    fixture.componentInstance.logout.subscribe(() => count++);
    (root.querySelector('[data-testid="nx-menu-trigger"]') as HTMLElement).click();
    fixture.detectChanges();
    await fixture.whenStable();
    (document.body.querySelector('[data-testid="logout-button"]') as HTMLElement).click();
    expect(count).toBe(1);
  });
});
