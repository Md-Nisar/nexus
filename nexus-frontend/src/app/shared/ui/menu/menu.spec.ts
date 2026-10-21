import { OverlayContainer } from '@angular/cdk/overlay';
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../testing/axe';
import { MenuItem, NxMenu } from './menu';

const ITEMS: readonly MenuItem[] = [
  { id: 'profile', label: 'Profile', icon: 'person' },
  { id: 'logout', label: 'Log out', danger: true, testId: 'logout-button' },
  { id: 'billing', label: 'Billing', disabled: true, disabledReason: 'Not on your plan' },
];

describe('NxMenu', () => {
  let fixture: ComponentFixture<NxMenu>;
  let overlay: HTMLElement;

  beforeEach(async () => {
    TestBed.configureTestingModule({ imports: [NxMenu], providers: [provideAnimationsAsync()] });
    overlay = TestBed.inject(OverlayContainer).getContainerElement();
    fixture = TestBed.createComponent(NxMenu);
    fixture.componentRef.setInput('items', ITEMS);
    fixture.componentRef.setInput('triggerLabel', 'Account menu');
    await fixture.whenStable();
  });

  afterEach(() => TestBed.inject(OverlayContainer).ngOnDestroy());

  function trigger(): HTMLButtonElement {
    return fixture.nativeElement.querySelector('[data-testid="nx-menu-trigger"]');
  }

  async function open(): Promise<void> {
    trigger().click();
    fixture.detectChanges();
    await fixture.whenStable();
  }

  function menuItem(testId: string): HTMLButtonElement {
    return overlay.querySelector(`[data-testid="${testId}"]`) as HTMLButtonElement;
  }

  it('labels the icon-only trigger with triggerLabel', () => {
    expect(trigger().getAttribute('aria-label')).toBe('Account menu');
  });

  it('uses more_vert by default and honours triggerIcon', async () => {
    expect(trigger().textContent).toContain('more_vert');
    fixture.componentRef.setInput('triggerIcon', 'account_circle');
    await fixture.whenStable();
    expect(trigger().textContent).toContain('account_circle');
  });

  it('reports aria-expanded on the trigger', async () => {
    expect(trigger().getAttribute('aria-expanded')).toBe('false');
    await open();
    expect(trigger().getAttribute('aria-expanded')).toBe('true');
  });

  it('renders no items until opened, then one menuitem per item', async () => {
    expect(overlay.querySelectorAll('[role="menuitem"]').length).toBe(0);
    await open();
    expect(overlay.querySelectorAll('[role="menuitem"]').length).toBe(3);
  });

  it('emits the item id and closes when an item is chosen', async () => {
    const ids: string[] = [];
    fixture.componentInstance.selected.subscribe((id) => ids.push(id));
    await open();
    menuItem('nx-menu-item-profile').click();
    await fixture.whenStable();
    expect(ids).toEqual(['profile']);
    expect(trigger().getAttribute('aria-expanded')).toBe('false');
  });

  it('uses the item testId when given', async () => {
    await open();
    expect(menuItem('logout-button').textContent).toContain('Log out');
  });

  it('marks a danger item with an icon as well as text', async () => {
    await open();
    expect(menuItem('logout-button').querySelector('mat-icon')?.textContent).toContain('warning');
  });

  it('keeps a disabled item with a reason focusable, announced and inert', async () => {
    const ids: string[] = [];
    fixture.componentInstance.selected.subscribe((id) => ids.push(id));
    await open();
    const item = menuItem('nx-menu-item-billing');
    expect(item.getAttribute('aria-disabled')).toBe('true');
    const reasonId = item.getAttribute('aria-describedby') as string;
    expect(overlay.querySelector(`#${reasonId}`)?.textContent).toContain('Not on your plan');
    item.click();
    await fixture.whenStable();
    expect(ids).toEqual([]);
  });

  it('moves focus between items with the arrow keys', async () => {
    await open();
    const panel = overlay.querySelector('[role="menu"]') as HTMLElement;
    const items = Array.from(overlay.querySelectorAll<HTMLElement>('[role="menuitem"]'));
    items[0].focus();
    panel.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'ArrowDown', keyCode: 40, bubbles: true }),
    );
    await fixture.whenStable();
    expect(document.activeElement).toBe(items[1]);
    panel.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'ArrowUp', keyCode: 38, bubbles: true }),
    );
    await fixture.whenStable();
    expect(document.activeElement).toBe(items[0]);
  });

  it('has no axe violations closed or open', async () => {
    await expectNoAxeViolations(fixture.nativeElement);
    await open();
    await expectNoAxeViolations(overlay);
  });
});
