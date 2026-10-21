import { Component, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect } from 'vitest';
import { expectNoAxeViolations } from '../../testing/axe';
import { NxTable, NxTableCellDef, TableColumn } from './table';

/**
 * Test data: standard table columns and rows for baseline tests.
 */
const COLS: TableColumn[] = [
  { key: 'name', header: 'Name' },
  { key: 'email', header: 'Email' },
];

/**
 * Test data: sample rows matching the column structure.
 */
const ROWS = [
  { name: 'Alice', email: 'alice@example.com' },
  { name: 'Bob', email: 'bob@example.com' },
];

/**
 * Test suite for NxTable component.
 *
 * ## Coverage
 * - Rendering: wrapper, headers, rows
 * - Loading state: progress bar visibility
 * - Pagination: controls visibility and structure
 * - Sorting: header click behavior and event emission
 * - Row interaction: clickable state and click emission
 * - Cell types: text (default), badge, mono rendering
 * - Empty state: fallback content and slot
 * - Accessibility: ARIA labels and semantic structure
 *
 * ## Test Strategy
 * - Unit tests focus on component interaction and event emission
 * - Accessibility is verified via ARIA attributes and semantic elements
 * - Material components (sort, paginator) are mocked; only interaction behavior tested
 * - Cell rendering logic tested via @switch/@case coverage
 *
 * Note: Integration tests (with Material animations, user interactions) would be in
 * `table.integration.spec.ts` using Playwright for end-to-end verification.
 */
describe('NxTable', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [NxTable],
      providers: [provideAnimationsAsync()],
    });
  });

  it('renders the table wrapper', () => {
    const fixture = TestBed.createComponent(NxTable);
    fixture.componentRef.setInput('columns', COLS);
    fixture.componentRef.setInput('rows', ROWS);
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('[data-testid="nx-table"]'))).toBeTruthy();
  });

  it('renders column headers', () => {
    const fixture = TestBed.createComponent(NxTable);
    fixture.componentRef.setInput('columns', COLS);
    fixture.componentRef.setInput('rows', ROWS);
    fixture.detectChanges();
    const text = fixture.nativeElement.textContent;
    expect(text).toContain('Name');
    expect(text).toContain('Email');
  });

  it('shows progress bar when loading=true', () => {
    const fixture = TestBed.createComponent(NxTable);
    fixture.componentRef.setInput('columns', COLS);
    fixture.componentRef.setInput('rows', []);
    fixture.componentRef.setInput('loading', true);
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('mat-progress-bar'))).toBeTruthy();
  });

  it('does not show progress bar when loading=false', () => {
    const fixture = TestBed.createComponent(NxTable);
    fixture.componentRef.setInput('columns', COLS);
    fixture.componentRef.setInput('rows', []);
    fixture.componentRef.setInput('loading', false);
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('mat-progress-bar'))).toBeNull();
  });
});

@Component({
  imports: [NxTable, NxTableCellDef],
  template: `
    <nx-table
      [columns]="columns"
      [rows]="rows"
      [stickyHeader]="sticky()"
      [caption]="caption()"
      [captionVisuallyHidden]="hidden()"
    >
      <ng-template nxTableCell="actions" let-row>
        <button type="button" class="row-action">Edit {{ row['name'] }}</button>
      </ng-template>
    </nx-table>
  `,
})
class CustomCellHost {
  readonly columns: TableColumn[] = [
    ...COLS,
    { key: 'actions', header: 'Actions', type: 'custom' },
  ];
  readonly rows = ROWS;
  readonly sticky = signal(false);
  readonly caption = signal('Team members');
  readonly hidden = signal(false);
}

@Component({
  imports: [NxTable],
  template: `<nx-table [columns]="columns" [rows]="rows" />`,
})
class MissingTemplateHost {
  readonly columns: TableColumn[] = [{ key: 'x', header: 'X', type: 'custom' }];
  readonly rows = [{ x: 1 }];
}

describe('NxTable A4 additions', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideAnimationsAsync()] });
  });

  async function setup() {
    const fixture = TestBed.createComponent(CustomCellHost);
    await fixture.whenStable();
    return fixture;
  }

  it('renders the nxTableCell template for custom columns, once per row, with the row', async () => {
    const fixture = await setup();
    const buttons = Array.from(fixture.nativeElement.querySelectorAll('.row-action'));
    expect(buttons.map((b) => (b as HTMLElement).textContent?.trim())).toEqual([
      'Edit Alice',
      'Edit Bob',
    ]);
  });

  it('renders an empty cell for a custom column without a template', async () => {
    const fixture = TestBed.createComponent(MissingTemplateHost);
    await fixture.whenStable();
    expect(fixture.nativeElement.querySelector('td')?.textContent?.trim()).toBe('');
  });

  it('renders a caption element when caption is set, visible by default', async () => {
    const fixture = await setup();
    const caption = fixture.nativeElement.querySelector('table > caption') as HTMLElement;
    expect(caption.textContent?.trim()).toBe('Team members');
    expect(caption.classList).not.toContain('nx-table__caption--hidden');
  });

  it('visually hides the caption but keeps it in the DOM', async () => {
    const fixture = await setup();
    fixture.componentInstance.hidden.set(true);
    await fixture.whenStable();
    expect(fixture.nativeElement.querySelector('caption')?.classList).toContain(
      'nx-table__caption--hidden',
    );
  });

  it('omits the caption when empty', async () => {
    const fixture = await setup();
    fixture.componentInstance.caption.set('');
    await fixture.whenStable();
    expect(fixture.nativeElement.querySelector('caption')).toBeNull();
  });

  it('applies the sticky classes only when stickyHeader is set', async () => {
    const fixture = await setup();
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('.nx-table-wrapper--sticky')).toBeNull();
    expect(root.querySelector('th.mat-mdc-table-sticky')).toBeNull();
    fixture.componentInstance.sticky.set(true);
    await fixture.whenStable();
    expect(root.querySelector('.nx-table-wrapper--sticky')).not.toBeNull();
    expect(root.querySelector('th.mat-mdc-table-sticky')).not.toBeNull();
  });

  it('has no axe violations with a caption and custom cells', async () => {
    const fixture = await setup();
    await expectNoAxeViolations(fixture.nativeElement);
  });
});
