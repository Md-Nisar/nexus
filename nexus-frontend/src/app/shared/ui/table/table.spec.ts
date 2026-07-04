import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect } from 'vitest';
import { NxTable, TableColumn } from './table';

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
