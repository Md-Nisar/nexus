import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect } from 'vitest';
import { NxTable, TableColumn } from './table';

const COLS: TableColumn[] = [
  { key: 'name', header: 'Name' },
  { key: 'email', header: 'Email' },
];

const ROWS = [
  { name: 'Alice', email: 'alice@example.com' },
  { name: 'Bob', email: 'bob@example.com' },
];

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
