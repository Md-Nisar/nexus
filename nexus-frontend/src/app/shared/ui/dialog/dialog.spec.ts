import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { MAT_DIALOG_DATA, MatDialog, MatDialogRef } from '@angular/material/dialog';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NxDialog, NxDialogShell, type DialogData } from './dialog';

describe('NxDialogShell', () => {
  function createShell(data: DialogData) {
    TestBed.configureTestingModule({
      imports: [NxDialogShell],
      providers: [
        provideAnimationsAsync(),
        { provide: MAT_DIALOG_DATA, useValue: data },
        { provide: MatDialogRef, useValue: { close: vi.fn() } },
      ],
    });
    const fixture = TestBed.createComponent(NxDialogShell);
    fixture.detectChanges();
    return fixture;
  }

  it('renders the injected title and message (regression: MAT_DIALOG_DATA wiring)', () => {
    const fixture = createShell({ title: 'Archive project', message: 'This will archive it.' });
    const host: HTMLElement = fixture.debugElement.query(
      By.css('[data-testid="nx-dialog"]'),
    ).nativeElement;

    expect(host.textContent).toContain('Archive project');
    expect(host.textContent).toContain('This will archive it.');
  });

  it('exposes the injected data on the component', () => {
    const data: DialogData = { title: 'Delete issue', variant: 'danger' };
    const fixture = createShell(data);
    expect(fixture.componentInstance.data).toBe(data);
    expect(fixture.componentInstance.data.title).toBe('Delete issue');
  });

  it('applies the danger modifier when variant is danger', () => {
    const fixture = createShell({ title: 'Delete', variant: 'danger' });
    const host: HTMLElement = fixture.debugElement.query(
      By.css('[data-testid="nx-dialog"]'),
    ).nativeElement;
    expect(host.classList).toContain('nx-dialog--danger');
  });

  it('falls back to default action labels when none provided', () => {
    const fixture = createShell({ title: 'Confirm' });
    const text = (
      fixture.debugElement.query(By.css('[data-testid="nx-dialog"]')).nativeElement as HTMLElement
    ).textContent;
    expect(text).toContain('Cancel');
    expect(text).toContain('Confirm');
  });

  it('uses custom action labels when provided', () => {
    const fixture = createShell({
      title: 'Confirm',
      confirmLabel: 'Archive',
      cancelLabel: 'Keep',
    });
    const text = (
      fixture.debugElement.query(By.css('[data-testid="nx-dialog"]')).nativeElement as HTMLElement
    ).textContent;
    expect(text).toContain('Keep');
    expect(text).toContain('Archive');
  });
});

describe('NxDialog service', () => {
  let matDialogSpy: { open: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    matDialogSpy = { open: vi.fn().mockReturnValue({ afterClosed: () => ({}) }) };
    TestBed.configureTestingModule({
      providers: [NxDialog, { provide: MatDialog, useValue: matDialogSpy }],
    });
  });

  it('opens the shell with the supplied DialogData', () => {
    const service = TestBed.inject(NxDialog);
    const data: DialogData = { title: 'Hello' };
    service.open(data);

    expect(matDialogSpy.open).toHaveBeenCalledWith(
      NxDialogShell,
      expect.objectContaining({ data, panelClass: 'nx-dialog-panel', restoreFocus: true }),
    );
  });

  it('opens a template via openTemplate with merged config', () => {
    const service = TestBed.inject(NxDialog);
    const tpl = {} as never;
    service.openTemplate(tpl, { width: '720px' });

    expect(matDialogSpy.open).toHaveBeenCalledWith(
      tpl,
      expect.objectContaining({ width: '720px', panelClass: 'nx-dialog-panel' }),
    );
  });
});
