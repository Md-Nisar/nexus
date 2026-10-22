import { OverlayContainer } from '@angular/cdk/overlay';
import { ApplicationRef } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { MAT_DIALOG_DATA, MatDialog, MatDialogRef } from '@angular/material/dialog';
import { afterEach, describe, it, expect, vi, beforeEach } from 'vitest';
import { expectNoAxeViolations } from '../../testing/axe';
import {
  NxDialog,
  NxDialogShell,
  type DialogData,
  NxTypedConfirmShell,
  type TypedConfirmData,
} from './dialog';

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

describe('NxDialog.confirmTyped configuration', () => {
  it('asks Material to focus the input first, never the destructive button', () => {
    const open = vi.fn().mockReturnValue({});
    TestBed.configureTestingModule({ providers: [{ provide: MatDialog, useValue: { open } }] });
    const data: TypedConfirmData = {
      title: 'Delete',
      message: 'Sure?',
      expectedText: 'DELETE',
      confirmLabel: 'Delete',
    };
    TestBed.inject(NxDialog).confirmTyped(data);
    expect(open).toHaveBeenCalledWith(
      NxTypedConfirmShell,
      expect.objectContaining({
        data,
        autoFocus: '[data-testid="nx-input"]',
        restoreFocus: true,
        panelClass: 'nx-dialog-panel',
      }),
    );
  });
});

describe('NxDialog.confirmTyped', () => {
  const DATA: TypedConfirmData = {
    title: 'Delete role',
    message: 'This cannot be undone.',
    expectedText: 'DELETE',
    confirmLabel: 'Delete role',
  };
  let overlay: HTMLElement;
  let ref: MatDialogRef<unknown, boolean>;
  let closed: (boolean | undefined)[];

  beforeEach(async () => {
    TestBed.configureTestingModule({ providers: [provideAnimationsAsync()] });
    overlay = TestBed.inject(OverlayContainer).getContainerElement();
    closed = [];
    ref = TestBed.inject(NxDialog).confirmTyped(DATA);
    ref.afterClosed().subscribe((result) => closed.push(result));
    await settle();
  });

  afterEach(() => {
    ref.close();
    TestBed.inject(OverlayContainer).ngOnDestroy();
  });

  async function settle(): Promise<void> {
    for (let i = 0; i < 5; i++) {
      await new Promise((resolve) => setTimeout(resolve, 20));
      TestBed.inject(ApplicationRef).tick();
    }
  }

  const q = <E extends HTMLElement>(testId: string) =>
    overlay.querySelector<E>(`[data-testid="${testId}"]`);

  async function type(value: string): Promise<void> {
    const input = q<HTMLInputElement>('nx-input') as HTMLInputElement;
    input.value = value;
    input.dispatchEvent(new Event('input'));
    await settle();
  }

  it('renders the danger variant with title and message', () => {
    expect(q('nx-dialog')?.classList).toContain('nx-dialog--danger');
    expect(overlay.textContent).toContain('Delete role');
    expect(overlay.textContent).toContain('This cannot be undone.');
  });

  it('labels the input "Type {expectedText} to confirm"', () => {
    expect(overlay.querySelector('mat-label')?.textContent).toContain('Type DELETE to confirm');
  });

  it('keeps confirm aria-disabled (but focusable) until the text matches exactly', async () => {
    const confirm = q<HTMLButtonElement>('nx-typed-confirm-confirm') as HTMLButtonElement;
    expect(confirm.getAttribute('aria-disabled')).toBe('true');
    expect(confirm.disabled).toBe(false);
    await type('DELET');
    expect(confirm.getAttribute('aria-disabled')).toBe('true');
    await type('delete');
    expect(confirm.getAttribute('aria-disabled')).toBe('true');
    await type('DELETE');
    expect(confirm.getAttribute('aria-disabled')).toBe('false');
  });

  it('trims surrounding whitespace before comparing', async () => {
    await type('  DELETE \n');
    expect(q('nx-typed-confirm-confirm')?.getAttribute('aria-disabled')).toBe('false');
  });

  it('does not close when confirm is activated without a match', async () => {
    q<HTMLButtonElement>('nx-typed-confirm-confirm')?.click();
    await settle();
    expect(closed).toEqual([]);
  });

  it('closes with true when confirmed after a match', async () => {
    await type('DELETE');
    q<HTMLButtonElement>('nx-typed-confirm-confirm')?.click();
    await settle();
    expect(closed).toEqual([true]);
  });

  it('closes without confirming on cancel', async () => {
    q<HTMLButtonElement>('nx-typed-confirm-cancel')?.click();
    await settle();
    expect(closed).toEqual([false]);
  });

  it('has no axe violations', async () => {
    await expect(expectNoAxeViolations(overlay)).resolves.toBeUndefined();
  });
});
