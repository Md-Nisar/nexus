import { Component, EnvironmentInjector, runInInjectionContext, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { Observable, Subject, firstValueFrom, isObservable } from 'rxjs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthStore } from '../../../core/auth/auth.store';
import {
  createAuthSession,
  createAuthStoreStub,
  createAuthUser,
} from '../../../shared/testing/auth.fixtures';
import { NxDialog, NxToast } from '../../../shared/ui';
import {
  HasUnsavedChanges,
  beforeUnloadWhileDirty,
  unsavedChangesGuard,
} from './unsaved-changes.guard';

function dialogStub() {
  const closed = new Subject<boolean | undefined>();
  const open = vi.fn(() => ({ afterClosed: () => closed.asObservable() }));
  return { closed, open, dialog: { open } };
}

function run(
  component: HasUnsavedChanges,
  dialog: { open: unknown },
  options: { signedIn?: boolean; toast?: { info: unknown } } = {},
) {
  TestBed.configureTestingModule({
    providers: [
      { provide: NxDialog, useValue: dialog },
      { provide: NxToast, useValue: options.toast ?? { info: vi.fn() } },
      {
        provide: AuthStore,
        useValue: createAuthStoreStub({
          session:
            options.signedIn === false
              ? null
              : createAuthSession({ user: createAuthUser({ userId: 'user-1' }) }),
        }),
      },
    ],
  });
  return runInInjectionContext(TestBed.inject(EnvironmentInjector), () =>
    unsavedChangesGuard(
      component,
      {} as ActivatedRouteSnapshot,
      {} as RouterStateSnapshot,
      {} as RouterStateSnapshot,
    ),
  );
}

describe('unsavedChangesGuard (US-020 design §4.8)', () => {
  it('allows leaving with no unsaved changes, without a dialog', () => {
    const stub = dialogStub();
    expect(run({ hasUnsavedChanges: () => false }, stub.dialog)).toBe(true);
    expect(stub.open).not.toHaveBeenCalled();
  });

  it('asks with the leave copy when there are unsaved changes', () => {
    const stub = dialogStub();
    run({ hasUnsavedChanges: () => true }, stub.dialog);
    expect(stub.open).toHaveBeenCalledWith({
      title: 'Leave without saving?',
      message: 'Your changes stay as a draft in this tab.',
      confirmLabel: 'Leave',
      cancelLabel: 'Stay',
      variant: 'default',
    });
  });

  it("uses the page's own leave message when it has one (a create has no draft to keep)", () => {
    const stub = dialogStub();
    run({ hasUnsavedChanges: () => true, leaveMessage: () => 'Nothing is kept.' }, stub.dialog);
    expect(stub.open).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'Nothing is kept.' }),
    );
  });

  it('leaves without a prompt once the session has ended: logout already deleted the draft (MJ-2)', () => {
    const stub = dialogStub();
    const result = run({ hasUnsavedChanges: () => true }, stub.dialog, { signedIn: false });
    expect(result).toBe(true);
    expect(stub.open).not.toHaveBeenCalled();
  });

  it('refuses to leave while a request that cannot be abandoned runs, with a notice (MJ-4)', () => {
    const stub = dialogStub();
    const toast = { info: vi.fn() };
    const result = run(
      {
        hasUnsavedChanges: () => true,
        leaveBlockedMessage: () => 'Still creating the role.',
      },
      stub.dialog,
      { toast },
    );
    expect(result).toBe(false);
    expect(stub.open).not.toHaveBeenCalled();
    expect(toast.info).toHaveBeenCalledWith('Still creating the role.');
  });

  it('asks as usual when the page reports nothing blocking', () => {
    const stub = dialogStub();
    run({ hasUnsavedChanges: () => true, leaveBlockedMessage: () => null }, stub.dialog);
    expect(stub.open).toHaveBeenCalledOnce();
  });

  it.each([
    ['Leave', true, true],
    ['Stay', false, false],
    ['a dismissal', undefined, false],
  ] as const)('resolves to the choice: %s', async (_choice, closedWith, expected) => {
    const stub = dialogStub();
    const result = run({ hasUnsavedChanges: () => true }, stub.dialog);
    expect(isObservable(result)).toBe(true);
    const decision = firstValueFrom(result as Observable<boolean>);
    stub.closed.next(closedWith);
    stub.closed.complete();
    await expect(decision).resolves.toBe(expected);
  });
});

@Component({ template: '' })
class DirtyHost {
  readonly dirty = signal(false);
  constructor() {
    beforeUnloadWhileDirty(() => this.dirty());
  }
}

describe('beforeUnloadWhileDirty (US-020 design §4.8)', () => {
  const unload = (): Event => {
    const event = new Event('beforeunload', { cancelable: true });
    window.dispatchEvent(event);
    return event;
  };

  afterEach(() => TestBed.resetTestingModule());

  it('registers a beforeunload listener only while dirty', async () => {
    const add = vi.spyOn(window, 'addEventListener');
    const fixture = TestBed.createComponent(DirtyHost);
    await fixture.whenStable();
    expect(add.mock.calls.filter(([type]) => type === 'beforeunload')).toHaveLength(0);
    expect(unload().defaultPrevented).toBe(false);

    fixture.componentInstance.dirty.set(true);
    await fixture.whenStable();
    expect(add.mock.calls.filter(([type]) => type === 'beforeunload')).toHaveLength(1);
    expect(unload().defaultPrevented).toBe(true);

    fixture.componentInstance.dirty.set(false);
    await fixture.whenStable();
    expect(unload().defaultPrevented).toBe(false);
    add.mockRestore();
  });

  it('removes the listener when the host is destroyed while dirty', async () => {
    const fixture = TestBed.createComponent(DirtyHost);
    fixture.componentInstance.dirty.set(true);
    await fixture.whenStable();
    expect(unload().defaultPrevented).toBe(true);
    fixture.destroy();
    expect(unload().defaultPrevented).toBe(false);
  });
});
