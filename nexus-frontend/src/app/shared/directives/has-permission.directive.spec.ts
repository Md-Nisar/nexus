import { Component, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { HasPermissionDirective } from './has-permission.directive';
import { AuthStore } from '../../core/auth/auth.store';
import { createAuthStoreStub, AuthStoreStub } from '../testing/auth.fixtures';

@Component({
  standalone: true,
  imports: [HasPermissionDirective],
  template: `<span *appHasPermission="perm()" data-testid="guarded">Manage users</span>`,
})
class HostComponent {
  readonly perm = signal('users:read');
}

@Component({
  standalone: true,
  imports: [HasPermissionDirective],
  template: `<span *appHasPermission="''" data-testid="guarded-empty">Empty permission</span>`,
})
class EmptyPermissionHostComponent {}

@Component({
  standalone: true,
  imports: [HasPermissionDirective],
  template: `
    <span *appHasPermission="'users:read'" data-testid="guarded-read">Manage users</span>
    <span *appHasPermission="'users:write'" data-testid="guarded-write">Edit users</span>
  `,
})
class MultiHostComponent {}

/**
 * HasPermissionDirective — the first structural directive in this codebase.
 *
 * Establishes the host-component harness pattern for future structural-directive specs:
 * a real WritableSignal in the AuthStore stub, so reactivity (not just a one-shot render)
 * is actually exercised.
 */
describe('HasPermissionDirective', () => {
  let stub: AuthStoreStub;

  beforeEach(() => {
    stub = createAuthStoreStub();
    TestBed.configureTestingModule({
      providers: [{ provide: AuthStore, useValue: stub }],
    });
  });

  function guardedElement() {
    const fixture = TestBed.createComponent(HostComponent);
    fixture.detectChanges();
    return { fixture, query: () => fixture.debugElement.query(By.css('[data-testid="guarded"]')) };
  }

  it('renders the host template when the user holds the required permission', () => {
    stub.permissions.set(['users:read']);
    const { query } = guardedElement();
    expect(query()).not.toBeNull();
  });

  it('does not render the host template when the user lacks the required permission', () => {
    stub.permissions.set(['users:write']);
    const { query } = guardedElement();
    expect(query()).toBeNull();
  });

  it('does not render, and logs no console error, when permissions() is empty', () => {
    const consoleErrorSpy = vi.spyOn(console, 'error');
    stub.permissions.set([]);

    const { query } = guardedElement();

    expect(query()).toBeNull();
    expect(consoleErrorSpy).not.toHaveBeenCalled();
  });

  it("reacts to the directive's own input changing, not just to AuthStore.permissions changing", () => {
    // Every other reactivity test in this file mutates stub.permissions (the AuthStore
    // signal). This proves the effect() also re-evaluates when appHasPermission itself
    // changes, via the HostComponent's own perm() signal, which is the other half of the
    // directive's reactive dependency graph.
    stub.permissions.set(['users:write']);
    const { fixture, query } = guardedElement();
    const host = fixture.componentInstance;
    expect(query()).toBeNull();

    host.perm.set('users:write');
    fixture.detectChanges();

    expect(query()).not.toBeNull();
  });

  it('renders reactively when the permission is granted after initial render', () => {
    stub.permissions.set([]);
    const { fixture, query } = guardedElement();
    expect(query()).toBeNull();

    stub.permissions.set(['users:read']);
    fixture.detectChanges();

    expect(query()).not.toBeNull();
  });

  it('removes the view reactively when the permission is revoked after initial render', () => {
    stub.permissions.set(['users:read']);
    const { fixture, query } = guardedElement();
    expect(query()).not.toBeNull();

    stub.permissions.set([]);
    fixture.detectChanges();

    expect(query()).toBeNull();
  });

  it('does not recreate the embedded view when permissions changes to a new array with identical contents', () => {
    stub.permissions.set(['users:read']);
    const { fixture, query } = guardedElement();
    const firstElement = query()?.nativeElement;
    expect(firstElement).toBeDefined();

    // A fresh array instance, same contents — the computed()'s value-equality short-circuit
    // must prevent the effect from re-running, so the view is never torn down and recreated.
    stub.permissions.set(['users:read']);
    fixture.detectChanges();

    const secondElement = query()?.nativeElement;
    expect(secondElement).toBe(firstElement);
  });

  it('never renders when appHasPermission is bound to an empty string, regardless of the permissions held', () => {
    // An empty required-permission string is a template authoring mistake, not a
    // "grant to everyone" wildcard: `permissions().includes('')` is only true if the
    // server literally issued a permission whose name is the empty string, which never
    // happens by the `resource:action` convention. Proven against both an empty and a
    // non-empty permissions list so this isn't just coincidentally false because the
    // stub defaults to [].
    stub.permissions.set(['users:read', 'users:write']);
    const fixture = TestBed.createComponent(EmptyPermissionHostComponent);
    fixture.detectChanges();

    expect(fixture.debugElement.query(By.css('[data-testid="guarded-empty"]'))).toBeNull();
  });

  it('updates multiple directive instances independently when permissions changes once', () => {
    // Two *appHasPermission instances on the same view, bound to different permission
    // strings, both reacting to the same AuthStore.permissions signal — each must reflect
    // only its own required permission, not the other's.
    stub.permissions.set([]);
    const fixture = TestBed.createComponent(MultiHostComponent);
    fixture.detectChanges();

    const readEl = () => fixture.debugElement.query(By.css('[data-testid="guarded-read"]'));
    const writeEl = () => fixture.debugElement.query(By.css('[data-testid="guarded-write"]'));

    expect(readEl()).toBeNull();
    expect(writeEl()).toBeNull();

    stub.permissions.set(['users:read']);
    fixture.detectChanges();

    expect(readEl()).not.toBeNull();
    expect(writeEl()).toBeNull();

    stub.permissions.set(['users:read', 'users:write']);
    fixture.detectChanges();

    expect(readEl()).not.toBeNull();
    expect(writeEl()).not.toBeNull();
  });

  it('coalesces two permissions writes made before a single detectChanges() flush into one settle-consistent render', () => {
    // Simulates two signal writes landing in the same JS task (e.g. a store update that
    // sets permissions twice back-to-back) before Angular ever gets a chance to run the
    // directive's effect. Angular's effect scheduler is pull-based: the effect reads
    // `granted()` once per flush, so it only ever observes the settled value after both
    // writes, never the intermediate one. Proven the same way as the "identical contents"
    // no-churn test above — via nativeElement reference identity — rather than a
    // ViewContainerRef spy: `ViewContainerRef` is an abstract class with no prototype
    // methods to spy on; its real implementation lives on Angular's internal
    // `R3ViewContainerRef`, which is not part of the public API. If the effect had
    // instead run twice (once for the revoke, once for the re-grant), the view would
    // have been torn down and recreated, and this element reference would change.
    stub.permissions.set(['users:read']);
    const { fixture, query } = guardedElement();
    const firstElement = query()?.nativeElement;
    expect(firstElement).toBeDefined();

    // Two rapid, same-tick writes: revoke then immediately re-grant, with no
    // detectChanges() in between.
    stub.permissions.set([]);
    stub.permissions.set(['users:read']);
    fixture.detectChanges();

    const secondElement = query()?.nativeElement;
    expect(secondElement).toBe(firstElement);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });
});
