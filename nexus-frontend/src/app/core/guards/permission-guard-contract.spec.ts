import { Component } from '@angular/core';
import { CanActivateFn, Router, Routes, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { TestBed } from '@angular/core/testing';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { permissionGuard } from './permission.guard';
import { authGuard } from './auth.guard';
import { AuthStore } from '../auth/auth.store';
import { AuthService } from '../../features/auth/auth.service';
import { LoggerService } from '../logging/logger.service';
import { routes } from '../../app.routes';
import {
  createAuthSession,
  createAuthStoreStub,
  AuthStoreStub,
} from '../../shared/testing/auth.fixtures';

@Component({ template: '', standalone: true })
class StubGatedComponent {}

@Component({ template: '', standalone: true })
class StubAccessDeniedComponent {}

/**
 * Checks one guard array (`canActivate` or `canActivateChild`) for `permissionGuard`
 * usage violations: a non-empty string `data.permission`, and `authGuard` composed
 * earlier in the SAME array or present on an ancestor.
 */
function checkGuardArray(
  guards: unknown[],
  arrayLabel: 'canActivate' | 'canActivateChild',
  path: string,
  data: Record<string, unknown> | undefined,
  ancestorHasAuthGuard: boolean,
): string[] {
  if (!guards.includes(permissionGuard)) return [];

  const violations: string[] = [];
  const permission = data?.['permission'];
  if (typeof permission !== 'string' || permission.length === 0) {
    violations.push(
      `${path}: permissionGuard used in ${arrayLabel} without a non-empty data.permission`,
    );
  }

  const authIndex = guards.indexOf(authGuard);
  const permissionIndex = guards.indexOf(permissionGuard);
  const composedInOwnArray = authIndex !== -1 && authIndex < permissionIndex;

  if (!composedInOwnArray && !ancestorHasAuthGuard) {
    violations.push(
      `${path}: authGuard must appear before permissionGuard in ${arrayLabel}, or on an ancestor route`,
    );
  }

  return violations;
}

/**
 * Walks a route table and returns human-readable violations of the `permissionGuard`
 * usage contract, checking BOTH `canActivate` (gates the route itself) and
 * `canActivateChild` (gates every descendant route) — a route's `authGuard` in either
 * array counts toward `ancestorHasAuthGuard` for its descendants (SEC-2,
 * 07-security-review.md: the original version only inspected `canActivate`). Extracted
 * to a standalone function so both the real route table and synthetic test tables can be
 * checked without duplicating the walk logic.
 *
 * KNOWN LIMITATION: `loadChildren`-loaded route tables (e.g. `features/auth/auth.routes.ts`)
 * are not statically visible here — they load asynchronously and this only walks the
 * routes array as imported. Any `permissionGuard` usage inside a lazy-loaded child route
 * table needs its own equivalent contract test local to that feature.
 */
function findPermissionGuardViolations(
  list: Routes,
  pathPrefix = '',
  ancestorHasAuthGuard = false,
): string[] {
  const violations: string[] = [];

  for (const route of list) {
    const path = `${pathPrefix}/${route.path ?? ''}`;
    const activateGuards = (route.canActivate ?? []) as unknown[];
    const activateChildGuards = (route.canActivateChild ?? []) as unknown[];
    const data = route.data as Record<string, unknown> | undefined;
    const ownHasAuthGuard =
      activateGuards.includes(authGuard) || activateChildGuards.includes(authGuard);

    violations.push(
      ...checkGuardArray(activateGuards, 'canActivate', path, data, ancestorHasAuthGuard),
      // A route's own canActivate always resolves before its canActivateChild is ever
      // evaluated (Angular activates a route before activating any of its children), so
      // an authGuard in this route's own canActivate array counts for this route's own
      // canActivateChild check too — not just for descendants.
      ...checkGuardArray(
        activateChildGuards,
        'canActivateChild',
        path,
        data,
        ancestorHasAuthGuard || activateGuards.includes(authGuard),
      ),
    );

    if (route.children) {
      violations.push(
        ...findPermissionGuardViolations(
          route.children,
          path,
          ancestorHasAuthGuard || ownHasAuthGuard,
        ),
      );
    }
  }

  return violations;
}

/**
 * Mechanical contract for `permissionGuard` usage across the real route table.
 *
 * Replaces two documentation-only invariants (permission.guard.ts's own JSDoc and the
 * developer guide) with a check that actually runs: every route that uses
 * `permissionGuard` must declare a valid `data.permission`, and must compose `authGuard`
 * — either earlier in its own `canActivate` array, or on an ancestor route. This is
 * deliberately NOT an ESLint rule — trivially defeated by aliasing/`@let` — it is a plain
 * assertion against the real, imported route table, so it cannot silently drift from
 * what's actually shipped.
 *
 * The "real route table" test is vacuously green today (no route uses permissionGuard
 * yet, per US-013's infrastructure-only scope) and becomes load-bearing the moment a real
 * route adopts it. The synthetic-table tests below exist specifically to prove the check
 * itself is correct — including the ancestor-composition case a synthetic-only test is
 * the only way to exercise before any real route uses that pattern.
 */
describe('permissionGuard route-table contract', () => {
  it('the real route table has zero violations', () => {
    expect(findPermissionGuardViolations(routes)).toEqual([]);
  });

  it('does not flag a route relying on an ancestor authGuard (no authGuard in its own array)', () => {
    const synthetic: Routes = [
      {
        path: 'admin',
        canActivate: [authGuard],
        children: [
          {
            path: 'roles',
            canActivate: [permissionGuard],
            data: { permission: 'roles:read' },
            children: [],
          },
        ],
      },
    ];

    expect(findPermissionGuardViolations(synthetic)).toEqual([]);
  });

  it('flags a route using permissionGuard with no authGuard anywhere in its ancestry', () => {
    const synthetic: Routes = [
      {
        path: 'roles',
        canActivate: [permissionGuard],
        data: { permission: 'roles:read' },
        children: [],
      },
    ];

    const violations = findPermissionGuardViolations(synthetic);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toContain('authGuard must appear before permissionGuard');
  });

  it('flags a route using permissionGuard without a non-empty data.permission', () => {
    const synthetic: Routes = [
      { path: 'roles', canActivate: [authGuard, permissionGuard], children: [] },
    ];

    const violations = findPermissionGuardViolations(synthetic);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toContain('non-empty data.permission');
  });

  // SEC-2 (07-security-review.md): canActivateChild must be checked too, not just
  // canActivate — otherwise this contract silently reverts to a human-memory control
  // for anything gated via canActivateChild.
  it('flags permissionGuard used in canActivateChild with no authGuard anywhere in its ancestry', () => {
    const synthetic: Routes = [
      {
        path: 'admin',
        canActivateChild: [permissionGuard],
        data: { permission: 'roles:read' },
        children: [],
      },
    ];

    const violations = findPermissionGuardViolations(synthetic);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toContain('canActivateChild');
  });

  it("credits a route's own canActivate authGuard to its own canActivateChild check", () => {
    const synthetic: Routes = [
      {
        path: 'admin',
        canActivate: [authGuard],
        canActivateChild: [permissionGuard],
        data: { permission: 'roles:read' },
        children: [],
      },
    ];

    expect(findPermissionGuardViolations(synthetic)).toEqual([]);
  });

  it('credits an ancestor authGuard declared in canActivateChild to its descendants', () => {
    const synthetic: Routes = [
      {
        path: 'admin',
        canActivateChild: [authGuard],
        children: [
          {
            path: 'roles',
            canActivate: [permissionGuard],
            data: { permission: 'roles:read' },
            children: [],
          },
        ],
      },
    ];

    expect(findPermissionGuardViolations(synthetic)).toEqual([]);
  });
});

/**
 * Router-integration coverage for `permissionGuard`, exercised through real Angular Router
 * navigation rather than direct guard invocation (which permission.guard.spec.ts already
 * covers). Uses a synthetic route table with stub components — the real
 * `AccessDeniedComponent` (US-013 T-009) does not exist yet.
 */
describe('permissionGuard router integration', () => {
  let stub: AuthStoreStub;

  function configureTestRoutes(canActivate: CanActivateFn[]): void {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([
          {
            path: 'test-gated',
            canActivate,
            data: { permission: 'roles:read' },
            component: StubGatedComponent,
          },
          { path: 'access-denied', component: StubAccessDeniedComponent },
        ]),
        { provide: AuthStore, useValue: stub },
        { provide: AuthService, useValue: { refresh: vi.fn() } },
        { provide: LoggerService, useValue: { debug: vi.fn() } },
      ],
    });
  }

  beforeEach(() => {
    stub = createAuthStoreStub();
  });

  it('allows navigation to the gated route when the user holds the permission', async () => {
    stub.session.set(createAuthSession());
    stub.permissions.set(['roles:read']);
    configureTestRoutes([authGuard, permissionGuard]);

    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/test-gated');

    expect(TestBed.inject(Router).url).toBe('/test-gated');
  });

  it('redirects to /access-denied when the user lacks the permission', async () => {
    stub.session.set(createAuthSession());
    stub.permissions.set([]);
    configureTestRoutes([authGuard, permissionGuard]);

    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/test-gated');

    expect(TestBed.inject(Router).url).toBe('/access-denied');
  });

  it('cold start: permissionGuard used alone (no authGuard) resolves to /access-denied, not a login page', async () => {
    // No session, no permissions — simulates a page reload before authGuard would have
    // had a chance to restore the session. This is exactly why permissionGuard must never
    // be composed without authGuard ahead of it: on its own, it has no way to distinguish
    // "not yet authenticated" from "authenticated but lacking the permission", and denies
    // in both cases.
    configureTestRoutes([permissionGuard]);

    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/test-gated');

    expect(TestBed.inject(Router).url).toBe('/access-denied');
  });
});
