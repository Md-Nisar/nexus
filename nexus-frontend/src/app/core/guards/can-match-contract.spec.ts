import { Injector, inject, runInInjectionContext } from '@angular/core';
import { CanMatchFn, PartialMatchRouteSnapshot, Route, Routes, UrlSegment } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { routes } from '../../app.routes';
import { AuthStore } from '../auth/auth.store';
import { APP_CONFIG, AppConfig } from '../config/app-config';
import { accessConsoleEnabledGuard } from './access-console-enabled.guard';
import { authGuard } from './auth.guard';

/**
 * `canMatch` guards that read configuration only. `canMatch` runs in the recognition phase,
 * BEFORE the shell's `authGuard` restores the session, so a guard here that read auth state would
 * see an empty session on a cold start (T-E57). Adding a guard to this list needs the same proof
 * as the guards below: it runs in an injector that provides nothing but `APP_CONFIG`.
 */
const CONFIG_ONLY_CAN_MATCH: readonly CanMatchFn[] = [accessConsoleEnabledGuard];

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: '/api',
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

/** Resolves a route's children, awaiting lazy `loadChildren` when it yields a route array. */
async function childrenOf(route: Route): Promise<Routes> {
  if (route.children) return route.children;
  if (typeof route.loadChildren !== 'function') return [];
  const loaded: unknown = await route.loadChildren();
  if (Array.isArray(loaded)) return loaded as Routes;
  const maybeDefault = (loaded as { default?: unknown } | null)?.default;
  return Array.isArray(maybeDefault) ? (maybeDefault as Routes) : [];
}

/** Every route in the WHOLE tree (C-4), lazy children included, keyed by absolute path. */
async function walk(table: Routes, prefix = ''): Promise<[string, Route][]> {
  const found: [string, Route][] = [];
  for (const route of table) {
    const path = `${prefix}/${route.path ?? ''}`.replace(/\/+/g, '/');
    found.push([path, route]);
    found.push(...(await walk(await childrenOf(route), path)));
  }
  return found;
}

/** Paths whose `canMatch` holds a guard outside {@link CONFIG_ONLY_CAN_MATCH}. */
async function unlistedCanMatch(table: Routes): Promise<string[]> {
  return (await walk(table))
    .filter(([, route]) =>
      ((route.canMatch ?? []) as readonly unknown[]).some(
        (g) => !(CONFIG_ONLY_CAN_MATCH as readonly unknown[]).includes(g),
      ),
    )
    .map(([path]) => path);
}

function runInConfigOnlyInjector(guard: CanMatchFn): unknown {
  const injector = Injector.create({ providers: [{ provide: APP_CONFIG, useValue: CONFIG }] });
  return runInInjectionContext(injector, () =>
    guard({ path: 'x' } as Route, [] as UrlSegment[], {} as PartialMatchRouteSnapshot),
  );
}

describe('canMatch contract (RC-76)', () => {
  it('puts only config-only guards in canMatch anywhere in the real route tree', async () => {
    expect(await unlistedCanMatch(routes)).toEqual([]);
  });

  it('is not vacuous: /admin/access carries exactly [accessConsoleEnabledGuard]', async () => {
    const consoleRoute = (await walk(routes)).find(([path]) => path === '/admin/access')?.[1];
    expect(consoleRoute?.canMatch).toEqual([accessConsoleEnabledGuard]);
  });

  it('reports an unlisted canMatch under a shell-like parent', async () => {
    const authed: CanMatchFn = () => inject(AuthStore).isAuthenticated();
    const fixture: Routes = [
      {
        path: '',
        canActivate: [authGuard],
        children: [
          { path: 'ok', canMatch: [accessConsoleEnabledGuard], children: [] },
          { path: 'bad', canMatch: [authed], children: [] },
        ],
      },
    ];
    expect(await unlistedCanMatch(fixture)).toEqual(['/bad']);
  });

  it('reports an unlisted canMatch inside lazy loadChildren', async () => {
    const authed: CanMatchFn = () => inject(AuthStore).isAuthenticated();
    const lazy: Routes = [{ path: 'deep', canMatch: [authed], children: [] }];
    const fixture: Routes = [
      { path: 'outer', canActivate: [authGuard], loadChildren: () => Promise.resolve(lazy) },
    ];
    expect(await unlistedCanMatch(fixture)).toEqual(['/outer/deep']);
  });

  it.each(CONFIG_ONLY_CAN_MATCH.map((g, i) => [i, g] as const))(
    'runs allow-listed guard #%i in an injector providing only APP_CONFIG',
    (_i, guard) => {
      expect(() => runInConfigOnlyInjector(guard)).not.toThrow();
    },
  );

  it('negative control: a guard injecting AuthStore throws in that injector', () => {
    const authed: CanMatchFn = () => inject(AuthStore).isAuthenticated();
    expect(() => runInConfigOnlyInjector(authed)).toThrow();
  });
});
