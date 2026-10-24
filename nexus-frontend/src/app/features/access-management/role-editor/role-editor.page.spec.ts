import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Component, ErrorHandler, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { Router, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthStore } from '../../../core/auth/auth.store';
import { APP_CONFIG, AppConfig } from '../../../core/config/app-config';
import { permissionGuard } from '../../../core/guards/permission.guard';
import { apiErrorInterceptor } from '../../../core/http/api-error.interceptor';
import { ServiceAvailabilityNotifier } from '../../../core/http/service-availability-notifier';
import { LoggerService } from '../../../core/logging/logger.service';
import {
  createAuthSession,
  createAuthStoreStub,
  createAuthUser,
} from '../../../shared/testing/auth.fixtures';
import { expectNoAxeViolations } from '../../../shared/testing/axe';
import type {
  PermissionPageResponse,
  PermissionResponse,
  RoleResponse,
} from '../../../shared/types/api/rbac';
import { CONSOLE_COPY } from '../copy/console-copy';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { CatalogueStore } from '../data/catalogue.store';
import { RoleDetailPage } from '../role-detail/role-detail.page';
import { RoleDetailStore } from '../role-detail/role-detail.store';
import { RolePermissionsTab } from '../role-detail/role-permissions.tab';
import { RoleEditorPage } from './role-editor.page';
import { unsavedChangesGuard } from './unsaved-changes.guard';

const API = 'http://localhost:1000/api';
const ROLE_ID = '0190a000-0000-7000-8000-0000000000c1';
const CATALOGUE_URL = `${API}/v1/permissions?page=0&size=100`;
const ROLE_URL = `${API}/v1/roles/${ROLE_ID}`;
const SET_URL = `${API}/v1/roles/${ROLE_ID}/permissions`;
const EDIT = `/admin/access/roles/${ROLE_ID}/edit`;
const VIEW = `/admin/access/roles/${ROLE_ID}/permissions`;

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

function permission(name: string, isSensitive = false): PermissionResponse {
  return { id: `id-${name}`, name, description: `Server description for ${name}`, isSensitive };
}

const CATALOGUE = [
  permission('tenant:read'),
  permission('user:read'),
  permission('user:directory:read', true),
  permission('role:read'),
  permission('role:write', true),
];
const ALL = CATALOGUE.map((entry) => entry.name);

function role(overrides: Partial<RoleResponse> = {}): RoleResponse {
  return {
    id: ROLE_ID,
    name: 'Support',
    description: 'Handles tickets',
    isSystemRole: false,
    createdAt: '2026-01-01T00:00:00Z',
    memberCount: 3,
    permissionCount: 2,
    ...overrides,
  };
}

function cataloguePage(): PermissionPageResponse {
  return {
    data: CATALOGUE,
    page: { size: 100, number: 0, totalElements: CATALOGUE.length, totalPages: 1 },
    links: { next: null, prev: null },
  };
}

@Component({ template: '<h1>Roles placeholder</h1>' })
class Placeholder {}

type ProfileStatus = 'ready' | 'error' | 'loading';

interface SetupOptions {
  /** What the live profile holds. */
  readonly held?: readonly string[];
  readonly isAdministrator?: boolean;
  readonly profile?: ProfileStatus;
}

function setup(options: SetupOptions = {}) {
  const held = options.held ?? ['role:read', 'role:write', 'user:read'];
  const profileStatus = signal<ProfileStatus>(options.profile ?? 'ready');
  const ready = (): boolean => profileStatus() === 'ready';
  const profileStub = {
    state: () => ({ status: profileStatus() }),
    can: (p: string) => ready() && held.includes(p),
    permissions: () => new Set(ready() ? held : []),
    isAdministrator: () => ready() && (options.isAdministrator ?? false),
    mutationsEnabled: () => ready(),
    load: vi.fn(),
    reload: vi.fn(),
  };
  const handleError = vi.fn();
  TestBed.configureTestingModule({
    providers: [
      { provide: APP_CONFIG, useValue: CONFIG },
      { provide: ErrorHandler, useValue: { handleError } },
      { provide: ServiceAvailabilityNotifier, useValue: { notifyUnavailable: vi.fn() } },
      {
        provide: AuthStore,
        useValue: createAuthStoreStub({
          session: createAuthSession({ user: createAuthUser({ userId: 'user-1' }) }),
          permissions: ['role:read', 'role:write'],
        }),
      },
      provideAnimationsAsync('noop'),
      provideHttpClient(withInterceptors([apiErrorInterceptor])),
      provideHttpClientTesting(),
      provideRouter([
        {
          path: 'admin/access',
          providers: [
            CatalogueStore,
            { provide: AuthorizationProfileStore, useValue: profileStub },
          ],
          children: [
            { path: 'roles', component: Placeholder },
            { path: 'roles/new', component: Placeholder },
            {
              path: 'roles/:roleId',
              component: RoleDetailPage,
              providers: [RoleDetailStore],
              children: [
                { path: '', pathMatch: 'full', redirectTo: 'permissions' },
                { path: 'permissions', component: RolePermissionsTab },
                {
                  path: 'edit',
                  component: RoleEditorPage,
                  canActivate: [permissionGuard],
                  canDeactivate: [unsavedChangesGuard],
                  data: { permission: 'role:write' },
                },
              ],
            },
          ],
        },
      ]),
    ],
  });
  const logger = TestBed.inject(LoggerService);
  const logs = [
    vi.spyOn(logger, 'debug'),
    vi.spyOn(logger, 'info'),
    vi.spyOn(logger, 'warn'),
    vi.spyOn(logger, 'error'),
  ];
  return {
    http: TestBed.inject(HttpTestingController),
    router: TestBed.inject(Router),
    handleError,
    profileStatus,
    logs,
  };
}

type Ctx = ReturnType<typeof setup>;

async function open(url: string) {
  const harness = await RouterTestingHarness.create();
  await harness.navigateByUrl(url);
  harness.detectChanges();
  const el = (): HTMLElement => harness.routeNativeElement as HTMLElement;
  const settle = async (): Promise<void> => {
    await harness.fixture.whenStable();
    harness.detectChanges();
    await harness.fixture.whenStable();
  };
  return { harness, el, settle };
}

function byTestId(root: ParentNode, id: string): HTMLElement | null {
  return root.querySelector(`[data-testid="${id}"]`);
}

function text(node: Element | null | undefined): string {
  return node?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
}

function button(root: ParentNode, id: string): HTMLButtonElement | null {
  return byTestId(root, id)?.querySelector('button') ?? null;
}

/** Answers the two role GETs, and the catalogue GET when it is pending. */
function answer(
  ctx: Ctx,
  options: { role?: RoleResponse; granted?: readonly string[]; etag?: string | null } = {},
): void {
  const granted = options.granted ?? ['role:read', 'user:read'];
  ctx.http.expectOne(ROLE_URL).flush(options.role ?? role({ permissionCount: granted.length }));
  const etag = options.etag === undefined ? '"v1"' : options.etag;
  const headers: Record<string, string> = etag === null ? {} : { ETag: etag };
  ctx.http
    .expectOne(SET_URL)
    .flush({ data: CATALOGUE.filter((p) => granted.includes(p.name)) }, { headers });
  for (const req of ctx.http.match(CATALOGUE_URL)) req.flush(cataloguePage());
}

/** The editor's checkbox for a permission code, in the table rendering. */
function box(el: HTMLElement, code: string): HTMLInputElement | null {
  return el.querySelector(
    `[data-testid="role-editor"] table tr[data-permission="${code}"] input[type="checkbox"]`,
  );
}

function review(): HTMLElement | null {
  return byTestId(document, 'role-review');
}

async function openEditor(ctx: Ctx, options: Parameters<typeof answer>[1] = {}) {
  const page = await open(EDIT);
  answer(ctx, options);
  await page.settle();
  return page;
}

describe('RoleEditorPage (US-020 design §4.8, §8, §12.4)', () => {
  let ctx: Ctx;

  afterEach(() => {
    ctx.http.verify();
    // RC-73: nothing ever reaches the global error handler.
    expect(ctx.handleError).not.toHaveBeenCalled();
  });

  describe('as a role editor who is not an administrator', () => {
    it('request budget (design §6.5 "Editor enter"): no request on entering from the detail page', async () => {
      ctx = setup();
      const { el, settle } = await open(VIEW);
      answer(ctx);
      await settle();

      button(el(), 'role-edit')?.click();
      await settle();

      expect(ctx.router.url).toBe(EDIT);
      expect(ctx.http.match(() => true)).toHaveLength(0);
      expect(box(el(), 'user:read')?.checked).toBe(true);
      // The detail page stays mounted: its header is still the one read before.
      expect(byTestId(el(), 'role-detail-title')?.querySelector('bdi')?.textContent).toBe(
        'Support',
      );
      // Edit is the open mode: no Edit control while editing.
      expect(byTestId(el(), 'role-edit')).toBeNull();
    });

    it('request budget (deep link): only the role page reads, once each', async () => {
      ctx = setup();
      await open(EDIT);
      expect(ctx.http.match(ROLE_URL)).toHaveLength(1);
      expect(ctx.http.match(SET_URL)).toHaveLength(1);
      expect(ctx.http.match(CATALOGUE_URL)).toHaveLength(1);
    });

    it('shows the matrix in edit mode with every row it cannot change disabled and explained', async () => {
      ctx = setup();
      const { el } = await openEditor(ctx);

      expect(box(el(), 'role:read')?.checked).toBe(true);
      expect(box(el(), 'role:write')?.checked).toBe(false);
      expect(box(el(), 'role:write')?.getAttribute('aria-disabled')).toBeNull();
      for (const code of ['tenant:read', 'user:directory:read']) {
        const row = box(el(), code) as HTMLInputElement;
        expect(row.getAttribute('aria-disabled')).toBe('true');
        const reason = el().querySelector(`[id="${row.getAttribute('aria-describedby')}"]`);
        expect(text(reason)).toBe(CONSOLE_COPY.disabledReason.notHeld);
      }
    });

    it('keeps the footer counts in a polite status and enables Review only with a change', async () => {
      ctx = setup();
      const { el, settle } = await openEditor(ctx);

      const counts = byTestId(el(), 'role-editor-counts');
      expect(counts?.getAttribute('role')).toBe('status');
      expect(text(counts)).toBe('0 to add, 0 to remove');
      const reviewButton = button(el(), 'role-editor-review');
      expect(reviewButton?.getAttribute('aria-disabled')).toBe('true');
      expect(reviewButton?.getAttribute('aria-describedby')).toBe(counts?.id);
      reviewButton?.click();
      await settle();
      expect(review()).toBeNull();

      box(el(), 'role:write')?.click();
      box(el(), 'user:read')?.click();
      await settle();
      expect(text(counts)).toBe('1 to add, 1 to remove');
      expect(button(el(), 'role-editor-review')?.getAttribute('aria-disabled')).toBeNull();

      box(el(), 'user:read')?.click();
      await settle();
      expect(text(counts)).toBe('1 to add, 0 to remove');
    });

    it('stages a group: every enabled member, never a disabled one', async () => {
      ctx = setup();
      const { el, settle } = await openEditor(ctx, { granted: ['user:read'] });

      const users = el().querySelector<HTMLInputElement>(
        '[data-testid="role-editor"] table tr[data-group="user"] input[type="checkbox"]',
      );
      // user:read is in; user:directory:read cannot be granted by this caller.
      expect(users?.getAttribute('aria-checked')).toBe('mixed');
      users?.click();
      await settle();
      expect(text(byTestId(el(), 'role-editor-counts'))).toBe('0 to add, 1 to remove');
      expect(box(el(), 'user:directory:read')?.checked).toBe(false);
    });

    it('reviews exactly what will be added and removed, with the sensitive confirm', async () => {
      ctx = setup();
      const { el, settle } = await openEditor(ctx);
      box(el(), 'role:write')?.click();
      box(el(), 'user:read')?.click();
      await settle();

      button(el(), 'role-editor-review')?.click();
      await settle();

      const dialog = review() as HTMLElement;
      expect(dialog).not.toBeNull();
      const title = byTestId(dialog, 'role-review-title');
      expect(title?.tagName).toBe('H2');
      expect(text(title)).toBe('Review changes to Support');
      expect(title?.querySelector('bdi')?.textContent).toBe('Support');
      expect(dialog.closest('[role="dialog"]')?.getAttribute('aria-labelledby')).toBe(title?.id);
      expect(document.querySelector('[mat-dialog-title], .mat-mdc-dialog-title')).toBeNull();

      const adding = byTestId(dialog, 'role-review-adding');
      expect(text(adding?.querySelector('h3'))).toBe('Adding (1)');
      const added = Array.from(adding?.querySelectorAll('li') ?? []);
      expect(added.map((li) => text(li.querySelector('.role-review__label')))).toEqual([
        'Create roles and manage role-permission assignments',
      ]);
      expect(added[0].querySelector('[data-testid="sensitive-badge"]')).not.toBeNull();
      const removing = byTestId(dialog, 'role-review-removing');
      expect(text(removing?.querySelector('h3'))).toBe('Removing (1)');
      expect(text(removing?.querySelector('li'))).toContain('Read user accounts and profiles');

      const affected = byTestId(dialog, 'role-review-affected');
      expect(text(affected?.querySelector('h3'))).toBe('Who is affected');
      expect(text(affected?.querySelector('p'))).toBe('3 people hold this role.');
      expect(byTestId(dialog, 'role-review-empty')).toBeNull();

      const confirm = button(dialog, 'role-review-confirm');
      expect(text(confirm?.querySelector('.nx-btn__label'))).toBe('Grant sensitive access');
      expect(confirm?.classList).toContain('nx-btn--danger');
      await expect(expectNoAxeViolations(dialog)).resolves.toBeUndefined();

      button(dialog, 'role-review-cancel')?.click();
      await settle();
      expect(review()).toBeNull();
      expect(text(byTestId(el(), 'role-editor-counts'))).toBe('1 to add, 1 to remove');
    });

    it('uses "Save changes" (primary) when nothing sensitive is added, and says who holds the role', async () => {
      ctx = setup();
      const { el, settle } = await openEditor(ctx, { role: role({ memberCount: 0 }) });
      box(el(), 'user:read')?.click();
      await settle();
      button(el(), 'role-editor-review')?.click();
      await settle();

      const dialog = review() as HTMLElement;
      const confirm = button(dialog, 'role-review-confirm');
      expect(text(confirm?.querySelector('.nx-btn__label'))).toBe('Save changes');
      expect(confirm?.classList).toContain('nx-btn--primary');
      expect(byTestId(dialog, 'role-review-adding')).toBeNull();
      expect(text(byTestId(dialog, 'role-review-affected')?.querySelector('p'))).toBe(
        'No one holds this role yet.',
      );
    });

    it('warns when the result would grant no access', async () => {
      ctx = setup();
      const { el, settle } = await openEditor(ctx);
      box(el(), 'user:read')?.click();
      box(el(), 'role:read')?.click();
      await settle();
      button(el(), 'role-editor-review')?.click();
      await settle();

      const warning = byTestId(review() as HTMLElement, 'role-review-empty');
      expect(warning?.getAttribute('role')).toBe('alert');
      expect(text(warning)).toBe('This role will grant no access.');
    });

    it('opens Review once however often it is pressed (FR-G5)', async () => {
      ctx = setup();
      const { el, settle } = await openEditor(ctx);
      box(el(), 'role:write')?.click();
      await settle();
      button(el(), 'role-editor-review')?.click();
      button(el(), 'role-editor-review')?.click();
      await settle();

      expect(document.querySelectorAll('[data-testid="role-review"]')).toHaveLength(1);
    });

    it('confirm closes the Review and keeps the staged work; nothing is sent yet (save is T-011)', async () => {
      ctx = setup();
      const { el, settle } = await openEditor(ctx);
      box(el(), 'role:write')?.click();
      await settle();
      button(el(), 'role-editor-review')?.click();
      await settle();

      button(review() as HTMLElement, 'role-review-confirm')?.click();
      await settle();

      expect(review()).toBeNull();
      expect(ctx.http.match(() => true)).toHaveLength(0);
      expect(text(byTestId(el(), 'role-editor-counts'))).toBe('1 to add, 0 to remove');
    });

    it('Discard drops the staged work and returns to the permissions tab without asking', async () => {
      ctx = setup();
      const { el, settle } = await openEditor(ctx);
      box(el(), 'role:write')?.click();
      await settle();

      button(el(), 'role-editor-discard')?.click();
      await settle();

      expect(ctx.router.url).toBe(VIEW);
      expect(document.querySelector('nx-dialog-shell')).toBeNull();
      expect(ctx.http.match(() => true)).toHaveLength(0);
    });

    it('asks before leaving with unsaved changes, and Stay keeps the editor', async () => {
      ctx = setup();
      const { el, settle } = await openEditor(ctx);
      box(el(), 'role:write')?.click();
      await settle();

      const navigation = ctx.router.navigateByUrl('/admin/access/roles');
      // Not `settle()`: the app is not stable while the guard waits for the choice.
      const prompt = await vi.waitFor(() => {
        const shell = document.querySelector<HTMLElement>('nx-dialog-shell');
        expect(text(shell)).toContain('Leave without saving?');
        return shell as HTMLElement;
      });
      expect(text(prompt)).toContain('Leave without saving?');
      expect(text(prompt)).toContain('Your changes stay as a draft in this tab.');
      const stay = Array.from(prompt.querySelectorAll('button')).find((b) => text(b) === 'Stay');
      (stay as HTMLButtonElement).click();
      await expect(navigation).resolves.toBe(false);
      await settle();

      expect(ctx.router.url).toBe(EDIT);
      expect(text(byTestId(el(), 'role-editor-counts'))).toBe('1 to add, 0 to remove');
    });

    it('leaves without asking when nothing is staged', async () => {
      ctx = setup();
      await openEditor(ctx);

      await expect(ctx.router.navigateByUrl('/admin/access/roles')).resolves.toBe(true);
      expect(document.querySelector('nx-dialog-shell')).toBeNull();
    });

    it('asks the browser to confirm an unload only while there are unsaved changes', async () => {
      ctx = setup();
      const { el, settle } = await openEditor(ctx);
      const unload = (): boolean => {
        const event = new Event('beforeunload', { cancelable: true });
        window.dispatchEvent(event);
        return event.defaultPrevented;
      };
      expect(unload()).toBe(false);
      box(el(), 'role:write')?.click();
      await settle();
      expect(unload()).toBe(true);
      box(el(), 'role:write')?.click();
      await settle();
      expect(unload()).toBe(false);
    });

    it('keeps a focused row clear of the sticky footer while open (WCAG 2.4.11)', async () => {
      ctx = setup();
      await openEditor(ctx);
      const padding = (): string =>
        document.documentElement.style.getPropertyValue('scroll-padding-bottom');
      expect(padding()).toBe('calc(var(--nx-space-24) + var(--nx-space-12))');

      await ctx.router.navigateByUrl('/admin/access/roles');
      expect(padding()).toBe('');
    });

    it('keeps the staged work consistent when Refresh brings the same change from elsewhere', async () => {
      ctx = setup();
      const { el, settle } = await openEditor(ctx);
      box(el(), 'role:write')?.click();
      box(el(), 'tenant:read')?.click();
      await settle();
      expect(text(byTestId(el(), 'role-editor-counts'))).toBe('1 to add, 0 to remove');

      button(el(), 'role-detail-refresh')?.click();
      ctx.http.expectOne(ROLE_URL).flush(role({ permissionCount: 3 }));
      ctx.http.expectOne(SET_URL).flush(
        {
          data: CATALOGUE.filter((p) => ['role:read', 'user:read', 'role:write'].includes(p.name)),
        },
        { headers: { ETag: '"v2"' } },
      );
      await settle();

      expect(text(byTestId(el(), 'role-editor-counts'))).toBe('0 to add, 0 to remove');
      expect(box(el(), 'role:write')?.checked).toBe(true);
    });

    it('renders user text as text and never logs the role name or description', async () => {
      ctx = setup();
      const name = '<img src=x onerror=alert(1)>‮Secret role';
      const { el, settle } = await openEditor(ctx, {
        role: role({ name, description: 'Secret words' }),
      });
      box(el(), 'role:write')?.click();
      await settle();
      button(el(), 'role-editor-review')?.click();
      await settle();

      const title = byTestId(review() as HTMLElement, 'role-review-title');
      expect(title?.querySelector('bdi')?.textContent).toBe(name);
      expect(document.querySelector('img')).toBeNull();
      const logged = JSON.stringify(ctx.logs.map((spy) => spy.mock.calls));
      expect(logged).not.toContain('Secret role');
      expect(logged).not.toContain('Secret words');
    });

    it('has no axe violations', async () => {
      ctx = setup();
      const { el, settle } = await openEditor(ctx);
      box(el(), 'role:write')?.click();
      await settle();

      await expect(expectNoAxeViolations(el())).resolves.toBeUndefined();
    });
  });

  describe('administrator hints (Q17: hints, never blocks)', () => {
    it('hints at demotion on a role that grants every permission, and in the Review', async () => {
      ctx = setup({ held: ALL, isAdministrator: true });
      const { el, settle } = await openEditor(ctx, {
        role: role({ permissionCount: ALL.length }),
        granted: ALL,
      });

      const hint = byTestId(el(), 'role-editor-admin-hint');
      expect(text(hint)).toContain(CONSOLE_COPY.hints.adminDemotion);
      const audit = box(el(), 'tenant:read') as HTMLInputElement;
      expect(audit.getAttribute('aria-disabled')).toBeNull();
      audit.click();
      await settle();
      button(el(), 'role-editor-review')?.click();
      await settle();

      const hints = Array.from(
        review()?.querySelectorAll('[data-testid="role-review-hint"]') ?? [],
      );
      expect(hints.map(text)).toEqual([CONSOLE_COPY.hints.adminDemotion]);
    });

    it('hints when the change makes the role grant every permission', async () => {
      ctx = setup({ held: ALL, isAdministrator: true });
      const { el, settle } = await openEditor(ctx, {
        granted: ALL.filter((name) => name !== 'tenant:read'),
      });
      expect(byTestId(el(), 'role-editor-admin-hint')).toBeNull();
      box(el(), 'tenant:read')?.click();
      await settle();
      button(el(), 'role-editor-review')?.click();
      await settle();

      const hints = Array.from(
        review()?.querySelectorAll('[data-testid="role-review-hint"]') ?? [],
      );
      expect(hints.map(text)).toEqual([CONSOLE_COPY.hints.wholeCatalogue]);
    });
  });

  describe('when the role cannot be edited', () => {
    it('renders no edit control on a system role (FR-B7)', async () => {
      ctx = setup();
      const { el } = await openEditor(ctx, {
        role: role({ isSystemRole: true, name: 'TENANT_ADMIN' }),
      });

      expect(el().querySelector('[data-testid="role-editor"] input[type="checkbox"]')).toBeNull();
      expect(byTestId(el(), 'role-editor-footer')).toBeNull();
      expect(byTestId(el(), 'role-system-banner')).not.toBeNull();
      expect(byTestId(el(), 'role-editor-back')?.getAttribute('href')).toBe(VIEW);
    });

    it('lets nothing be staged when the version tag is unusable (design §7.2)', async () => {
      ctx = setup();
      const { el } = await openEditor(ctx, { etag: 'W/"v1"' });

      expect(el().querySelector('[data-testid="role-editor"] input[type="checkbox"]')).toBeNull();
      expect(text(byTestId(el(), 'role-editor-blocked-reason'))).toBe(
        CONSOLE_COPY.disabledReason.etagUnusable,
      );
      expect(byTestId(el(), 'role-editor-back')).not.toBeNull();
    });

    it('follows the live profile when it does not hold role:write (ADR-0028)', async () => {
      ctx = setup({ held: ['role:read', 'user:read'] });
      const { el } = await openEditor(ctx);

      expect(el().querySelector('[data-testid="role-editor"] input[type="checkbox"]')).toBeNull();
      expect(text(byTestId(el(), 'role-editor-blocked-reason'))).toBe(CONSOLE_COPY.editor.noWrite);
    });

    it('disables every row with the reason while the profile is unavailable (Q8)', async () => {
      ctx = setup({ profile: 'error' });
      const { el } = await openEditor(ctx);

      const boxes = Array.from(
        el().querySelectorAll<HTMLInputElement>(
          '[data-testid="role-editor"] table tr[data-permission] input[type="checkbox"]',
        ),
      );
      expect(boxes).toHaveLength(CATALOGUE.length);
      for (const row of boxes) {
        expect(row.getAttribute('aria-disabled')).toBe('true');
        const reason = el().querySelector(`[id="${row.getAttribute('aria-describedby')}"]`);
        expect(text(reason)).toBe(CONSOLE_COPY.disabledReason.profileUnavailable);
      }
    });

    it('waits for the profile before showing any control', async () => {
      ctx = setup({ profile: 'loading' });
      const { el } = await openEditor(ctx);

      expect(el().querySelector('[data-testid="role-editor"] input[type="checkbox"]')).toBeNull();
      expect(byTestId(el(), 'role-editor-loading')?.getAttribute('aria-busy')).toBe('true');
    });
  });
});
