import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  HttpTestingController,
  TestRequest,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { Component, ErrorHandler, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { Router, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { of } from 'rxjs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthStore } from '../../../core/auth/auth.store';
import { APP_CONFIG, AppConfig } from '../../../core/config/app-config';
import { permissionGuard } from '../../../core/guards/permission.guard';
import { apiErrorInterceptor } from '../../../core/http/api-error.interceptor';
import { ServiceAvailabilityNotifier } from '../../../core/http/service-availability-notifier';
import { LoggerService } from '../../../core/logging/logger.service';
import { AuthService } from '../../auth/auth.service';
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
import { NxDialog, NxToast } from '../../../shared/ui';
import { CONSOLE_COPY, RbacErrorMessages, format } from '../copy/console-copy';
import { permissionLabel } from '../copy/permission-labels';
import { PROPAGATION_COPY } from '../copy/propagation';
import { AuthorizationProfileStore } from '../data/authorization-profile.store';
import { CatalogueStore } from '../data/catalogue.store';
import { RolesStore } from '../data/roles.store';
import { RoleDetailPage } from '../role-detail/role-detail.page';
import { RoleDetailStore } from '../role-detail/role-detail.store';
import { RolePermissionsTab } from '../role-detail/role-permissions.tab';
import { RoleCreatePage } from './role-create.page';
import { RoleEditorPage } from './role-editor.page';
import { unsavedChangesGuard } from './unsaved-changes.guard';

const API = 'http://localhost:1000/api';
const SOURCE_ID = '0190a000-0000-7000-8000-0000000000c1';
const NEW_ID = '0190a000-0000-7000-8000-0000000000d1';
const CATALOGUE_URL = `${API}/v1/permissions?page=0&size=100`;
const ROLES_URL = `${API}/v1/roles`;
const roleUrl = (id: string): string => `${API}/v1/roles/${id}`;
const setUrl = (id: string): string => `${API}/v1/roles/${id}/permissions`;
const CREATE = '/admin/access/roles/new';
const CLONE = `/admin/access/roles/new?from=${SOURCE_ID}`;
const DRAFT_KEY = `nexus.session.access-draft.v1.user-1.${NEW_ID}`;

const CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: API,
  logLevel: 'debug',
  supportContact: null,
  accessConsoleEnabled: true,
};

const PERMISSION_IDS: Readonly<Record<string, string>> = {
  'tenant:read': '0190a000-0000-7000-8000-000000000101',
  'user:read': '0190a000-0000-7000-8000-000000000102',
  'user:directory:read': '0190a000-0000-7000-8000-000000000103',
  'role:read': '0190a000-0000-7000-8000-000000000104',
  'role:write': '0190a000-0000-7000-8000-000000000105',
};

function idOf(name: string): string {
  return PERMISSION_IDS[name] ?? `id-${name}`;
}

function permission(name: string, isSensitive = false): PermissionResponse {
  return { id: idOf(name), name, description: `Server description for ${name}`, isSensitive };
}

const CATALOGUE = [
  permission('tenant:read'),
  permission('user:read'),
  permission('user:directory:read', true),
  permission('role:read'),
  permission('role:write', true),
];

function role(overrides: Partial<RoleResponse> = {}): RoleResponse {
  return {
    id: SOURCE_ID,
    name: 'Support',
    description: 'Handles tickets',
    isSystemRole: false,
    createdAt: '2026-01-01T00:00:00Z',
    memberCount: 3,
    permissionCount: 2,
    ...overrides,
  };
}

function created(overrides: Partial<RoleResponse> = {}): RoleResponse {
  return role({
    id: NEW_ID,
    name: 'Auditors',
    description: 'Reads the trail',
    memberCount: 0,
    permissionCount: 0,
    ...overrides,
  });
}

function cataloguePage(): PermissionPageResponse {
  return {
    data: CATALOGUE,
    page: { size: 100, number: 0, totalElements: CATALOGUE.length, totalPages: 1 },
    links: { next: null, prev: null },
  };
}

function labelOf(code: string): string {
  return permissionLabel(code) ?? code;
}

@Component({ template: '<h1>Roles placeholder</h1>' })
class Placeholder {}

type ProfileStatus = 'ready' | 'error' | 'loading';

interface SetupOptions {
  readonly held?: readonly string[];
  readonly isAdministrator?: boolean;
  readonly profile?: ProfileStatus;
}

function setup(options: SetupOptions = {}) {
  const held = signal<readonly string[]>(options.held ?? ['role:read', 'role:write', 'user:read']);
  const profileStatus = signal<ProfileStatus>(options.profile ?? 'ready');
  const ready = (): boolean => profileStatus() === 'ready';
  const profileStub = {
    state: () => ({ status: profileStatus() }),
    can: (p: string) => ready() && held().includes(p),
    permissions: () => new Set(ready() ? held() : []),
    isAdministrator: () => ready() && (options.isAdministrator ?? false),
    mutationsEnabled: () => ready(),
    roleIds: () => new Set<string>(),
    load: vi.fn(),
    reload: vi.fn(),
  };
  const handleError = vi.fn();
  const authRefresh = vi.fn();
  TestBed.configureTestingModule({
    providers: [
      { provide: APP_CONFIG, useValue: CONFIG },
      { provide: ErrorHandler, useValue: { handleError } },
      { provide: ServiceAvailabilityNotifier, useValue: { notifyUnavailable: vi.fn() } },
      { provide: AuthService, useValue: { refresh: authRefresh } },
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
            RolesStore,
            { provide: AuthorizationProfileStore, useValue: profileStub },
          ],
          children: [
            { path: 'roles', component: Placeholder },
            {
              path: 'roles/new',
              component: RoleCreatePage,
              canActivate: [permissionGuard],
              canDeactivate: [unsavedChangesGuard],
              data: { permission: 'role:write' },
            },
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
                  canDeactivate: [unsavedChangesGuard],
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
  const toast = vi.spyOn(TestBed.inject(NxToast), 'success').mockImplementation(() => undefined);
  const invalidate = vi.spyOn(RolesStore.prototype, 'invalidate');
  return {
    http: TestBed.inject(HttpTestingController),
    router: TestBed.inject(Router),
    handleError,
    authRefresh,
    profileStub,
    held,
    logs,
    toast,
    invalidate,
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
    harness.detectChanges();
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

function flushCatalogue(ctx: Ctx): void {
  for (const req of ctx.http.match(CATALOGUE_URL)) req.flush(cataloguePage());
}

async function openCreate(ctx: Ctx, url = CREATE) {
  const page = await open(url);
  flushCatalogue(ctx);
  await page.settle();
  return page;
}

function nameInput(el: HTMLElement): HTMLInputElement {
  return el.querySelector('#role-create-name') as HTMLInputElement;
}

function descriptionInput(el: HTMLElement): HTMLTextAreaElement {
  return el.querySelector('textarea[data-testid="role-create-description"]') as HTMLTextAreaElement;
}

function type(field: HTMLInputElement | HTMLTextAreaElement, value: string): void {
  field.value = value;
  field.dispatchEvent(new Event('input'));
  field.dispatchEvent(new Event('blur'));
}

function box(el: HTMLElement, code: string): HTMLInputElement | null {
  return el.querySelector(
    `[data-testid="role-create"] table tr[data-permission="${code}"] input[type="checkbox"]`,
  );
}

function describedByTexts(el: HTMLElement, field: HTMLElement): string[] {
  return (field.getAttribute('aria-describedby') ?? '')
    .split(' ')
    .filter(Boolean)
    .map((id) => text(el.querySelector(`[id="${id}"]`)));
}

/** Fills a valid form and submits it; the POST is then pending. */
async function fillAndSubmit(
  page: Awaited<ReturnType<typeof open>>,
  codes: readonly string[] = [],
): Promise<void> {
  type(nameInput(page.el()), 'Auditors');
  type(descriptionInput(page.el()), 'Reads the trail');
  for (const code of codes) box(page.el(), code)?.click();
  await page.settle();
  button(page.el(), 'role-create-submit')?.click();
  await page.settle();
}

function refuse(req: TestRequest, code: string, status: number, extra: object = {}): void {
  req.flush(
    { code, detail: 'Server detail with limit 50', traceId: 'trace-9', ...extra },
    { status, statusText: code },
  );
}

/** Answers the POST with the new role. */
function answerCreate(ctx: Ctx): TestRequest {
  const req = ctx.http.expectOne(
    (candidate) => candidate.method === 'POST' && candidate.url === ROLES_URL,
  );
  req.flush(created(), { status: 201, statusText: 'Created' });
  return req;
}

function expectSetGet(ctx: Ctx): TestRequest {
  return ctx.http.expectOne(
    (candidate) => candidate.method === 'GET' && candidate.url === setUrl(NEW_ID),
  );
}

function expectPut(ctx: Ctx): TestRequest {
  return ctx.http.expectOne(
    (candidate) => candidate.method === 'PUT' && candidate.url === setUrl(NEW_ID),
  );
}

/** Answers the role page's own reads after a navigation to the new role. */
function answerRolePage(ctx: Ctx, granted: readonly string[] = [], etag = '"e1"'): void {
  ctx.http.expectOne(roleUrl(NEW_ID)).flush(created({ permissionCount: granted.length }));
  ctx.http
    .expectOne(setUrl(NEW_ID))
    .flush(
      { data: CATALOGUE.filter((p) => granted.includes(p.name)) },
      { headers: { ETag: etag } },
    );
}

function loggedText(ctx: Ctx): string {
  return JSON.stringify(ctx.logs.flatMap((spy) => spy.mock.calls));
}

describe('RoleCreatePage (US-020 design §6.6, §11.3, §12.5)', () => {
  let ctx: Ctx;

  afterEach(() => {
    ctx.http.verify();
    // RC-73: nothing ever reaches the global error handler.
    expect(ctx.handleError).not.toHaveBeenCalled();
    // RC-65: the console never starts a session refresh of its own.
    expect(ctx.authRefresh).not.toHaveBeenCalled();
    vi.restoreAllMocks();
    sessionStorage.clear();
  });

  describe('the form', () => {
    it('shows the name with its hint and counter, the description with its counter, and the matrix', async () => {
      ctx = setup();
      const { el, settle } = await openCreate(ctx);

      expect(text(el().querySelector('h1'))).toBe(CONSOLE_COPY.createRole.title);
      type(nameInput(el()), 'Ops');
      type(descriptionInput(el()), 'Night shift');
      await settle();

      const name = describedByTexts(el(), nameInput(el()));
      expect(name).toContain(CONSOLE_COPY.createRole.nameHint);
      expect(name).toContain('3 of 64');
      expect(describedByTexts(el(), descriptionInput(el()))).toContain('11 of 255');
      // Counters are not live regions (design §13 "Forms").
      expect(byTestId(el(), 'role-create-name-counter')?.closest('[aria-live],[role]')).toBeNull();
      // Every row is an add on a new role; the ones the caller does not hold are disabled.
      expect(box(el(), 'user:read')?.getAttribute('aria-disabled')).toBeNull();
      expect(box(el(), 'tenant:read')?.getAttribute('aria-disabled')).toBe('true');
      expect(box(el(), 'user:read')?.checked).toBe(false);
    });

    it('shows the grant line only while permissions are chosen (FR-F3)', async () => {
      ctx = setup();
      const { el, settle } = await openCreate(ctx);
      expect(byTestId(el(), 'role-create-propagation')).toBeNull();

      box(el(), 'user:read')?.click();
      await settle();

      expect(text(byTestId(el(), 'role-create-propagation'))).toBe(PROPAGATION_COPY.grant);
    });

    it('refuses to submit invalid details: an error summary that links to each field, and nothing sent', async () => {
      ctx = setup();
      const { el, settle } = await openCreate(ctx);
      type(descriptionInput(el()), 'two\u2028lines');
      await settle();

      button(el(), 'role-create-submit')?.click();
      await settle();

      ctx.http.expectNone(ROLES_URL);
      const summary = byTestId(el(), 'role-create-summary') as HTMLElement;
      expect(summary.getAttribute('role')).toBe('alert');
      expect(document.activeElement).toBe(summary);
      const links = [...summary.querySelectorAll('a')];
      expect(links.map((link) => text(link))).toEqual([
        CONSOLE_COPY.createRole.errors.nameRequired,
        CONSOLE_COPY.createRole.errors.descriptionControl,
      ]);
      expect(describedByTexts(el(), nameInput(el()))).toContain(
        CONSOLE_COPY.createRole.errors.nameRequired,
      );
      expect(descriptionInput(el()).getAttribute('aria-invalid')).toBe('true');

      links[0].click();
      expect(document.activeElement).toBe(nameInput(el()));
      links[1].click();
      expect(document.activeElement).toBe(descriptionInput(el()));
      // The links never navigate: the router would ask the leave guard.
      expect(ctx.router.url).toBe(CREATE);
    });

    it('shows a field error once the field is left, without submitting', async () => {
      ctx = setup();
      const { el, settle } = await openCreate(ctx);
      type(nameInput(el()), 'member');
      await settle();

      expect(text(byTestId(el(), 'role-create-name-error'))).toBe(
        CONSOLE_COPY.createRole.errors.nameReserved,
      );
      expect(byTestId(el(), 'role-create-summary')).toBeNull();
    });

    it('asks before leaving with unsaved details, with copy that promises no draft', async () => {
      ctx = setup();
      const { el, settle } = await openCreate(ctx);
      const dialog = vi
        .spyOn(TestBed.inject(NxDialog), 'open')
        .mockReturnValue({ afterClosed: () => of(false) } as ReturnType<NxDialog['open']>);
      type(nameInput(el()), 'Ops');
      await settle();

      await ctx.router.navigateByUrl('/admin/access/roles');

      expect(dialog).toHaveBeenCalledWith(
        expect.objectContaining({ message: CONSOLE_COPY.createRole.leaveMessage }),
      );
      expect(ctx.router.url).toBe(CREATE);
    });

    it('leaves a clean form without asking', async () => {
      ctx = setup();
      await openCreate(ctx);
      const dialog = vi.spyOn(TestBed.inject(NxDialog), 'open');
      await ctx.router.navigateByUrl('/admin/access/roles');
      expect(dialog).not.toHaveBeenCalled();
      expect(ctx.router.url).toBe('/admin/access/roles');
    });

    it('has no axe violations with the error summary and field errors shown', async () => {
      ctx = setup();
      const { el, settle } = await openCreate(ctx);
      button(el(), 'role-create-submit')?.click();
      await settle();
      await expectNoAxeViolations(el());
    });
  });

  describe('create (design §11.3)', () => {
    it('request budget (design §6.5 "Create"): no permissions gives exactly one POST', async () => {
      ctx = setup();
      const page = await openCreate(ctx);
      await fillAndSubmit(page);

      const post = answerCreate(ctx);
      expect(post.request.body).toEqual({ name: 'Auditors', description: 'Reads the trail' });
      // Nothing follows the 201 when no permission was chosen.
      expect(ctx.http.match(() => true)).toHaveLength(0);
      await page.settle();

      expect(ctx.router.url).toBe(`/admin/access/roles/${NEW_ID}/permissions`);
      expect(ctx.toast).toHaveBeenCalledWith(CONSOLE_COPY.createRole.success);
      expect(ctx.invalidate).toHaveBeenCalled();
      answerRolePage(ctx);
      await page.settle();
    });

    it('request budget: with permissions, POST, then GET of the new set, then one PUT with its strong tag', async () => {
      ctx = setup();
      const page = await openCreate(ctx);
      await fillAndSubmit(page, ['user:read', 'role:write']);

      answerCreate(ctx);
      expectSetGet(ctx).flush({ data: [] }, { headers: { ETag: '"e0"' } });
      const put = expectPut(ctx);
      expect(put.request.headers.getAll('If-Match')).toEqual(['"e0"']);
      expect([...(put.request.body as { permissionIds: string[] }).permissionIds].sort()).toEqual(
        [idOf('user:read'), idOf('role:write')].sort(),
      );
      put.flush(
        { data: CATALOGUE.filter((p) => ['user:read', 'role:write'].includes(p.name)) },
        { headers: { ETag: '"e1"' } },
      );
      expect(ctx.http.match(() => true)).toHaveLength(0);
      await page.settle();

      expect(ctx.router.url).toBe(`/admin/access/roles/${NEW_ID}/permissions`);
      expect(ctx.toast).toHaveBeenCalledWith(
        `${CONSOLE_COPY.createRole.success} ${PROPAGATION_COPY.grant}`,
      );
      answerRolePage(ctx, ['user:read', 'role:write']);
      await page.settle();
    });

    it('ignores a second submit while the create runs (no double POST)', async () => {
      ctx = setup();
      const page = await openCreate(ctx);
      await fillAndSubmit(page);
      const submit = button(page.el(), 'role-create-submit');
      expect(submit?.getAttribute('aria-disabled')).toBe('true');
      submit?.click();
      await page.settle();

      answerCreate(ctx);
      await page.settle();
      answerRolePage(ctx);
      await page.settle();
    });

    it('refuses to leave while the POST is in flight, says why, and lets the create finish (MJ-4)', async () => {
      ctx = setup();
      const page = await openCreate(ctx);
      const prompt = vi.spyOn(TestBed.inject(NxDialog), 'open');
      const info = vi.spyOn(TestBed.inject(NxToast), 'info').mockImplementation(() => undefined);
      await fillAndSubmit(page, ['user:read']);

      await expect(ctx.router.navigateByUrl('/admin/access/roles')).resolves.toBe(false);

      expect(prompt).not.toHaveBeenCalled();
      expect(info).toHaveBeenCalledWith(CONSOLE_COPY.createRole.stillCreating);
      expect(ctx.router.url).toBe(CREATE);
      // The page is still there, so the create runs to its end and the list is invalidated.
      answerCreate(ctx);
      expectSetGet(ctx).flush({ data: [] }, { headers: { ETag: '"e0"' } });
      expectPut(ctx).flush(
        { data: CATALOGUE.filter((p) => p.name === 'user:read') },
        { headers: { ETag: '"e1"' } },
      );
      await page.settle();
      expect(ctx.invalidate).toHaveBeenCalled();
      expect(ctx.router.url).toBe(`/admin/access/roles/${NEW_ID}/permissions`);
      answerRolePage(ctx, ['user:read']);
      await page.settle();
    });

    it('invalidates the roles list even when the page goes away with the POST unanswered', async () => {
      ctx = setup();
      const page = await openCreate(ctx);
      await fillAndSubmit(page);
      ctx.invalidate.mockClear();

      page.harness.fixture.destroy();

      expect(ctx.invalidate).toHaveBeenCalled();
      const post = ctx.http.expectOne(
        (candidate) => candidate.method === 'POST' && candidate.url === ROLES_URL,
      );
      expect(post.cancelled).toBe(true);
    });

    it('sends a description with markup verbatim and renders nothing of it as HTML (FR-G9)', async () => {
      ctx = setup();
      const { el, settle } = await openCreate(ctx);
      type(nameInput(el()), 'Auditors');
      type(descriptionInput(el()), '<img src=x onerror=alert(1)>');
      await settle();
      button(el(), 'role-create-submit')?.click();
      await settle();

      const post = ctx.http.expectOne(ROLES_URL);
      expect(post.request.body).toEqual({
        name: 'Auditors',
        description: '<img src=x onerror=alert(1)>',
      });
      expect(el().querySelector('img')).toBeNull();
      refuse(post, 'INTERNAL_ERROR', 500);
      await settle();
    });

    describe('a failure after the 201 (partial create)', () => {
      async function partialAfterPut(ctx: Ctx) {
        const page = await openCreate(ctx);
        await fillAndSubmit(page, ['user:read']);
        answerCreate(ctx);
        expectSetGet(ctx).flush({ data: [] }, { headers: { ETag: '"e0"' } });
        refuse(expectPut(ctx), 'INTERNAL_ERROR', 500);
        await page.settle();
        return page;
      }

      it('shows the partial banner with Retry and Open role, and writes an ids-only draft for the new role', async () => {
        ctx = setup();
        const { el } = await partialAfterPut(ctx);

        const banner = byTestId(el(), 'role-create-partial');
        expect(text(banner)).toContain(CONSOLE_COPY.createRole.partial);
        expect(text(banner)).toContain('trace-9');
        expect(button(el(), 'role-create-retry')).not.toBeNull();
        expect(button(el(), 'role-create-open')).not.toBeNull();

        const raw = sessionStorage.getItem(DRAFT_KEY) as string;
        const draft = JSON.parse(raw) as Record<string, unknown>;
        expect(draft).toEqual({
          v: 1,
          add: [idOf('user:read')],
          remove: [],
          baseEtag: '"e0"',
          savedAt: expect.any(Number),
        });
        for (const userText of ['Auditors', 'Reads the trail', labelOf('user:read')]) {
          expect(raw).not.toContain(userText);
        }
        expect(ctx.invalidate).toHaveBeenCalled();
        expect(ctx.router.url).toBe(CREATE);
      });

      it('never posts again: the details are locked and leaving does not ask', async () => {
        ctx = setup();
        const { el, settle } = await partialAfterPut(ctx);

        expect(nameInput(el()).disabled).toBe(true);
        expect(descriptionInput(el()).disabled).toBe(true);
        expect(byTestId(el(), 'role-create-submit')).toBeNull();
        // Read mode: what the role is meant to grant, with no control to change it.
        expect(box(el(), 'user:read')).toBeNull();
        expect(
          text(
            el().querySelector(
              'table tr[data-permission="user:read"] [data-testid="matrix-status"]',
            ),
          ),
        ).toContain(CONSOLE_COPY.matrix.granted);
        const dialog = vi.spyOn(TestBed.inject(NxDialog), 'open');
        await ctx.router.navigateByUrl('/admin/access/roles');
        await settle();
        expect(dialog).not.toHaveBeenCalled();
        ctx.http.expectNone(ROLES_URL);
      });

      it('Retry re-reads the new set and PUTs with the fresh tag, then clears the draft', async () => {
        ctx = setup();
        const page = await partialAfterPut(ctx);

        button(page.el(), 'role-create-retry')?.click();
        await page.settle();
        expectSetGet(ctx).flush({ data: [] }, { headers: { ETag: '"e5"' } });
        const put = expectPut(ctx);
        expect(put.request.headers.get('If-Match')).toBe('"e5"');
        expect(put.request.body).toEqual({ permissionIds: [idOf('user:read')] });
        put.flush({ data: [permission('user:read')] }, { headers: { ETag: '"e6"' } });
        await page.settle();

        expect(sessionStorage.getItem(DRAFT_KEY)).toBeNull();
        expect(ctx.router.url).toBe(`/admin/access/roles/${NEW_ID}/permissions`);
        expect(ctx.toast).toHaveBeenCalledWith(
          `${CONSOLE_COPY.createRole.success} ${PROPAGATION_COPY.grant}`,
        );
        answerRolePage(ctx, ['user:read']);
        await page.settle();
      });

      it('a failed Retry keeps the banner, the draft and the work', async () => {
        ctx = setup();
        const page = await partialAfterPut(ctx);

        button(page.el(), 'role-create-retry')?.click();
        await page.settle();
        refuse(expectSetGet(ctx), 'INTERNAL_ERROR', 500);
        await page.settle();

        expect(byTestId(page.el(), 'role-create-partial')).not.toBeNull();
        expect(sessionStorage.getItem(DRAFT_KEY)).not.toBeNull();
        expect(ctx.router.url).toBe(CREATE);
      });

      it('Open role lands in the editor of the new role, which offers the draft', async () => {
        ctx = setup();
        const page = await partialAfterPut(ctx);

        button(page.el(), 'role-create-open')?.click();
        await page.settle();
        expect(ctx.router.url).toBe(`/admin/access/roles/${NEW_ID}/edit`);
        answerRolePage(ctx, [], '"e0"');
        await page.settle();

        expect(byTestId(page.el(), 'role-editor-draft-offer')).not.toBeNull();
      });

      it('a failed read of the new set gives the partial banner, a draft without a tag, and no PUT', async () => {
        ctx = setup();
        const page = await openCreate(ctx);
        await fillAndSubmit(page, ['user:read']);
        answerCreate(ctx);
        refuse(expectSetGet(ctx), 'AUTH_005', 503);
        await page.settle();

        ctx.http.expectNone(setUrl(NEW_ID));
        expect(byTestId(page.el(), 'role-create-partial')).not.toBeNull();
        expect(JSON.parse(sessionStorage.getItem(DRAFT_KEY) as string)).toMatchObject({
          add: [idOf('user:read')],
          baseEtag: null,
        });
      });

      it('a weak tag on the new set gives the partial banner without a PUT', async () => {
        ctx = setup();
        const page = await openCreate(ctx);
        await fillAndSubmit(page, ['user:read']);
        answerCreate(ctx);
        expectSetGet(ctx).flush({ data: [] }, { headers: { ETag: 'W/"e0"' } });
        await page.settle();

        ctx.http.expectNone(setUrl(NEW_ID));
        const banner = byTestId(page.el(), 'role-create-partial');
        expect(text(banner)).toContain(CONSOLE_COPY.roleDetail.etagUnusable.body);
        expect(sessionStorage.getItem(DRAFT_KEY)).not.toBeNull();
      });

      it('logs ids, counts and codes only: never the name or the description', async () => {
        ctx = setup();
        await partialAfterPut(ctx);

        const logged = loggedText(ctx);
        expect(logged).toContain(NEW_ID);
        expect(logged).toContain('access_console_create_partial');
        for (const userText of ['Auditors', 'Reads the trail', 'Server detail']) {
          expect(logged).not.toContain(userText);
        }
      });
    });

    describe('the create is refused', () => {
      it.each(['RBAC_006', 'RBAC_007'] as const)(
        '%s goes on the name field and in the summary',
        async (code) => {
          ctx = setup();
          const page = await openCreate(ctx);
          await fillAndSubmit(page);
          refuse(ctx.http.expectOne(ROLES_URL), code, 409);
          await page.settle();

          const message = RbacErrorMessages[code].body;
          expect(text(byTestId(page.el(), 'role-create-name-error'))).toBe(message);
          expect(describedByTexts(page.el(), nameInput(page.el()))).toContain(message);
          expect(text(byTestId(page.el(), 'role-create-summary'))).toContain(message);
          expect(byTestId(page.el(), 'role-create-partial')).toBeNull();

          // A new name clears the server's verdict on the old one.
          type(nameInput(page.el()), 'Auditors 2');
          await page.settle();
          expect(byTestId(page.el(), 'role-create-name-error')).toBeNull();
        },
      );

      it('RBAC_008 is a banner with the copy only: no number from the server', async () => {
        ctx = setup();
        const page = await openCreate(ctx);
        await fillAndSubmit(page);
        refuse(ctx.http.expectOne(ROLES_URL), 'RBAC_008', 409);
        await page.settle();

        const banner = byTestId(page.el(), 'role-create-limit');
        expect(text(banner)).toContain(RbacErrorMessages.RBAC_008.title);
        expect(text(banner)).toContain(RbacErrorMessages.RBAC_008.body);
        expect(text(banner)).not.toMatch(/\d/);
      });

      it('maps VALIDATION_FAILED details[] by field; an unknown field shows in the summary only', async () => {
        ctx = setup();
        const page = await openCreate(ctx);
        await fillAndSubmit(page);
        refuse(ctx.http.expectOne(ROLES_URL), 'VALIDATION_FAILED', 400, {
          details: [
            { field: 'description', message: 'must not contain control characters' },
            { field: 'tenantId', message: 'must not be set' },
          ],
        });
        await page.settle();

        expect(describedByTexts(page.el(), descriptionInput(page.el()))).toContain(
          'must not contain control characters',
        );
        const summary = text(byTestId(page.el(), 'role-create-summary'));
        expect(summary).toContain('must not contain control characters');
        expect(summary).toContain('must not be set');
        expect(byTestId(page.el(), 'role-create-name-error')).toBeNull();
      });

      it('a 403 shows the reason inline, keeps the details and re-reads the profile', async () => {
        ctx = setup();
        const page = await openCreate(ctx);
        await fillAndSubmit(page);
        refuse(ctx.http.expectOne(ROLES_URL), 'RBAC_001', 403, {
          reason: 'ADMINISTRATOR_REQUIRED',
        });
        await page.settle();

        const error = byTestId(page.el(), 'role-create-error') as HTMLElement;
        expect(error.getAttribute('role')).toBe('alert');
        expect(text(error)).toContain('Administrator needed');
        expect(ctx.profileStub.reload).toHaveBeenCalledWith('denied-predicted-allowed');
        expect(nameInput(page.el()).value).toBe('Auditors');
      });

      it('a 503 holds the submit for the wait and says so', async () => {
        ctx = setup();
        const page = await openCreate(ctx);
        await fillAndSubmit(page);
        const post = ctx.http.expectOne(ROLES_URL);
        post.flush(
          { code: 'AUTH_005', detail: 'x' },
          { status: 503, statusText: 'Unavailable', headers: { 'Retry-After': '12' } },
        );
        await page.settle();

        expect(text(byTestId(page.el(), 'role-create-error'))).toContain('Nothing was changed');
        expect(text(byTestId(page.el(), 'role-create-wait'))).toBe(
          format(CONSOLE_COPY.save.wait, { n: 12 }),
        );
        const submit = button(page.el(), 'role-create-submit');
        expect(submit?.getAttribute('aria-disabled')).toBe('true');
        submit?.click();
        await page.settle();
        ctx.http.expectNone(ROLES_URL);
      });
    });
  });

  describe('live-profile gating (ADR-0028)', () => {
    it('without role:write in the live profile there is no form, only the reason', async () => {
      ctx = setup({ held: ['role:read'] });
      const { el } = await openCreate(ctx);

      expect(text(byTestId(el(), 'role-create-blocked'))).toContain(
        CONSOLE_COPY.createRole.noWrite,
      );
      expect(byTestId(el(), 'role-create-submit')).toBeNull();
    });

    it('with the profile unavailable, Create is off with the reason and every row is disabled', async () => {
      ctx = setup({ profile: 'error' });
      const { el, settle } = await openCreate(ctx);
      type(nameInput(el()), 'Auditors');
      await settle();

      const submit = button(el(), 'role-create-submit') as HTMLButtonElement;
      expect(submit.getAttribute('aria-disabled')).toBe('true');
      expect(describedByTexts(el(), submit)).toContain(
        CONSOLE_COPY.disabledReason.profileUnavailable,
      );
      expect(box(el(), 'user:read')?.getAttribute('aria-disabled')).toBe('true');
      submit.click();
      await settle();
      ctx.http.expectNone(ROLES_URL);
    });
  });

  describe('clone (design §12.5; FR-B5)', () => {
    /** Opens the source role's page and presses Clone. */
    async function cloneFromDetail(ctx: Ctx, granted: readonly string[], source = role()) {
      const page = await open(`/admin/access/roles/${SOURCE_ID}/permissions`);
      ctx.http.expectOne(roleUrl(SOURCE_ID)).flush(source);
      ctx.http
        .expectOne(setUrl(SOURCE_ID))
        .flush(
          { data: CATALOGUE.filter((p) => granted.includes(p.name)) },
          { headers: { ETag: '"s1"' } },
        );
      flushCatalogue(ctx);
      await page.settle();
      button(page.el(), 'role-clone')?.click();
      await page.settle();
      return page;
    }

    it('reuses the source the role page read: no request, the name prefilled, the grantable permissions staged', async () => {
      ctx = setup();
      const { el } = await cloneFromDetail(ctx, ['role:read', 'tenant:read', 'user:read']);

      expect(ctx.router.url).toBe(CLONE);
      expect(ctx.http.match(() => true)).toHaveLength(0);
      expect(nameInput(el()).value).toBe('Copy of Support');
      expect(box(el(), 'role:read')?.checked).toBe(true);
      expect(box(el(), 'user:read')?.checked).toBe(true);
      expect(box(el(), 'tenant:read')?.checked).toBe(false);
    });

    it('reads the source role and set once each when nothing is cached', async () => {
      ctx = setup();
      const page = await open(CLONE);
      ctx.http.expectOne(roleUrl(SOURCE_ID)).flush(role());
      ctx.http
        .expectOne(setUrl(SOURCE_ID))
        .flush({ data: [permission('user:read')] }, { headers: { ETag: '"s1"' } });
      flushCatalogue(ctx);
      await page.settle();

      expect(nameInput(page.el()).value).toBe('Copy of Support');
      expect(box(page.el(), 'user:read')?.checked).toBe(true);
    });

    it('cuts the prefilled name to 64 characters', async () => {
      ctx = setup();
      const { el } = await cloneFromDetail(ctx, [], role({ name: 'n'.repeat(64) }));

      expect(nameInput(el()).value).toBe(`Copy of ${'n'.repeat(56)}`);
      expect(byTestId(el(), 'role-create-name-error')).toBeNull();
    });

    it('lists under "Not copied" exactly the permissions it cannot grant, with the reason', async () => {
      ctx = setup({ held: ['role:read', 'role:write', 'user:read', 'user:directory:read'] });
      const { el } = await cloneFromDetail(ctx, [
        'role:read',
        'tenant:read',
        'user:directory:read',
      ]);

      const banner = byTestId(el(), 'role-create-not-copied') as HTMLElement;
      expect(text(banner)).toContain(
        format(CONSOLE_COPY.createRole.notCopied, {
          labels: [labelOf('tenant:read'), labelOf('user:directory:read')].join(', '),
        }),
      );
      const items = [...banner.querySelectorAll('[data-testid="role-create-not-copied-item"]')];
      expect(items.map((item) => text(item))).toEqual([
        `${labelOf('tenant:read')}: ${CONSOLE_COPY.disabledReason.notHeld}`,
        `${labelOf('user:directory:read')}: ${CONSOLE_COPY.disabledReason.adminOnlyDirectory}`,
      ]);
      expect(box(el(), 'role:read')?.checked).toBe(true);
      expect(box(el(), 'tenant:read')?.checked).toBe(false);
      expect(box(el(), 'user:directory:read')?.checked).toBe(false);
    });

    it('creates the clone with the copied permissions only', async () => {
      ctx = setup();
      const page = await cloneFromDetail(ctx, ['role:read', 'tenant:read']);
      button(page.el(), 'role-create-submit')?.click();
      await page.settle();

      const post = ctx.http.expectOne(ROLES_URL);
      expect(post.request.body).toEqual({ name: 'Copy of Support', description: '' });
      post.flush(created({ name: 'Copy of Support' }), { status: 201, statusText: 'Created' });
      expectSetGet(ctx).flush({ data: [] }, { headers: { ETag: '"e0"' } });
      const put = expectPut(ctx);
      expect(put.request.body).toEqual({ permissionIds: [idOf('role:read')] });
      put.flush({ data: [permission('role:read')] }, { headers: { ETag: '"e1"' } });
      await page.settle();
      answerRolePage(ctx, ['role:read']);
      await page.settle();
    });

    it('says the source is gone when it no longer exists, with a way back', async () => {
      ctx = setup();
      const page = await open(CLONE);
      ctx.http.expectOne(setUrl(SOURCE_ID)).flush({ data: [] }, { headers: { ETag: '"s1"' } });
      refuse(ctx.http.expectOne(roleUrl(SOURCE_ID)), 'ROLE_NOT_FOUND', 404);
      flushCatalogue(ctx);
      await page.settle();

      const gone = byTestId(page.el(), 'role-create-source-gone');
      expect(text(gone)).toContain(RbacErrorMessages.ROLE_NOT_FOUND.title);
      expect(gone?.querySelector('a')?.getAttribute('href')).toBe('/admin/access/roles');
      expect(byTestId(page.el(), 'role-create-submit')).toBeNull();
    });

    it('offers Retry when the source cannot be read for another reason', async () => {
      ctx = setup();
      const page = await open(CLONE);
      ctx.http.expectOne(setUrl(SOURCE_ID)).flush({ data: [] }, { headers: { ETag: '"s1"' } });
      refuse(ctx.http.expectOne(roleUrl(SOURCE_ID)), 'INTERNAL_ERROR', 500);
      flushCatalogue(ctx);
      await page.settle();

      expect(byTestId(page.el(), 'role-create-source-error')).not.toBeNull();
      byTestId(page.el(), 'role-create-source-error')
        ?.querySelector<HTMLButtonElement>('button')
        ?.click();
      await page.settle();
      ctx.http.expectOne(roleUrl(SOURCE_ID)).flush(role());
      ctx.http.expectOne(setUrl(SOURCE_ID)).flush({ data: [] }, { headers: { ETag: '"s1"' } });
      await page.settle();
      expect(nameInput(page.el()).value).toBe('Copy of Support');
    });

    it('never logs the source name or description', async () => {
      ctx = setup();
      const page = await open(CLONE);
      ctx.http.expectOne(setUrl(SOURCE_ID)).flush({ data: [] }, { headers: { ETag: '"s1"' } });
      refuse(ctx.http.expectOne(roleUrl(SOURCE_ID)), 'INTERNAL_ERROR', 500);
      flushCatalogue(ctx);
      await page.settle();

      const logged = loggedText(ctx);
      expect(logged).toContain(SOURCE_ID);
      expect(logged).not.toContain('Support');
      expect(logged).not.toContain('Handles tickets');
    });
  });
});
