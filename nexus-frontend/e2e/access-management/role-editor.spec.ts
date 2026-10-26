import { APIRequestContext, BrowserContext, Page, Request } from '@playwright/test';
import { expectNoSeriousA11yViolations } from '../fixtures/axe';
import { apiBase } from '../fixtures/backend';
import { expect, test } from '../fixtures/test';

// The editor renders tenant data; no trace is recorded, so nothing of it reaches the uploaded
// report (file-level: Playwright does not allow a trace override inside a group).
test.use({ trace: 'off' });

/**
 * US-020 T-011: saving a role's permissions (design §7.2, §7.3, §11.1, §12.4, §19.3).
 *
 * Every test works on its own per-worker role `e2e-w{worker}-{random}`, created through the API
 * and deleted in `afterAll`, so workers never touch each other's roles or a role a persona holds.
 * API writes use a bearer token taken from the persona context's own refresh cookie while no page
 * of that context is open (one page at a time per persona context, see `fixtures/test.ts`).
 */

/** Labels of the permissions used here (`copy/permission-labels.ts`, provisional D3). */
const LABELS = {
  'tenant:read': 'Read tenant configuration and metadata',
  'role:read': 'Read roles and their permission assignments',
  'audit:read': 'Read the authentication and audit event trail',
  'user:directory:read': 'Read the tenant user directory, including email addresses',
} as const;

type Code = keyof typeof LABELS;

const SET_PATH = /^\/api\/v1\/roles\/[^/]+\/permissions$/;

/** Roles this worker created, deleted in `afterAll`. */
const created: string[] = [];

interface PermissionPage {
  readonly data: readonly { readonly id: string; readonly name: string }[];
}

/** A small RBAC client bound to one persona's bearer token. */
interface RbacClient {
  createRole(codes: readonly Code[]): Promise<{ id: string; name: string }>;
  readSet(roleId: string): Promise<{ codes: string[]; etag: string }>;
  replace(roleId: string, codes: readonly Code[], etag: string): Promise<number>;
  deleteRole(roleId: string): Promise<number>;
}

async function rbacClient(context: BrowserContext): Promise<RbacClient> {
  const request: APIRequestContext = context.request;
  const refreshed = await request.post(`${apiBase}/api/v1/auth/refresh`);
  expect(refreshed.ok()).toBe(true);
  const session = (await refreshed.json()) as { accessToken: string; tokenType: string };
  const headers = { Authorization: `${session.tokenType} ${session.accessToken}` };

  const catalogue = await request.get(`${apiBase}/api/v1/permissions?page=0&size=100`, {
    headers,
  });
  expect(catalogue.ok()).toBe(true);
  const byName = new Map(
    ((await catalogue.json()) as PermissionPage).data.map((entry) => [entry.name, entry.id]),
  );
  const idsOf = (codes: readonly Code[]): string[] =>
    codes.map((code) => {
      const id = byName.get(code);
      if (id === undefined) throw new Error(`Permission ${code} is not in the catalogue`);
      return id;
    });

  const client: RbacClient = {
    async readSet(roleId) {
      const response = await request.get(`${apiBase}/api/v1/roles/${roleId}/permissions`, {
        headers,
      });
      expect(response.ok()).toBe(true);
      const body = (await response.json()) as PermissionPage;
      return {
        codes: body.data.map((entry) => entry.name).sort(),
        etag: response.headers()['etag'] ?? '',
      };
    },
    async replace(roleId, codes, etag) {
      const response = await request.put(`${apiBase}/api/v1/roles/${roleId}/permissions`, {
        headers: { ...headers, 'If-Match': etag },
        data: { permissionIds: idsOf(codes) },
      });
      return response.status();
    },
    async createRole(codes) {
      const name = `e2e-w${test.info().workerIndex}-${Math.random().toString(36).slice(2, 10)}`;
      const response = await request.post(`${apiBase}/api/v1/roles`, {
        headers,
        data: { name, description: 'Created by the role editor end-to-end test' },
      });
      expect(response.status()).toBe(201);
      const { id } = (await response.json()) as { id: string };
      created.push(id);
      if (codes.length > 0) {
        const { etag } = await client.readSet(id);
        expect(await client.replace(id, codes, etag)).toBe(200);
      }
      return { id, name };
    },
    async deleteRole(roleId) {
      const response = await request.delete(`${apiBase}/api/v1/roles/${roleId}`, { headers });
      return response.status();
    },
  };
  return client;
}

function checkbox(page: Page, code: Code) {
  return page.getByRole('checkbox', { name: `${LABELS[code]} (${code})`, exact: true });
}

/**
 * Toggles a permission checkbox and waits for the staged state to show. The matrix checkbox is
 * controlled by the host store, so it reflects a click only after the store updates and the view
 * renders; `locator.check()` reads the state straight after the click and fails on a slow runner.
 */
async function setChecked(page: Page, code: Code, checked: boolean): Promise<void> {
  const box = checkbox(page, code);
  if ((await box.isChecked()) === checked) {
    return;
  }
  await box.click();
  await (checked ? expect(box).toBeChecked() : expect(box).not.toBeChecked());
}

/** Deep-links into the editor of a role and waits until it offers its controls. */
async function openEditor(page: Page, roleId: string): Promise<void> {
  await page.goto(`/admin/access/roles/${roleId}/edit`);
  await expect(page.getByTestId('role-editor-footer')).toBeVisible();
}

function isSetCall(request: Request, method: string): boolean {
  return request.method() === method && SET_PATH.test(new URL(request.url()).pathname);
}

async function openReview(page: Page): Promise<void> {
  await page.getByTestId('role-editor-review').getByRole('button').click();
  await expect(page.getByTestId('role-review')).toBeVisible();
}

test.describe('role editor: save', () => {
  test.afterAll(async ({ personaContext }) => {
    if (created.length === 0) return;
    const admin = await rbacClient(await personaContext('admin'));
    for (const roleId of created.splice(0)) {
      expect([204, 404]).toContain(await admin.deleteRole(roleId));
    }
  });

  test('edit, Review and Save sends one PUT with a strong If-Match and applies the result', async ({
    personaContext,
  }) => {
    const context = await personaContext('admin');
    const admin = await rbacClient(context);
    const role = await admin.createRole(['tenant:read']);
    const page = await context.newPage();
    try {
      const puts: Request[] = [];
      page.on('request', (request) => {
        if (isSetCall(request, 'PUT')) puts.push(request);
      });
      await openEditor(page, role.id);

      await setChecked(page, 'audit:read', true);
      await setChecked(page, 'tenant:read', false);
      await expect(page.getByTestId('role-editor-counts')).toHaveText('1 to add, 1 to remove');
      await openReview(page);
      const dialog = page.getByTestId('role-review');
      await expect(dialog.getByTestId('role-review-title')).toHaveText(
        `Review changes to ${role.name}`,
      );
      await expect(dialog.getByTestId('role-review-propagation')).toHaveCount(2);

      const saved = page.waitForResponse(
        (response) => isSetCall(response.request(), 'PUT') && response.status() === 200,
      );
      await dialog.getByTestId('role-review-confirm').getByRole('button').click();
      await saved;

      await expect(dialog).toBeHidden();
      await expect(page.getByTestId('role-editor-counts')).toHaveText('0 to add, 0 to remove');
      await expect(checkbox(page, 'audit:read')).toBeChecked();
      await expect(checkbox(page, 'tenant:read')).not.toBeChecked();
      expect(puts).toHaveLength(1);
      expect(puts[0].headers()['if-match']).toMatch(/^"[^"]+"$/);
    } finally {
      await page.close();
    }
    expect((await admin.readSet(role.id)).codes).toEqual(['audit:read']);
  });

  test('with nothing staged, Review stays unavailable and nothing is sent', async ({
    personaContext,
  }) => {
    const context = await personaContext('admin');
    const role = await (await rbacClient(context)).createRole(['tenant:read']);
    const page = await context.newPage();
    try {
      let puts = 0;
      page.on('request', (request) => {
        if (isSetCall(request, 'PUT')) puts += 1;
      });
      await openEditor(page, role.id);

      // Staging and unstaging the same row leaves nothing to save.
      await setChecked(page, 'audit:read', true);
      await setChecked(page, 'audit:read', false);
      const review = page.getByTestId('role-editor-review').getByRole('button');
      await expect(review).toHaveAttribute('aria-disabled', 'true');
      // Forced: Playwright waits for an aria-disabled control; the button must swallow the press.
      await review.click({ force: true });

      await expect(page.getByTestId('role-review')).toHaveCount(0);
      expect(puts).toBe(0);
    } finally {
      await page.close();
    }
  });

  test('412: a change made elsewhere is shown and the staged work is rebased, not resubmitted', async ({
    personaContext,
  }) => {
    const context = await personaContext('admin');
    const admin = await rbacClient(context);
    const role = await admin.createRole(['tenant:read']);
    const page = await context.newPage();
    try {
      let puts = 0;
      page.on('request', (request) => {
        if (isSetCall(request, 'PUT')) puts += 1;
      });
      await openEditor(page, role.id);
      await setChecked(page, 'audit:read', true);

      // Someone else adds role:read between the load and the save.
      const { etag } = await admin.readSet(role.id);
      expect(await admin.replace(role.id, ['tenant:read', 'role:read'], etag)).toBe(200);

      await openReview(page);
      const refused = page.waitForResponse(
        (response) => isSetCall(response.request(), 'PUT') && response.status() === 412,
      );
      const reread = page.waitForResponse(
        (response) => isSetCall(response.request(), 'GET') && response.ok(),
      );
      await page.getByTestId('role-review-confirm').getByRole('button').click();
      await Promise.all([refused, reread]);

      const banner = page.getByTestId('role-editor-conflict');
      await expect(banner).toContainText('Someone else changed this role');
      await expect(banner).toContainText(`Changed by someone else: added ${LABELS['role:read']}.`);
      await expect(page.getByTestId('role-review')).toBeHidden();
      // The rebased intent: still one add, on top of the change made elsewhere.
      await expect(page.getByTestId('role-editor-counts')).toHaveText('1 to add, 0 to remove');
      await expect(checkbox(page, 'audit:read')).toBeChecked();
      await expect(checkbox(page, 'role:read')).toBeChecked();
      expect(puts).toBe(1);
    } finally {
      await page.close();
    }
    expect((await admin.readSet(role.id)).codes).toEqual(['role:read', 'tenant:read']);
  });

  test('a role manager cannot remove from a role carrying user:directory:read, and the API agrees', async ({
    personaContext,
  }) => {
    const role = await (
      await rbacClient(await personaContext('admin'))
    ).createRole(['role:read', 'user:directory:read']);
    const context = await personaContext('roleManager');
    const page = await context.newPage();
    try {
      await openEditor(page, role.id);

      const remove = checkbox(page, 'role:read');
      await expect(remove).toBeChecked();
      await expect(remove).toHaveAttribute('aria-disabled', 'true');
      await expect(remove).toHaveAccessibleDescription(
        "You can't remove permissions from this role because it includes access you don't hold.",
      );
    } finally {
      await page.close();
    }

    // A forced attempt to remove role:read anyway is refused by the server.
    const roleManager = await rbacClient(context);
    const { etag } = await roleManager.readSet(role.id);
    expect(await roleManager.replace(role.id, ['user:directory:read'], etag)).toBe(403);
  });

  for (const scheme of ['light', 'dark'] as const) {
    test(`the editor and the Review dialog have no serious accessibility violations in ${scheme} mode`, async ({
      personaContext,
    }) => {
      const context = await personaContext('admin');
      const role = await (await rbacClient(context)).createRole(['tenant:read']);
      const page = await context.newPage();
      try {
        await page.emulateMedia({ colorScheme: scheme });
        await page.addInitScript((theme) => localStorage.setItem('nx-theme', theme), scheme);
        await openEditor(page, role.id);
        await expect(page.locator('html')).toHaveAttribute('data-theme', scheme);
        await expectNoSeriousA11yViolations(page);

        await setChecked(page, 'audit:read', true);
        await openReview(page);
        await expectNoSeriousA11yViolations(page);
        await page.getByTestId('role-review-cancel').getByRole('button').click();
        await expect(page.getByTestId('role-review')).toBeHidden();
      } finally {
        await page.close();
      }
    });
  }
});
