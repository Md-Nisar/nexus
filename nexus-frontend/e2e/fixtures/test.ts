import { BrowserContext, test as base, expect } from '@playwright/test';
import { apiBase, requireBackend } from './backend';
import { PERSONAS, PERSONA_PASSWORD, PersonaKey } from './personas';

type PersonaContextFactory = (key: PersonaKey) => Promise<BrowserContext>;

interface WorkerFixtures {
  /**
   * Returns this worker's browser context for a persona, signed in through the API on first use.
   * `context.request` shares the context's cookie jar, so the refresh cookie follows every
   * rotation. Refresh tokens rotate with reuse detection, which is why a saved `storageState`
   * (valid for one page load) or two pages refreshing one context at once would revoke the
   * token family: open one page at a time per persona context and close it at the end.
   */
  personaContext: PersonaContextFactory;
}

export const test = base.extend<object, WorkerFixtures>({
  personaContext: [
    async ({ browser }, use) => {
      const contexts = new Map<PersonaKey, BrowserContext>();
      const factory: PersonaContextFactory = async (key) => {
        const existing = contexts.get(key);
        if (existing) return existing;

        await requireBackend();
        const persona = PERSONAS[key];
        const context = await browser.newContext();
        const response = await context.request.post(`${apiBase}/api/v1/auth/login`, {
          data: { email: persona.email, password: PERSONA_PASSWORD },
        });
        if (!response.ok()) {
          await context.close();
          throw new Error(`Login failed for persona '${key}' with status ${response.status()}`);
        }
        contexts.set(key, context);
        return context;
      };
      await use(factory);
      await Promise.all([...contexts.values()].map((context) => context.close()));
    },
    { scope: 'worker' },
  ],
});

export { expect };
