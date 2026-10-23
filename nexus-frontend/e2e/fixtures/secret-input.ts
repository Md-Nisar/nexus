import type { Locator } from '@playwright/test';

/**
 * Types an address into a field without it appearing in Playwright's step titles. `locator.fill(value)` writes the
 * value into the step title, which lands in the HTML and JSON reports that CI uploads, and
 * `tools/scan-pii.mjs` fails the build when a persona or registrant address is in them. A trace
 * (recorded on a retry) still holds the call's arguments, which the scan also catches. Setting
 * the value in the page and dispatching `input` and `change` is what the Angular forms listen to.
 */
export async function enterAddress(field: Locator, value: string): Promise<void> {
  await field.evaluate((element, text) => {
    const input = element as HTMLInputElement;
    input.value = text;
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }, value);
}
