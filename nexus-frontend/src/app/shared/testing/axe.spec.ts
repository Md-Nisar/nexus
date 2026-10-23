import { afterEach, describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from './axe';

describe('expectNoAxeViolations', () => {
  let host: HTMLElement;

  function render(label: string): HTMLElement {
    host = document.createElement('main');
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = label;
    host.appendChild(button);
    document.body.appendChild(host);
    return host;
  }

  afterEach(() => host.remove());

  it('passes for an accessible fixture', async () => {
    const el = render('Save');
    await expect(expectNoAxeViolations(el)).resolves.toBeUndefined();
  });

  it('fails for an unlabelled button', async () => {
    const el = render('');
    await expect(expectNoAxeViolations(el)).rejects.toThrow(/button-name/);
  });
});
