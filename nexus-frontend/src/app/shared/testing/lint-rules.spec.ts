import { ESLint } from 'eslint';
import { describe, expect, it } from 'vitest';

async function ruleIds(filePath: string, source: string): Promise<readonly string[]> {
  const eslint = new ESLint();
  const [result] = await eslint.lintText(source, { filePath });
  return result.messages.map((m) => m.ruleId ?? 'parse-error');
}

const FEATURE = 'src/app/features/lint-fixture/lint-fixture.component.ts';

describe('security lint rules (RC-62)', () => {
  it('rejects [innerHTML] in an inline template', async () => {
    const source = `import { Component } from '@angular/core';
@Component({ selector: 'app-fixture', template: '<div [innerHTML]="html"></div>' })
export class LintFixture { html = ''; }
`;
    expect(await ruleIds(FEATURE, source)).toContain('no-restricted-syntax');
  });

  it('rejects [innerHTML] in an external template', async () => {
    const ids = await ruleIds(
      'src/app/features/lint-fixture/lint-fixture.component.html',
      '<div [innerHTML]="html"></div>\n',
    );
    expect(ids).toContain('no-restricted-syntax');
  });

  it('rejects nativeElement.innerHTML', async () => {
    const source = `export function f(ref: { nativeElement: HTMLElement }): void {
  ref.nativeElement.innerHTML = 'x';
}
`;
    expect(await ruleIds(FEATURE, source)).toContain('no-restricted-syntax');
  });

  it('rejects bypassSecurityTrust*', async () => {
    const source = `export function f(s: { bypassSecurityTrustHtml(v: string): unknown }): unknown {
  return s.bypassSecurityTrustHtml('x');
}
`;
    expect(await ruleIds(FEATURE, source)).toContain('no-restricted-syntax');
  });

  it.each([
    [
      'bracket access to innerHTML',
      `export function f(el: HTMLElement): void { el['innerHTML'] = 'x'; }`,
    ],
    [
      'bracket access to outerHTML',
      `export function f(el: HTMLElement): void { el['outerHTML'] = 'x'; }`,
    ],
    [
      'insertAdjacentHTML',
      `export function f(el: HTMLElement): void { el.insertAdjacentHTML('beforeend', 'x'); }`,
    ],
    [
      'bracket insertAdjacentHTML',
      `export function f(el: HTMLElement): void { el['insertAdjacentHTML']('beforeend', 'x'); }`,
    ],
    ['createContextualFragment', `export const f = (r: Range) => r.createContextualFragment('x');`],
    ['document.write', `export function f(): void { document.write('x'); }`],
    [
      'destructured innerHTML',
      `export function f(el: HTMLElement): void { Object.assign(el, { innerHTML: 'x' }); }`,
    ],
    [
      'destructured bypassSecurityTrust*',
      `export function f(s: { bypassSecurityTrustHtml(v: string): unknown }): unknown {
  const { bypassSecurityTrustHtml } = s;
  return bypassSecurityTrustHtml('x');
}`,
    ],
    [
      'aliased bypassSecurityTrust*',
      `export function f(s: { bypassSecurityTrustUrl(v: string): unknown }): unknown {
  const trust = s.bypassSecurityTrustUrl;
  return trust('x');
}`,
    ],
    [
      'bracket bypassSecurityTrust*',
      `export function f(s: Record<string, (v: string) => unknown>): unknown {
  return s['bypassSecurityTrustHtml']('x');
}`,
    ],
  ])('rejects %s', async (_name, source) => {
    expect(await ruleIds(FEATURE, `${source}\n`)).toContain('no-restricted-syntax');
  });

  it('rejects Material imports from a feature', async () => {
    const source = `import { MatButtonModule } from '@angular/material/button';
export const m = MatButtonModule;
`;
    expect(await ruleIds(FEATURE, source)).toContain('no-restricted-imports');
  });

  it('rejects CDK imports from a feature', async () => {
    const source = `import { A11yModule } from '@angular/cdk/a11y';
export const m = A11yModule;
`;
    expect(await ruleIds(FEATURE, source)).toContain('no-restricted-imports');
  });

  it('allows Material imports inside shared/ui', async () => {
    const source = `import { MatButtonModule } from '@angular/material/button';
export const m = MatButtonModule;
`;
    expect(await ruleIds('src/app/shared/ui/lint-fixture/lint-fixture.ts', source)).not.toContain(
      'no-restricted-imports',
    );
  });
});
