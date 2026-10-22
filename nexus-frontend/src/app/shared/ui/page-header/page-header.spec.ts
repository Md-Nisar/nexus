import { Component, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../testing/axe';
import { NxPageHeader } from './page-header';

@Component({
  imports: [NxPageHeader],
  template: `
    <nx-page-header title="Users" [description]="description()">
      <nav slot="breadcrumb" id="crumbs">Home</nav>
      <button slot="actions" id="act">Invite</button>
    </nx-page-header>
  `,
})
class Host {
  readonly description = signal('Everyone in your tenant');
}

describe('NxPageHeader', () => {
  async function setup() {
    const fixture = TestBed.createComponent(Host);
    await fixture.whenStable();
    return fixture;
  }

  it('renders the title as the single h1, focusable programmatically only', async () => {
    const fixture = await setup();
    const headings = fixture.nativeElement.querySelectorAll('h1');
    expect(headings.length).toBe(1);
    expect(headings[0].textContent.trim()).toBe('Users');
    expect(headings[0].getAttribute('tabindex')).toBe('-1');
    expect(headings[0].getAttribute('data-testid')).toBe('nx-page-header-title');
  });

  it('renders the description when given and omits it otherwise', async () => {
    const fixture = await setup();
    const q = () =>
      fixture.nativeElement.querySelector('[data-testid="nx-page-header-description"]');
    expect(q().textContent.trim()).toBe('Everyone in your tenant');
    fixture.componentInstance.description.set('');
    await fixture.whenStable();
    expect(q()).toBeNull();
  });

  it('projects the breadcrumb and actions slots', async () => {
    const fixture = await setup();
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('.nx-page-header__breadcrumb #crumbs')).not.toBeNull();
    expect(root.querySelector('.nx-page-header__actions #act')).not.toBeNull();
  });

  it('has no axe violations', async () => {
    const fixture = await setup();
    await expect(expectNoAxeViolations(fixture.nativeElement)).resolves.toBeUndefined();
  });
});
