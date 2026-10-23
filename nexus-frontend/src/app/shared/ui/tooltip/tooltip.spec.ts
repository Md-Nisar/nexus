import { OverlayContainer } from '@angular/cdk/overlay';
import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../testing/axe';
import { NxTooltip } from './tooltip';

@Component({
  imports: [NxTooltip],
  template: `<button type="button" id="host" nxTooltip="Copy the link" nxTooltipPosition="below">
    Copy
  </button>`,
})
class Host {}

describe('NxTooltip', () => {
  afterEach(() => TestBed.inject(OverlayContainer).ngOnDestroy());

  async function setup() {
    const fixture = TestBed.createComponent(Host);
    await fixture.whenStable();
    const host = fixture.nativeElement.querySelector('#host') as HTMLButtonElement;
    const overlay = TestBed.inject(OverlayContainer).getContainerElement();
    return { fixture, host, overlay };
  }

  it('describes the host with the tooltip text for assistive technology', async () => {
    const { host } = await setup();
    const id = host.getAttribute('aria-describedby');
    expect(id).toBeTruthy();
    expect(document.getElementById(id as string)?.textContent).toBe('Copy the link');
  });

  it('shows on keyboard focus', async () => {
    const { fixture, host, overlay } = await setup();
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true }));
    host.focus();
    fixture.detectChanges();
    await fixture.whenStable();
    expect(overlay.textContent).toContain('Copy the link');
  });

  it('shows nothing before interaction', async () => {
    const { overlay } = await setup();
    expect(overlay.textContent).not.toContain('Copy the link');
  });

  it('has no axe violations', async () => {
    const { fixture } = await setup();
    await expect(expectNoAxeViolations(fixture.nativeElement)).resolves.toBeUndefined();
  });
});
