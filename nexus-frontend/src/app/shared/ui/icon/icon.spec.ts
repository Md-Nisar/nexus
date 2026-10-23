import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { NxIcon } from './icon';

describe('NxIcon', () => {
  it('renders the ligature name as a decorative icon', async () => {
    const fixture = TestBed.createComponent(NxIcon);
    fixture.componentRef.setInput('name', 'check_circle');
    await fixture.whenStable();
    const icon: HTMLElement = fixture.nativeElement.querySelector('mat-icon');
    expect(icon.textContent?.trim()).toBe('check_circle');
    expect(icon.getAttribute('aria-hidden')).toBe('true');
  });
});
