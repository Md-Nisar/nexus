import { Title } from '@angular/platform-browser';
import { TestBed } from '@angular/core/testing';
import { Component } from '@angular/core';
import { Router, TitleStrategy, provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { NexusTitleStrategy } from './nexus-title-strategy';

@Component({ template: '' })
class Page {}

function setup() {
  TestBed.configureTestingModule({
    providers: [
      provideRouter([
        { path: 'titled', title: 'Dashboard', component: Page },
        { path: 'untitled', component: Page },
      ]),
      { provide: TitleStrategy, useClass: NexusTitleStrategy },
    ],
  });
  return { router: TestBed.inject(Router), title: TestBed.inject(Title) };
}

describe('NexusTitleStrategy', () => {
  it('formats a route title as "{title} · Nexus"', async () => {
    const { router, title } = setup();
    await router.navigateByUrl('/titled');
    expect(title.getTitle()).toBe('Dashboard · Nexus');
  });

  it('falls back to "Nexus" for a route without a title', async () => {
    const { router, title } = setup();
    await router.navigateByUrl('/untitled');
    expect(title.getTitle()).toBe('Nexus');
  });
});
