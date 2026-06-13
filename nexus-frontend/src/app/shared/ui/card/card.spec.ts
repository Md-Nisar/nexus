import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect } from 'vitest';
import { NxCard } from './card';

describe('NxCard', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [NxCard],
      providers: [provideAnimationsAsync()],
    });
  });

  it('renders card element', () => {
    const fixture = TestBed.createComponent(NxCard);
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('[data-testid="nx-card"]'))).toBeTruthy();
  });

  it('applies raised elevation class by default', () => {
    const fixture = TestBed.createComponent(NxCard);
    fixture.detectChanges();
    const card = fixture.debugElement.query(By.css('[data-testid="nx-card"]'));
    expect(card.nativeElement.classList).toContain('nx-card--raised');
  });

  it('applies flat elevation class when flat', () => {
    const fixture = TestBed.createComponent(NxCard);
    fixture.componentRef.setInput('elevation', 'flat');
    fixture.detectChanges();
    const card = fixture.debugElement.query(By.css('[data-testid="nx-card"]'));
    expect(card.nativeElement.classList).toContain('nx-card--flat');
  });

  it('renders title when provided', () => {
    const fixture = TestBed.createComponent(NxCard);
    fixture.componentRef.setInput('title', 'My Card');
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('My Card');
  });
});
