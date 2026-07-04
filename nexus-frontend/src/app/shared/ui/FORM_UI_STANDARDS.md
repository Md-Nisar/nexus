# Form UI Components — Documentation Standards

This document standardizes how form UI components are documented in the Nexus design system. All components in `shared/ui/` should follow these conventions.

## Documentation Structure

Each form UI component file should include:

1. **JSDoc Block** (required)
   - Component description (1-2 sentences)
   - Use cases (when to use this component)
   - Alternatives (when NOT to use this component)
   - Examples (2-3 real-world usage patterns)
   - Accessibility notes (`@accessibility`)
   - UX notes (`@ux-notes`)
   - State management notes (`@state-management`) if relevant
   - See-also references (`@see`)

2. **Input Documentation** (required for each `input()`)
   - One-line description of what the input controls
   - Type constraints or valid values
   - Default value (`@default`)
   - Example values (`@example`)

3. **Output Documentation** (required for each `output()`)
   - When the output emits
   - What event caused the emission
   - Example usage (`@example`)

4. **Slot Documentation** (required for `ng-content`)
   - What content can be projected
   - When the slot is empty vs. filled
   - Semantic guidance (use buttons, not divs)

## JSDoc Sections — Order & Format

Follow this order in JSDoc blocks:

```typescript
/**
 * [DESCRIPTION]
 * One or two sentences describing the component's purpose and visual role.
 *
 * Use `ComponentName` when:
 * - Case 1: description
 * - Case 2: description
 * - Case 3: description
 *
 * Use `AlternativeComponent` instead when:
 * - Case 1: description
 * - Case 2: description
 *
 * @example
 * // Scenario 1: basic usage
 * <nx-component prop="value">Content</nx-component>
 *
 * @example
 * // Scenario 2: with event binding
 * <nx-component [prop]="signal()" (output)="handler()">
 *   Slotted content
 * </nx-component>
 *
 * @example
 * // Scenario 3: complex integration
 * <nx-component
 *   [prop1]="value1"
 *   [prop2]="value2"
 *   (output)="handler($event)"
 * />
 *
 * @accessibility
 * - [A11y note 1] — brief explanation
 * - [A11y note 2] — brief explanation
 * - [A11y note 3] — brief explanation
 *
 * @ux-notes
 * - [UX note 1] — guidance for consumers
 * - [UX note 2] — common patterns or gotchas
 * - [UX note 3] — best practices
 *
 * @state-management
 * - [State note] — how signals/values are managed
 * - [State note] — form integration patterns
 *
 * @see {@link RelatedComponent} for related functionality
 * @see Material 3 documentation for design reference
 */
```

## Input Documentation — Format

Each `readonly input()` or `input.required()` should have:

```typescript
/**
 * [DESCRIPTION: what does this input control?]
 *
 * [CONSTRAINTS or valid values (if applicable)]
 * [When empty/null/false, what happens?]
 *
 * @example `[input]="'value'"` renders as [visual result]
 * @example `[input]="false"` hides the [feature]
 *
 * @default [default value]
 */
readonly input = input<Type>([default]);
```

### Examples

```typescript
/**
 * HTML input type attribute.
 * Common values: `text`, `email`, `password`, `number`, `tel`, `url`, `date`, `time`.
 * Controls browser validation, mobile keyboard layout, and autofill behavior.
 * @default 'text'
 */
readonly type = input<string>('text');
```

```typescript
/**
 * Error message displayed below the input in error color.
 * When non-empty, replaces hint and shifts focus to error state.
 * Parent form should bind to validation errors from FormControl.
 * @example [error]="form.get('email')?.errors?.['required'] ? 'Email is required' : ''"
 * @default ''
 */
readonly error = input<string>('');
```

## Output Documentation — Format

Each `readonly output()` should have:

```typescript
/**
 * Emitted [when event occurs / after action completes].
 * [What triggered the output?]
 * [What payload does it carry?]
 *
 * @event
 * @example (output)="handler($event)"
 */
readonly output = output<PayloadType>();
```

### Examples

```typescript
/**
 * Emitted when the input value changes.
 * Fires after every keystroke; for validation, use FormControl.valueChanges instead.
 * @event
 */
readonly valueChange = output<string>();
```

```typescript
/**
 * Emitted when the user clicks the "Try again" button.
 * Only emitted if `showRetry()` is true and button is clicked.
 * Parent should typically call a retry/reload function in response.
 * @event
 * @example (retry)="retryLoadTasks()"
 */
readonly retry = output<void>();
```

## Slot Documentation — Format

If the component accepts `ng-content`, document it as a JSDoc comment before the closing brace:

```typescript
/**
 * Optional [slot name] content slot (ng-content).
 * Typically contains [examples of what can go here].
 * Use semantic elements only; avoid generic divs with click handlers.
 * Examples:
 * - `<button nx-button (click)="action()">Label</button>`
 * - `<a routerLink="/path">Link</a>`
 * - `<span><!-- Plain text or inline content --></span>`
 * If [feature], omit ng-content entirely.
 */
// ng-content is not a field but documented here for completeness
```

### Examples

```typescript
/**
 * Optional action content slot (ng-content).
 * Typically contains a single button or link (e.g., "Create new item", "Go back").
 * Use semantic elements only; avoid generic divs with click handlers.
 * Examples:
 * - `<button nx-button (click)="create()">Create new</button>`
 * - `<a nx-button routerLink="/settings">Configure</a>`
 * If no action is needed, omit ng-content entirely.
 */
// ng-content is not a field but documented here for completeness
```

## Accessibility Standards

All form UI components must document:

- **Keyboard navigation** — how Tab, Enter, Arrow keys work
- **Screen reader support** — ARIA roles, labels, live regions
- **Focus indicators** — visible focus ring or outline
- **Semantic HTML** — native `<button>`, `<input>`, etc., not divs
- **Color contrast** — how errors, hints, disabled states appear
- **Icon treatment** — `aria-hidden="true"` on decorative icons

Example:

```typescript
/**
 * @accessibility
 * - Root element has `role="alert"` to announce error to screen readers immediately
 * - Icon marked as `aria-hidden="true"` (decorative; message conveyed by text)
 * - Title is mandatory and serves as the alert message
 * - Message provides additional context and troubleshooting steps
 * - Retry button (if present) is easily focusable and keyboard-operable
 * - ng-content slot should contain semantic action elements (buttons, links)
 * - Alert automatically announces when inserted (no need for aria-live)
 */
```

## UX Notes Standards

All form UI components must document:

- **Common usage patterns** — how consumers typically use this component
- **Configuration gotchas** — what settings might surprise users
- **Performance considerations** — lazy loading, large lists, etc.
- **Styling hooks** — CSS classes, tokens, customization points
- **Empty/error states** — how the component looks when empty or in error
- **Responsive behavior** — how the component adapts to viewport size

Example:

```typescript
/**
 * @ux-notes
 * - Component is centered with generous vertical padding; works well in full-height
 *   containers (e.g., page-height panels, modal dialogs)
 * - Icon is always "error_outline" (Material icon); use title/message for context
 * - Retry button is only shown if `showRetry()` is true; omit for unrecoverable errors
 * - Message is optional but strongly recommended; explains the error and next steps
 * - ng-content slot (action area) is typically for secondary actions (links, help buttons)
 * - Error color is determined by Material theme; maintains contrast in light and dark modes
 * - Avoid nested errors; if error occurs within an error state, replace rather than nest
 */
```

## Form Control Integration

Components that implement `ControlValueAccessor` should document:

- Constructor injection pattern (none; use signals)
- Form control type and value shape
- How validation errors are bound
- When `markAsTouched()` is called
- How disabled state is managed

Example:

```typescript
/**
 * @state-management
 * - Single-select: stores a single `T` value or null
 * - Multi-select: stores `T[]` array; empty array when no selections
 * - Disabled state managed via form control disabled flag (setDisabledState callback)
 *
 * @see {@link ControlValueAccessor} for form integration details
 */
```

## Required Sections Checklist

- [ ] Component description (1-2 sentences)
- [ ] Use cases (when to use)
- [ ] Alternatives (when NOT to use)
- [ ] 2-3 @example blocks
- [ ] @accessibility section (if interactive)
- [ ] @ux-notes section
- [ ] @state-management section (if form-related)
- [ ] @see references
- [ ] All inputs documented with @default and examples
- [ ] All outputs documented with @event and examples
- [ ] ng-content slot documented (if present)

## References

- [Angular JSDoc conventions](https://angular.io/guide/styleguide#documentation)
- [Material Design 3 form field specs](https://m3.material.io/components/text-fields/overview)
- [WCAG 2.1 accessibility guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [MDN HTML accessibility](https://developer.mozilla.org/en-US/docs/Web/Accessibility)

## Component Index

Current form UI components following these standards:

- **`NxInput`** — Text input with label, hint, error, icons (`input.ts`)
- **`NxSelect`** — Single/multi-select dropdown (`select.ts`)
- **`NxButton`** — Variant button with icons and loading state (`button.ts`)
- **`NxEmptyState`** — Empty state presentation (`empty-state.ts`)
- **`NxErrorState`** — Error state with retry action (`error-state.ts`)

Additional components (not form-specific but still documented):

- **`NxCard`** — Container component (`card.ts`)
- **`NxBadge`** — Label/status indicator (`badge.ts`)
- **`NxTable`** — Data table (`table.ts`)
- **`NxDialog`** — Modal dialog (`dialog.ts`)
- **`NxToast`** — Toast notification (`toast.ts`)
