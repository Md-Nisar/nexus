import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { FormControl, ReactiveFormsModule } from '@angular/forms';
import { MatIconModule } from '@angular/material/icon';
import { ThemeService } from '../../core/theme.service';
import {
  NxBadge,
  NxButton,
  NxCard,
  NxInput,
  NxSelect,
  NxTable,
  NxEmptyState,
  NxErrorState,
  NxToast,
  BadgeVariant,
  SelectOption,
  TableColumn,
  ToastVariant,
} from '../../shared/ui';

@Component({
  selector: 'app-design-system-preview',
  standalone: true,
  imports: [
    ReactiveFormsModule,
    MatIconModule,
    NxBadge,
    NxButton,
    NxCard,
    NxInput,
    NxSelect,
    NxTable,
    NxEmptyState,
    NxErrorState,
  ],
  templateUrl: './design-system-preview.component.html',
  styleUrl: './design-system-preview.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DesignSystemPreviewComponent {
  private readonly toast = inject(NxToast);
  readonly themeService = inject(ThemeService);
  readonly themeIcon = computed(() =>
    this.themeService.theme() === 'dark' ? 'light_mode' : 'dark_mode',
  );
  readonly themeLabel = computed(() =>
    this.themeService.theme() === 'dark' ? 'Switch to light mode' : 'Switch to dark mode',
  );

  // Interactive form controls
  readonly titleControl = new FormControl('');
  readonly emailControl = new FormControl('you@company.com');
  readonly errorControl = new FormControl('NXS-???');
  readonly selectControl = new FormControl('high');
  readonly disabledControl = new FormControl({ value: 'Disabled value', disabled: true });

  readonly priorityOptions: SelectOption[] = [
    { label: 'High', value: 'high' },
    { label: 'Medium', value: 'medium' },
    { label: 'Low', value: 'low' },
    { label: 'None', value: 'none' },
  ];

  readonly statusOptions: SelectOption[] = [
    { label: 'Todo', value: 'todo' },
    { label: 'In Progress', value: 'in_progress' },
    { label: 'In Review', value: 'in_review' },
    { label: 'Done', value: 'done' },
    { label: 'Cancelled', value: 'cancelled', disabled: true },
  ];

  readonly tableColumns: TableColumn[] = [
    { key: 'id', header: 'Issue', type: 'mono', sortable: true, width: '108px' },
    { key: 'title', header: 'Title', sortable: true },
    {
      key: 'status',
      header: 'Status',
      type: 'badge',
      width: '128px',
      badgeVariant: (v): BadgeVariant => {
        const map: Record<string, BadgeVariant> = {
          Done: 'success',
          'In Progress': 'primary',
          Todo: 'neutral',
        };
        return map[v as string] ?? 'neutral';
      },
    },
    {
      key: 'priority',
      header: 'Priority',
      type: 'badge',
      width: '100px',
      badgeVariant: (v): BadgeVariant => {
        const map: Record<string, BadgeVariant> = {
          High: 'error',
          Medium: 'warning',
          Low: 'neutral',
        };
        return map[v as string] ?? 'neutral';
      },
    },
  ];

  readonly tableRows = [
    { id: 'NXS-001', title: 'Establish identity data model', status: 'Done', priority: 'High' },
    {
      id: 'NXS-002',
      title: 'Design system — tokens + shared/ui',
      status: 'Done',
      priority: 'High',
    },
    { id: 'NXS-003', title: 'Self-service registration', status: 'In Progress', priority: 'High' },
    { id: 'NXS-004', title: 'API rate limiting middleware', status: 'Todo', priority: 'Medium' },
    { id: 'NXS-005', title: 'Observability pipeline', status: 'Todo', priority: 'Low' },
  ];

  readonly colorSwatches = [
    {
      group: 'Brand',
      tokens: [
        { name: 'primary', var: '--nx-color-primary' },
        { name: 'primary-hover', var: '--nx-color-primary-hover' },
        { name: 'on-primary', var: '--nx-color-on-primary', dark: true },
        { name: 'primary-surface', var: '--nx-color-primary-surface' },
      ],
    },
    {
      group: 'Surface',
      tokens: [
        { name: 'canvas', var: '--nx-color-canvas', dark: true },
        { name: 'surface', var: '--nx-color-surface' },
        { name: 'surface-2', var: '--nx-color-surface-2' },
        { name: 'surface-3', var: '--nx-color-surface-3' },
      ],
    },
    {
      group: 'Ink',
      tokens: [
        { name: 'on-surface', var: '--nx-color-on-surface', dark: true },
        { name: 'muted', var: '--nx-color-on-surface-muted', dark: true },
        { name: 'faint', var: '--nx-color-on-surface-faint', dark: true },
        { name: 'dim', var: '--nx-color-on-surface-dim', dark: true },
      ],
    },
    {
      group: 'Semantic',
      tokens: [
        { name: 'success', var: '--nx-color-success' },
        { name: 'warning', var: '--nx-color-warning' },
        { name: 'error', var: '--nx-color-error' },
        { name: 'outline', var: '--nx-color-outline' },
      ],
    },
  ];

  readonly typeScale = [
    { token: '--nx-text-xs', label: 'text-xs / 12px', sample: 'Caption text' },
    { token: '--nx-text-sm', label: 'text-sm / 13px', sample: 'Eyebrow / mono labels' },
    { token: '--nx-text-base', label: 'text-base / 14px', sample: 'Body small / button labels' },
    { token: '--nx-text-md', label: 'text-md / 16px', sample: 'Body default' },
    { token: '--nx-text-lg', label: 'text-lg / 18px', sample: 'Body large / lead text' },
    { token: '--nx-text-xl', label: 'text-xl / 20px', sample: 'Subheading' },
    { token: '--nx-text-2xl', label: 'text-2xl / 22px', sample: 'Card title' },
    { token: '--nx-text-3xl', label: 'text-3xl / 28px', sample: 'Page headline' },
  ];

  showToast(variant: ToastVariant): void {
    const messages: Record<ToastVariant, string> = {
      success: 'Changes saved successfully.',
      error: 'Could not save — please try again.',
      warning: 'Unsaved changes will be lost on navigation.',
      info: 'Email verification link has been re-sent.',
    };
    this.toast.show({ message: messages[variant], variant, action: 'Dismiss' });
  }

  retryAction(): void {
    this.toast.info('Retrying…');
  }
}
