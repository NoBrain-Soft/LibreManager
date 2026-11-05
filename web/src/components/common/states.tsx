import { CircleAlertIcon, InboxIcon, LoaderCircleIcon, LockIcon, RefreshCwIcon, type LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { errorMessage, errorTitle, isApiError } from '@/api/errors';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/misc';
import { cn } from '@/lib/utils';

export function Spinner({ className, label = 'Loading' }: { className?: string; label?: string }) {
  return <LoaderCircleIcon className={cn('size-4 animate-spin text-muted-foreground', className)} aria-label={label} />;
}

export function LoadingState({ label = 'Loading…', className }: { label?: string; className?: string }) {
  return (
    <div className={cn('flex items-center justify-center gap-2 py-10 text-sm text-muted-foreground', className)} role="status">
      <Spinner />
      <span>{label}</span>
    </div>
  );
}

export function TableSkeleton({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="grid gap-2 p-3" role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="flex gap-3">
          {Array.from({ length: cols }, (_, c) => (
            <Skeleton key={c} className={cn('h-5', c === 0 ? 'w-40' : 'flex-1')} />
          ))}
        </div>
      ))}
    </div>
  );
}

interface ErrorStateProps {
  error: unknown;
  onRetry?: () => void;
  className?: string;
  compact?: boolean;
}

export function ErrorState({ error, onRetry, className, compact }: ErrorStateProps) {
  const forbidden = isApiError(error) && error.code === 'forbidden';
  const Icon = forbidden ? LockIcon : CircleAlertIcon;
  return (
    <div
      role="alert"
      className={cn(
        'flex flex-col items-center justify-center gap-2 text-center',
        compact ? 'py-4' : 'py-10',
        className,
      )}
    >
      <Icon className={cn('size-6', forbidden ? 'text-muted-foreground' : 'text-critical')} aria-hidden />
      <div className="text-sm font-medium">{errorTitle(error)}</div>
      <p className="max-w-md text-xs text-muted-foreground">
        {forbidden ? 'Your role does not include access to this. Ask an administrator if you need it.' : errorMessage(error)}
      </p>
      {onRetry && !forbidden && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCwIcon /> Retry
        </Button>
      )}
    </div>
  );
}

/** Shown when the session lacks the permission for a page (the server enforces it too). */
export function ForbiddenState({ className }: { className?: string }) {
  return (
    <div role="alert" className={cn('flex flex-col items-center justify-center gap-2 py-10 text-center', className)}>
      <LockIcon className="size-6 text-muted-foreground" aria-hidden />
      <div className="text-sm font-medium">Access denied</div>
      <p className="max-w-md text-xs text-muted-foreground">
        Your role does not include access to this. Ask an administrator if you need it.
      </p>
    </div>
  );
}

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}

export function EmptyState({ icon: Icon = InboxIcon, title, description, action, className }: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center gap-2 py-10 text-center', className)}>
      <Icon className="size-6 text-muted-foreground/70" aria-hidden />
      <div className="text-sm font-medium">{title}</div>
      {description && <div className="max-w-md text-xs text-muted-foreground">{description}</div>}
      {action && <div className="mt-1">{action}</div>}
    </div>
  );
}

interface CalloutProps {
  tone?: 'info' | 'warning' | 'critical' | 'good';
  title?: ReactNode;
  children?: ReactNode;
  icon?: LucideIcon;
  className?: string;
  action?: ReactNode;
}

const toneClasses = {
  info: 'border-info/30 bg-info/8 [&>svg]:text-info',
  warning: 'border-warning/45 bg-warning/12 [&>svg]:text-text-warning',
  critical: 'border-critical/35 bg-critical/8 [&>svg]:text-critical',
  good: 'border-good/35 bg-good/8 [&>svg]:text-good',
};

export function Callout({ tone = 'info', title, children, icon: Icon = CircleAlertIcon, className, action }: CalloutProps) {
  return (
    <div
      role={tone === 'critical' ? 'alert' : 'status'}
      className={cn('flex items-start gap-2.5 rounded-md border px-3 py-2.5 text-sm', toneClasses[tone], className)}
    >
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="grid min-w-0 flex-1 gap-0.5">
        {title && <div className="font-medium">{title}</div>}
        {children && <div className="text-xs text-muted-foreground [&_strong]:text-foreground">{children}</div>}
      </div>
      {action}
    </div>
  );
}
