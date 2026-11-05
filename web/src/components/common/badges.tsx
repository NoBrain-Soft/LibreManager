import {
  BanIcon,
  CircleCheckIcon,
  CircleDotIcon,
  CircleIcon,
  CircleXIcon,
  ClockIcon,
  HourglassIcon,
  LoaderCircleIcon,
  type LucideIcon,
  SendIcon,
  ShieldXIcon,
  TimerOffIcon,
  TriangleAlertIcon,
  InfoIcon,
  CircleSlashIcon,
  RotateCwIcon,
} from 'lucide-react';
import type { JobStatus, JobTargetStatus } from '@/api/types';
import { Badge } from '@/components/ui/badge';
import type { BadgeVariantProps } from '@/components/ui/variants';
import { cn } from '@/lib/utils';

type Variant = NonNullable<BadgeVariantProps['variant']>;

interface StatusSpec {
  label: string;
  variant: Variant;
  icon: LucideIcon;
  spin?: boolean;
}

function StatusBadge({ spec, className, title }: { spec: StatusSpec; className?: string; title?: string }) {
  const Icon = spec.icon;
  return (
    <Badge variant={spec.variant} className={className} title={title}>
      <Icon className={cn(spec.spin && 'animate-spin')} aria-hidden />
      {spec.label}
    </Badge>
  );
}

export function ConnectionBadge({ connected, status }: { connected: boolean; status?: string }) {
  if (status === 'decommissioned') return <StatusBadge spec={{ label: 'Decommissioned', variant: 'neutral', icon: BanIcon }} />;
  if (status === 'disabled') return <StatusBadge spec={{ label: 'Disabled', variant: 'neutral', icon: CircleSlashIcon }} />;
  return connected ? (
    <StatusBadge spec={{ label: 'Connected', variant: 'good', icon: CircleDotIcon }} />
  ) : (
    <StatusBadge spec={{ label: 'Offline', variant: 'serious', icon: CircleIcon }} />
  );
}

const jobStatus: Record<JobStatus, StatusSpec> = {
  running: { label: 'Running', variant: 'info', icon: LoaderCircleIcon, spin: true },
  succeeded: { label: 'Succeeded', variant: 'good', icon: CircleCheckIcon },
  failed: { label: 'Failed', variant: 'critical', icon: CircleXIcon },
  partial: { label: 'Partial', variant: 'warning', icon: TriangleAlertIcon },
  canceled: { label: 'Canceled', variant: 'neutral', icon: BanIcon },
};

export function JobStatusBadge({ status }: { status: string }) {
  const spec = jobStatus[status as JobStatus] ?? { label: status, variant: 'neutral', icon: CircleIcon };
  return <StatusBadge spec={spec} />;
}

const targetStatus: Record<JobTargetStatus, StatusSpec> = {
  queued: { label: 'Queued', variant: 'neutral', icon: ClockIcon },
  dispatched: { label: 'Dispatched', variant: 'info', icon: SendIcon },
  running: { label: 'Running', variant: 'info', icon: LoaderCircleIcon, spin: true },
  succeeded: { label: 'Succeeded', variant: 'good', icon: CircleCheckIcon },
  failed: { label: 'Failed', variant: 'critical', icon: CircleXIcon },
  rejected: { label: 'Rejected', variant: 'critical', icon: ShieldXIcon },
  canceled: { label: 'Canceled', variant: 'neutral', icon: BanIcon },
  timed_out: { label: 'Timed out', variant: 'warning', icon: TimerOffIcon },
  expired: { label: 'Expired', variant: 'warning', icon: HourglassIcon },
};

export function TargetStatusBadge({ status, title }: { status: string; title?: string }) {
  const spec = targetStatus[status as JobTargetStatus] ?? { label: status, variant: 'neutral', icon: CircleIcon };
  return <StatusBadge spec={spec} {...(title ? { title } : {})} />;
}

const severity: Record<string, StatusSpec> = {
  critical: { label: 'Critical', variant: 'critical', icon: CircleXIcon },
  high: { label: 'High', variant: 'serious', icon: TriangleAlertIcon },
  serious: { label: 'Serious', variant: 'serious', icon: TriangleAlertIcon },
  warning: { label: 'Warning', variant: 'warning', icon: TriangleAlertIcon },
  medium: { label: 'Medium', variant: 'warning', icon: TriangleAlertIcon },
  low: { label: 'Low', variant: 'neutral', icon: InfoIcon },
  info: { label: 'Info', variant: 'info', icon: InfoIcon },
};

export function SeverityBadge({ severity: sev }: { severity: string | undefined }) {
  const key = (sev ?? '').toLowerCase();
  const spec = severity[key] ?? { label: sev || 'Unknown', variant: 'neutral', icon: InfoIcon };
  return <StatusBadge spec={spec} />;
}

const checkStatus: Record<string, StatusSpec> = {
  pass: { label: 'Pass', variant: 'good', icon: CircleCheckIcon },
  fail: { label: 'Fail', variant: 'critical', icon: CircleXIcon },
  warn: { label: 'Warn', variant: 'warning', icon: TriangleAlertIcon },
  na: { label: 'N/A', variant: 'neutral', icon: CircleSlashIcon },
  error: { label: 'Error', variant: 'serious', icon: TriangleAlertIcon },
};

export function CheckStatusBadge({ status }: { status: string }) {
  return <StatusBadge spec={checkStatus[status] ?? { label: status, variant: 'neutral', icon: CircleIcon }} />;
}

export function AlertStatusBadge({ status }: { status: string }) {
  return status === 'firing' ? (
    <StatusBadge spec={{ label: 'Firing', variant: 'critical', icon: TriangleAlertIcon }} />
  ) : (
    <StatusBadge spec={{ label: 'Resolved', variant: 'good', icon: CircleCheckIcon }} />
  );
}

export function RebootBadge() {
  return <StatusBadge spec={{ label: 'Reboot required', variant: 'warning', icon: RotateCwIcon }} />;
}

export function YesNo({ value, yes = 'Allowed', no = 'Denied' }: { value: boolean; yes?: string; no?: string }) {
  return value ? (
    <StatusBadge spec={{ label: yes, variant: 'good', icon: CircleCheckIcon }} />
  ) : (
    <StatusBadge spec={{ label: no, variant: 'neutral', icon: BanIcon }} />
  );
}
