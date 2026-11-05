import type { JobParams, JobType } from '@/api/types';
import type { Permission } from '@/lib/permissions';

export const JOB_TYPES: readonly JobType[] = [
  'pkg_refresh',
  'pkg_upgrade',
  'pkg_install',
  'pkg_remove',
  'service',
  'reboot',
  'run_check',
  'collect_inventory',
];

/** Permission needed per job type (UI gating only; the server decides). */
export const JOB_PERMISSION: Readonly<Record<JobType, Permission>> = {
  pkg_refresh: 'pkg.refresh',
  pkg_upgrade: 'pkg.upgrade',
  pkg_install: 'pkg.install',
  pkg_remove: 'pkg.install',
  service: 'service.control',
  reboot: 'host.reboot',
  run_check: 'security.manage',
  collect_inventory: 'host.manage',
};

export const SERVICE_OPS = ['start', 'stop', 'restart', 'reload', 'enable', 'disable'] as const;
export type ServiceOp = (typeof SERVICE_OPS)[number];

const PACKAGE_RE = /^[A-Za-z0-9][A-Za-z0-9._+:~@=-]{0,127}$/;
const UNIT_RE = /^[A-Za-z0-9@:._\\-]{1,256}$/;
const CHECK_RE = /^[A-Za-z0-9._-]{1,32}$/;

export function splitList(input: string): string[] {
  return [...new Set(input.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean))];
}

export interface JobFormValues {
  type: JobType;
  scope: 'all' | 'security' | 'named';
  packages: string;
  unit: string;
  op: ServiceOp;
  delay: string;
  message: string;
  checkIds: string;
}

/** Validate and build JobParams; returns an error message instead when invalid. */
export function buildParams(v: JobFormValues): { params?: JobParams; error?: string } {
  switch (v.type) {
    case 'pkg_upgrade': {
      if (v.scope !== 'named') return { params: { scope: v.scope } };
      const pkgs = splitList(v.packages);
      const err = validatePackages(pkgs);
      return err ? { error: err } : { params: { scope: 'named', packages: pkgs } };
    }
    case 'pkg_install':
    case 'pkg_remove': {
      const pkgs = splitList(v.packages);
      const err = validatePackages(pkgs);
      return err ? { error: err } : { params: { packages: pkgs } };
    }
    case 'service': {
      const unit = v.unit.trim();
      if (!UNIT_RE.test(unit)) return { error: 'Enter a valid systemd unit name, e.g. nginx.service.' };
      return { params: { unit, op: v.op } };
    }
    case 'reboot': {
      const delay = Number(v.delay || '0');
      if (!Number.isInteger(delay) || delay < 0 || delay > 3600) return { error: 'Delay must be 0–3600 seconds.' };
      const message = v.message.trim();
      if (message.length > 256) return { error: 'Message is limited to 256 characters.' };
      return { params: { delay_s: delay, ...(message ? { message } : {}) } };
    }
    case 'run_check': {
      const ids = splitList(v.checkIds);
      if (ids.length > 200) return { error: 'At most 200 check IDs.' };
      const bad = ids.find((id) => !CHECK_RE.test(id));
      if (bad) return { error: `Invalid check ID "${bad}".` };
      return { params: ids.length ? { check_ids: ids } : {} };
    }
    default:
      return { params: {} };
  }
}

function validatePackages(pkgs: string[]): string | undefined {
  if (pkgs.length === 0) return 'Enter at least one package name.';
  if (pkgs.length > 500) return 'At most 500 packages per job.';
  const bad = pkgs.find((p) => !PACKAGE_RE.test(p));
  return bad ? `Invalid package name "${bad}".` : undefined;
}
