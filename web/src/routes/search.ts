// URL search-param validators. Never trust the URL: unknown values are dropped.

import type { HostStatus } from '@/api/types';

type Raw = Record<string, unknown>;

function str(v: unknown, max = 128): string | undefined {
  return typeof v === 'string' && v !== '' ? v.slice(0, max) : undefined;
}

function oneOf<T extends string>(v: unknown, allowed: readonly T[]): T | undefined {
  return typeof v === 'string' && (allowed as readonly string[]).includes(v) ? (v as T) : undefined;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function uuid(v: unknown): string | undefined {
  return typeof v === 'string' && UUID.test(v) ? v : undefined;
}

function compact<T extends object>(o: T): T {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T;
}

export interface LoginSearch {
  redirect?: string;
}
export function validateLoginSearch(s: Raw): LoginSearch {
  return compact({ redirect: str(s.redirect, 2048) });
}

export interface HostsSearch {
  q?: string;
  status?: HostStatus;
  group?: string;
  conn?: 'connected' | 'offline';
  updates?: 'any' | 'security' | 'reboot';
}
export function validateHostsSearch(s: Raw): HostsSearch {
  return compact({
    q: str(s.q),
    status: oneOf(s.status, ['active', 'disabled', 'decommissioned'] as const),
    group: uuid(s.group),
    conn: oneOf(s.conn, ['connected', 'offline'] as const),
    updates: oneOf(s.updates, ['any', 'security', 'reboot'] as const),
  });
}

export interface AlertsSearch {
  status?: 'firing' | 'resolved' | 'all';
}
export function validateAlertsSearch(s: Raw): AlertsSearch {
  return compact({ status: oneOf(s.status, ['firing', 'resolved', 'all'] as const) });
}

export interface JobDetailSearch {
  target?: string;
}
export function validateJobDetailSearch(s: Raw): JobDetailSearch {
  return compact({ target: uuid(s.target) });
}

export interface InventorySearch {
  section?: string;
}
export function validateInventorySearch(s: Raw): InventorySearch {
  const v = str(s.section, 64);
  return compact({ section: v && /^[a-z0-9_]+$/i.test(v) ? v : undefined });
}

export interface ShellSessionsSearch {
  host?: string;
}
export function validateShellSessionsSearch(s: Raw): ShellSessionsSearch {
  return compact({ host: uuid(s.host) });
}
