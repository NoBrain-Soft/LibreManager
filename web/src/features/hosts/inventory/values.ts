import { formatBytes, formatDateTime, humanize } from '@/lib/format';
import { num, str } from '@/lib/utils';

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function isScalar(v: unknown): v is string | number | boolean | null {
  return v === null || ['string', 'number', 'boolean'].includes(typeof v);
}

const BYTES_KEY = /(^|_)bytes$|Bytes$|^size$/;
const UNIX_KEY = /(^|_)unix$|Unix$/;

export type Formatted = { kind: 'text'; text: string } | { kind: 'bool'; value: boolean } | { kind: 'empty' };

/** Format a scalar based on its key name (e.g. memory_bytes, last_login_unix). */
export function formatValue(key: string, v: unknown): Formatted {
  if (v === null || v === undefined || v === '') return { kind: 'empty' };
  if (typeof v === 'boolean') return { kind: 'bool', value: v };
  if (BYTES_KEY.test(key)) {
    const n = num(v);
    if (n !== undefined) return { kind: 'text', text: formatBytes(n) };
  }
  if (UNIX_KEY.test(key)) {
    const n = num(v);
    if (n !== undefined) return n > 0 ? { kind: 'text', text: formatDateTime(new Date(n * 1000)) } : { kind: 'empty' };
  }
  if (Array.isArray(v)) {
    const parts = v.map((x) => str(x)).filter(Boolean);
    return parts.length ? { kind: 'text', text: parts.join(', ') } : { kind: 'empty' };
  }
  return { kind: 'text', text: str(v) };
}

/** Human label for a key, without unit suffixes the value formatting already shows. */
export function labelFor(key: string): string {
  const stripped = key.replace(/(_bytes|Bytes|_unix|Unix)$/, '');
  return humanize(stripped || key);
}

/** Text used for searching a row. */
export function rowText(row: Record<string, unknown>): string {
  return Object.values(row)
    .map((v) => (Array.isArray(v) ? v.map(str).join(' ') : str(v)))
    .join(' ')
    .toLowerCase();
}

/** Union of keys in first-seen order. */
export function columnsOf(rows: readonly Record<string, unknown>[]): string[] {
  const seen = new Set<string>();
  for (const r of rows.slice(0, 200)) for (const k of Object.keys(r)) seen.add(k);
  return [...seen];
}

/** Seconds until a *_unix timestamp (negative when in the past). */
export function secondsUntil(v: unknown, nowMs: number): number | undefined {
  const n = num(v);
  return n === undefined || n <= 0 ? undefined : n - nowMs / 1000;
}
