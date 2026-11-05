// Number, unit, and time formatting shared by tables, tiles and charts.

export type MetricUnit = 'percent' | 'bytes' | 'bytes_per_second' | 'ops_per_second' | 'count' | 'seconds';

const DASH = '–';

function trimFixed(v: number, digits: number): string {
  const s = v.toFixed(digits);
  return s.includes('.') ? s.replace(/\.?0+$/, '') : s;
}

/** Digits so that values keep ~3 significant figures (1.23, 12.3, 123). */
function autoDigits(abs: number): number {
  if (abs >= 100) return 0;
  if (abs >= 10) return 1;
  return 2;
}

const IEC = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'] as const;

/** IEC binary bytes: 1536 -> "1.5 KiB". */
export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return DASH;
  const sign = n < 0 ? '-' : '';
  let v = Math.abs(n);
  let i = 0;
  while (v >= 1024 && i < IEC.length - 1) {
    v /= 1024;
    i++;
  }
  // Rounding may push 1023.99 KiB to "1024 KiB"; promote to the next unit.
  if (i < IEC.length - 1 && Number(trimFixed(v, autoDigits(v))) >= 1024) {
    v /= 1024;
    i++;
  }
  const digits = i === 0 ? 0 : autoDigits(v);
  return `${sign}${trimFixed(v, digits)} ${IEC[i]}`;
}

const SI = [
  { v: 1e12, s: 'T' },
  { v: 1e9, s: 'G' },
  { v: 1e6, s: 'M' },
  { v: 1e3, s: 'k' },
] as const;

/** Compact SI number: 1234 -> "1.23k", 0.5 -> "0.5", 42 -> "42". */
export function formatSI(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return DASH;
  const abs = Math.abs(n);
  for (const { v, s } of SI) {
    if (abs >= v * 0.9995) {
      return `${trimFixed(n / v, autoDigits(abs / v))}${s}`;
    }
  }
  return trimFixed(n, autoDigits(abs));
}

/** Human duration for a number of seconds: 0.25 -> "250 ms", 90 -> "1.5 min". */
export function formatSeconds(s: number | null | undefined): string {
  if (s === null || s === undefined || !Number.isFinite(s)) return DASH;
  const abs = Math.abs(s);
  if (abs === 0) return '0 s';
  if (abs < 1e-3) return `${trimFixed(s * 1e6, autoDigits(abs * 1e6))} µs`;
  if (abs < 1) return `${trimFixed(s * 1e3, autoDigits(abs * 1e3))} ms`;
  if (abs < 60) return `${trimFixed(s, autoDigits(abs))} s`;
  if (abs < 3600) return `${trimFixed(s / 60, autoDigits(abs / 60))} min`;
  if (abs < 86400) return `${trimFixed(s / 3600, autoDigits(abs / 3600))} h`;
  return `${trimFixed(s / 86400, autoDigits(abs / 86400))} d`;
}

export function formatPercent(v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return DASH;
  const abs = Math.abs(v);
  return `${trimFixed(v, abs >= 10 ? 0 : 1)} %`;
}

/** Format a metric value according to its MetricsResponse unit. */
export function formatMetric(v: number | null | undefined, unit: string): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return DASH;
  switch (unit as MetricUnit) {
    case 'percent':
      return formatPercent(v);
    case 'bytes':
      return formatBytes(v);
    case 'bytes_per_second':
      return `${formatBytes(v)}/s`;
    case 'ops_per_second':
      return `${formatSI(v)}/s`;
    case 'count':
      return formatSI(v);
    case 'seconds':
      return formatSeconds(v);
    default:
      return unit ? `${formatSI(v)} ${unit}` : formatSI(v);
  }
}

/** Axis tick increments that land on clean values in the displayed unit. */
export function tickIncrements(unit: string): number[] | undefined {
  const base = [1, 2, 5, 10, 20, 50, 100, 200, 500];
  if (unit === 'bytes' || unit === 'bytes_per_second') {
    const out: number[] = [];
    for (let k = 0; k < 6; k++) for (const m of base) out.push(m * 1024 ** k);
    return out;
  }
  if (unit === 'seconds') {
    return [
      1e-6, 2e-6, 5e-6, 1e-5, 2e-5, 5e-5, 1e-4, 2e-4, 5e-4,
      0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5,
      1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 14400, 43200, 86400,
    ];
  }
  return undefined;
}

// ---------------------------------------------------------------- series

export interface SeriesInput {
  label: string;
  points: readonly (readonly number[])[];
}

export interface AlignedSeries {
  /** Sorted unique timestamps (unix seconds). */
  x: number[];
  /** One array per series, null where a series has no sample. */
  ys: (number | null)[][];
}

/** Merge series with differing timestamps into uPlot's aligned format. */
export function alignSeries(series: readonly SeriesInput[]): AlignedSeries {
  const stamps = new Set<number>();
  for (const s of series) {
    for (const p of s.points) {
      const t = p[0];
      if (typeof t === 'number' && Number.isFinite(t)) stamps.add(t);
    }
  }
  const x = [...stamps].sort((a, b) => a - b);
  const index = new Map<number, number>();
  x.forEach((t, i) => index.set(t, i));
  const ys = series.map((s) => {
    const arr: (number | null)[] = new Array<number | null>(x.length).fill(null);
    for (const p of s.points) {
      const t = p[0];
      const v = p[1];
      if (typeof t !== 'number' || !Number.isFinite(t)) continue;
      const i = index.get(t);
      if (i === undefined) continue;
      arr[i] = typeof v === 'number' && Number.isFinite(v) ? v : null;
    }
    return arr;
  });
  return { x, ys };
}

const NICE_STEPS = [15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400];

/** Query step (seconds) for a time range, aiming at <= maxPoints samples. */
export function chooseStep(rangeSeconds: number, maxPoints = 300): number {
  const raw = rangeSeconds / Math.max(1, maxPoints);
  for (const s of NICE_STEPS) if (s >= raw) return s;
  return 86400;
}

// ------------------------------------------------------------------ time

export function parseDate(value: string | Date | null | undefined): Date | null {
  if (value === null || value === undefined || value === '') return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto', style: 'short' });

/** "5 min. ago", "in 2 days", "now". */
export function formatRelative(value: string | Date | null | undefined, now: number = Date.now()): string {
  const d = parseDate(value);
  if (!d) return DASH;
  const diff = (d.getTime() - now) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return diff <= 0 ? 'just now' : 'in a few seconds';
  if (abs < 45 * 60) return rtf.format(Math.round(diff / 60), 'minute');
  if (abs < 22 * 3600) return rtf.format(Math.round(diff / 3600), 'hour');
  if (abs < 26 * 86400) return rtf.format(Math.round(diff / 86400), 'day');
  if (abs < 320 * 86400) return rtf.format(Math.round(diff / (30 * 86400)), 'month');
  return rtf.format(Math.round(diff / (365 * 86400)), 'year');
}

const dtf = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  timeZoneName: 'short',
});

export function formatDateTime(value: string | Date | null | undefined): string {
  const d = parseDate(value);
  return d ? dtf.format(d) : DASH;
}

/** Compact elapsed time: 75 -> "1m 15s", 3700 -> "1h 1m", 90000 -> "1d 1h". */
export function formatElapsed(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds < 0) return DASH;
  const s = Math.floor(seconds);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
}

export function durationBetween(
  start: string | null | undefined,
  end: string | null | undefined,
  now: number = Date.now(),
): number | null {
  const a = parseDate(start);
  if (!a) return null;
  const b = parseDate(end);
  return ((b ? b.getTime() : now) - a.getTime()) / 1000;
}

const nf = new Intl.NumberFormat('en');
export function formatNumber(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return DASH;
  return nf.format(n);
}

/** Turn "pkg_upgrade" / "lastLoginUnix" / "ssh_host_keys" into "Pkg upgrade" etc. */
export function humanize(key: string): string {
  const spaced = key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_\-.]+/g, ' ')
    .trim()
    .toLowerCase();
  const fixed = spaced
    .replace(/\b(id|ip|os|cpu|mac|mtu|dns|uid|gid|pid|rss|tcp|udp|ssh|tls|fqdn|url|ttl|sha256|smtp|mfa|totp|lvm)\b/g, (w) =>
      w.toUpperCase(),
    );
  return fixed.charAt(0).toUpperCase() + fixed.slice(1);
}
