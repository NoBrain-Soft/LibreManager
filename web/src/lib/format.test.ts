import { describe, expect, it } from 'vitest';
import {
  alignSeries,
  chooseStep,
  durationBetween,
  formatBytes,
  formatElapsed,
  formatMetric,
  formatPercent,
  formatRelative,
  formatSI,
  formatSeconds,
  humanize,
  tickIncrements,
} from './format';

describe('formatBytes (IEC)', () => {
  it.each([
    [0, '0 B'],
    [512, '512 B'],
    [1023, '1023 B'],
    [1024, '1 KiB'],
    [1536, '1.5 KiB'],
    [10 * 1024 + 300, '10.3 KiB'],
    [1024 ** 2 * 250, '250 MiB'],
    [1024 ** 3 * 7.25, '7.25 GiB'],
    [1024 ** 4 * 2, '2 TiB'],
    [1024 * 1024 - 1, '1 MiB'],
    [-2048, '-2 KiB'],
  ])('%d -> %s', (n, s) => {
    expect(formatBytes(n)).toBe(s);
  });

  it('renders missing values as a dash', () => {
    expect(formatBytes(null)).toBe('–');
    expect(formatBytes(Number.NaN)).toBe('–');
  });
});

describe('formatSI', () => {
  it.each([
    [0, '0'],
    [0.5, '0.5'],
    [42, '42'],
    [999, '999'],
    [1000, '1k'],
    [1234, '1.23k'],
    [12_345, '12.3k'],
    [1_500_000, '1.5M'],
    [2e9, '2G'],
    [-1500, '-1.5k'],
  ])('%d -> %s', (n, s) => {
    expect(formatSI(n)).toBe(s);
  });
});

describe('formatSeconds', () => {
  it.each([
    [0, '0 s'],
    [0.0000025, '2.5 µs'],
    [0.25, '250 ms'],
    [1.5, '1.5 s'],
    [90, '1.5 min'],
    [7200, '2 h'],
    [3 * 86400, '3 d'],
  ])('%d -> %s', (n, s) => {
    expect(formatSeconds(n)).toBe(s);
  });
});

describe('formatMetric by unit', () => {
  it.each([
    [42.123, 'percent', '42 %'],
    [3.14, 'percent', '3.1 %'],
    [1024 ** 3, 'bytes', '1 GiB'],
    [5 * 1024 ** 2, 'bytes_per_second', '5 MiB/s'],
    [1234, 'ops_per_second', '1.23k/s'],
    [17, 'count', '17'],
    [0.002, 'seconds', '2 ms'],
    [5, 'widgets', '5 widgets'],
    [5, '', '5'],
  ])('%d %s -> %s', (v, unit, s) => {
    expect(formatMetric(v, unit)).toBe(s);
  });

  it('handles null', () => {
    expect(formatMetric(null, 'bytes')).toBe('–');
    expect(formatPercent(undefined)).toBe('–');
  });
});

describe('tickIncrements', () => {
  it('provides binary-friendly increments for byte units', () => {
    const incrs = tickIncrements('bytes')!;
    expect(incrs).toContain(1024);
    expect(incrs).toContain(200 * 1024 ** 2);
    expect(incrs.every((v, i) => i === 0 || v > incrs[i - 1]!)).toBe(true);
    // every increment formats to a clean label
    for (const v of incrs) expect(formatBytes(v)).toMatch(/^\d+ [KMGTP]?i?B$/);
  });

  it('provides time-friendly increments for seconds and none otherwise', () => {
    expect(tickIncrements('seconds')).toContain(60);
    expect(tickIncrements('percent')).toBeUndefined();
  });
});

describe('alignSeries', () => {
  it('merges differing timestamps and fills gaps with null', () => {
    const out = alignSeries([
      { label: 'a', points: [[10, 1], [20, 2], [30, 3]] },
      { label: 'b', points: [[20, 5], [40, 6]] },
    ]);
    expect(out.x).toEqual([10, 20, 30, 40]);
    expect(out.ys).toEqual([
      [1, 2, 3, null],
      [null, 5, null, 6],
    ]);
  });

  it('drops malformed points and maps non-finite values to null', () => {
    const out = alignSeries([{ label: 'a', points: [[10, Number.NaN], [Number.NaN, 2], [20], [30, 3]] }]);
    expect(out.x).toEqual([10, 20, 30]);
    expect(out.ys).toEqual([[null, null, 3]]);
  });

  it('handles no series', () => {
    expect(alignSeries([])).toEqual({ x: [], ys: [] });
  });
});

describe('chooseStep', () => {
  it.each([
    [3600, 15],
    [6 * 3600, 120],
    [24 * 3600, 300],
    [7 * 86400, 3600],
    [30 * 86400, 10800],
    [10 * 365 * 86400, 86400],
  ])('range %d -> step %d', (range, step) => {
    expect(chooseStep(range)).toBe(step);
  });
});

describe('time helpers', () => {
  const now = Date.parse('2026-11-05T12:00:00Z');
  it.each([
    ['2026-11-05T11:59:50Z', 'just now'],
    ['2026-11-05T11:55:00Z', '5 min. ago'],
    ['2026-11-05T09:00:00Z', '3 hr. ago'],
    ['2026-11-03T12:00:00Z', '2 days ago'],
    ['2026-11-07T12:00:00Z', 'in 2 days'],
  ])('formatRelative(%s) = %s', (iso, s) => {
    expect(formatRelative(iso, now)).toBe(s);
  });

  it('formatRelative handles missing/invalid', () => {
    expect(formatRelative(null, now)).toBe('–');
    expect(formatRelative('not a date', now)).toBe('–');
  });

  it('formatElapsed', () => {
    expect(formatElapsed(5)).toBe('5s');
    expect(formatElapsed(75)).toBe('1m 15s');
    expect(formatElapsed(3700)).toBe('1h 1m');
    expect(formatElapsed(90000)).toBe('1d 1h');
    expect(formatElapsed(-1)).toBe('–');
  });

  it('durationBetween uses now for open intervals', () => {
    expect(durationBetween('2026-11-05T11:00:00Z', '2026-11-05T11:01:30Z', now)).toBe(90);
    expect(durationBetween('2026-11-05T11:00:00Z', null, now)).toBe(3600);
    expect(durationBetween(null, null, now)).toBeNull();
  });
});

describe('humanize', () => {
  it.each([
    ['pkg_upgrade', 'Pkg upgrade'],
    ['shell_allow_root', 'Shell allow root'],
    ['lastLoginUnix', 'Last login unix'],
    ['ssh_host_keys', 'SSH host keys'],
    ['cpu_model', 'CPU model'],
    ['fingerprint_sha256', 'Fingerprint SHA256'],
  ])('%s -> %s', (k, s) => {
    expect(humanize(k)).toBe(s);
  });
});
