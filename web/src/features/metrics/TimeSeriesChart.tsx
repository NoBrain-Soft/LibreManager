import { useEffect, useMemo, useRef, useState } from 'react';
import uPlot from 'uplot';
import 'uplot/dist/uPlot.min.css';
import type { MetricsResponse } from '@/api/types';
import { cssVar, useTheme } from '@/app/theme';
import { alignSeries, formatMetric, tickIncrements } from '@/lib/format';
import { cn } from '@/lib/utils';

const MAX_SERIES = 8; // categorical palette slots; never generate a 9th hue

interface Props {
  data: MetricsResponse;
  height?: number;
  /** [start, end] in unix seconds, so the x-axis spans the selected range. */
  range: [number, number];
}

interface Prepared {
  labels: string[];
  x: number[];
  ys: (number | null)[][];
  hidden: number;
}

function prepare(data: MetricsResponse): Prepared {
  let series = data.series.filter((s) => Array.isArray(s.points));
  let hidden = 0;
  if (series.length > MAX_SERIES) {
    // Keep the 8 series with the highest peak, then order them by label so a
    // series keeps its color as long as it stays in the set.
    const peak = (pts: readonly (readonly number[])[]) => pts.reduce((m, p) => Math.max(m, Number(p[1]) || 0), -Infinity);
    hidden = series.length - MAX_SERIES;
    series = [...series].sort((a, b) => peak(b.points) - peak(a.points)).slice(0, MAX_SERIES);
    series.sort((a, b) => a.label.localeCompare(b.label));
  }
  const { x, ys } = alignSeries(series);
  return { labels: series.map((s) => s.label || 'value'), x, ys, hidden };
}

function lastValue(ys: readonly (number | null)[]): number | null {
  for (let i = ys.length - 1; i >= 0; i--) {
    const v = ys[i];
    if (v !== null && v !== undefined) return v;
  }
  return null;
}

const timeFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });

export function TimeSeriesChart({ data, height = 180, range }: Props) {
  const el = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);
  const { resolved } = useTheme();
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const [off, setOff] = useState<ReadonlySet<number>>(new Set());
  const unit = data.unit;
  const prepared = useMemo(() => prepare(data), [data]);
  const structure = `${unit}|${prepared.labels.join('\u0000')}|${resolved}|${height}`;

  // Create the plot when its structure changes (series set, unit, theme).
  useEffect(() => {
    const node = el.current;
    if (!node) return;
    const colors = Array.from({ length: MAX_SERIES }, (_, i) => cssVar(`--chart-${i + 1}`, '#2a78d6'));
    const grid = cssVar('--chart-grid', '#e8e7e1');
    const axisLine = cssVar('--chart-axis', '#c3c2b7');
    const ink = cssVar('--chart-muted', '#898781');
    const single = prepared.labels.length === 1;
    const axisFont = '11px ui-sans-serif, system-ui, sans-serif';
    const opts: uPlot.Options = {
      width: Math.max(200, node.clientWidth),
      height,
      legend: { show: false },
      padding: [8, 8, 0, 0],
      cursor: { points: { size: 8, width: 2 }, drag: { x: false, y: false } },
      scales: {
        x: { time: true },
        y:
          unit === 'percent'
            ? { range: (_u, _min, max) => [0, Math.max(100, max)] }
            : { range: (_u, min, max) => [Math.min(0, min), max > 0 ? max * 1.08 : 1] },
      },
      series: [
        {},
        ...prepared.labels.map((label, i) => ({
          label,
          stroke: colors[i],
          width: 2,
          points: { show: false },
          spanGaps: false,
          ...(single ? { fill: `${colors[0]}1a` } : {}),
        })),
      ],
      axes: [
        {
          stroke: ink,
          font: axisFont,
          grid: { stroke: grid, width: 1 },
          ticks: { stroke: axisLine, width: 1, size: 4 },
        },
        {
          stroke: ink,
          font: axisFont,
          size: 64,
          grid: { stroke: grid, width: 1 },
          ticks: { show: false },
          values: (_u, splits) => splits.map((v) => formatMetric(v, unit)),
          ...(tickIncrements(unit) ? { incrs: tickIncrements(unit) } : {}),
        },
      ],
      hooks: {
        setCursor: [
          (u) => {
            const idx = u.cursor.idx;
            setHoverIdx(idx === null || idx === undefined ? null : idx);
          },
        ],
      },
    };
    const u = new uPlot(opts, [[], ...prepared.labels.map(() => [])] as unknown as uPlot.AlignedData, node);
    plot.current = u;
    const ro = new ResizeObserver(() => {
      if (node.clientWidth > 0) u.setSize({ width: node.clientWidth, height });
    });
    ro.observe(node);
    return () => {
      ro.disconnect();
      u.destroy();
      plot.current = null;
    };
    // `structure` captures everything the options depend on.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [structure]);

  // Push new data without recreating the plot (auto-refresh keeps hover state).
  useEffect(() => {
    const u = plot.current;
    if (!u) return;
    u.setData([prepared.x, ...prepared.ys] as unknown as uPlot.AlignedData, false);
    u.setScale('x', { min: range[0], max: range[1] });
    prepared.labels.forEach((_, i) => u.setSeries(i + 1, { show: !off.has(i) }));
  }, [prepared, range, off, structure]);

  const toggle = (i: number) =>
    setOff((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });

  const hoverTime = hoverIdx !== null ? prepared.x[hoverIdx] : undefined;
  return (
    <div>
      <div ref={el} className="w-full" style={{ minHeight: height }} role="img" aria-label={`Chart: ${prepared.labels.join(', ')}`} />
      <div className="mt-2 flex items-baseline justify-between gap-2 text-[11px] text-muted-foreground">
        <span>{hoverTime !== undefined ? timeFmt.format(new Date(hoverTime * 1000)) : 'Latest'}</span>
        {prepared.hidden > 0 && <span>{prepared.hidden} more series not shown (top 8 by peak)</span>}
      </div>
      <ul className="mt-1 grid grid-cols-[repeat(auto-fill,minmax(10rem,1fr))] gap-x-4 gap-y-0.5 text-xs">
        {prepared.labels.map((label, i) => {
          const ys = prepared.ys[i] ?? [];
          const v = hoverIdx !== null ? (ys[hoverIdx] ?? null) : lastValue(ys);
          const isOff = off.has(i);
          return (
            <li key={label}>
              <button
                type="button"
                onClick={() => toggle(i)}
                aria-pressed={!isOff}
                title={isOff ? 'Show series' : 'Hide series'}
                className={cn('flex w-full items-center gap-1.5 rounded px-0.5 text-left hover:bg-accent', isOff && 'opacity-45')}
              >
                <span className="h-0.5 w-3 shrink-0 rounded-full" style={{ background: `var(--chart-${i + 1})` }} aria-hidden />
                <span className="min-w-0 flex-1 truncate text-muted-foreground">{label}</span>
                <span className="tabular text-foreground">{formatMetric(v, unit)}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
