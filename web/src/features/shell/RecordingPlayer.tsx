import { useQuery } from '@tanstack/react-query';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { BookmarkIcon, PauseIcon, PlayIcon, RotateCcwIcon } from 'lucide-react';
import { type KeyboardEvent, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '@/api/client';
import { request } from '@/api/request';
import { useTheme } from '@/app/theme';
import { Callout, ErrorState, LoadingState } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { NativeSelect } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/misc';
import { AsciicastError, applyIdleLimit, parseAsciicast } from '@/lib/asciicast';
import { cn } from '@/lib/utils';
import { CastPlayer, type PlayerSnapshot } from './castPlayer';
import { baseTerminalOptions, xtermTheme } from './xterm';

const SPEEDS = [0.5, 1, 2, 4, 8];
const DEFAULT_IDLE_LIMIT = 2;

function mmss(s: number): string {
  const t = Math.max(0, Math.floor(s));
  const h = Math.floor(t / 3600);
  const m = Math.floor((t % 3600) / 60);
  const sec = t % 60;
  return h > 0 ? `${h}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}` : `${m}:${String(sec).padStart(2, '0')}`;
}

/** Fetches a recording (asciicast v2, untrusted) and replays it read-only. */
export function RecordingPlayer({ sessionId }: { sessionId: string }) {
  const q = useQuery({
    queryKey: ['shell-recording', sessionId],
    queryFn: () =>
      request(() =>
        api.GET('/shell-sessions/{sessionId}/recording', {
          params: { path: { sessionId } },
          parseAs: 'text',
          headers: { Accept: 'application/x-asciicast, text/plain' },
        }),
      ),
    staleTime: Infinity,
    gcTime: 60_000,
    retry: false,
  });

  const parsed = useMemo(() => {
    if (typeof q.data !== 'string') return null;
    try {
      return { cast: parseAsciicast(q.data), error: null };
    } catch (e) {
      return { cast: null, error: e instanceof AsciicastError ? e.message : 'The recording could not be parsed.' };
    }
  }, [q.data]);

  if (q.isPending) return <LoadingState label="Loading recording…" />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  if (!parsed?.cast) return <Callout tone="critical" title="Invalid recording">{parsed?.error ?? 'Empty recording.'}</Callout>;
  return <Player cast={parsed.cast} />;
}

function Player({ cast }: { cast: NonNullable<ReturnType<typeof parseAsciicast>> }) {
  const el = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const playerRef = useRef<CastPlayer | null>(null);
  const { resolved } = useTheme();
  const [skipIdle, setSkipIdle] = useState(true);
  const [snap, setSnap] = useState<PlayerSnapshot>({ playing: false, position: 0, duration: 0, speed: 1 });
  const [speed, setSpeed] = useState(1);
  const themeAtMount = useRef(resolved);
  // Latest speed for player re-creation (idle toggle) without re-running the effect.
  const speedRef = useRef(speed);

  const events = useMemo(
    () => (skipIdle ? applyIdleLimit(cast.events, cast.header.idleTimeLimit ?? DEFAULT_IDLE_LIMIT) : cast.events),
    [cast, skipIdle],
  );
  const markers = useMemo(() => events.filter((e) => e.code === 'm'), [events]);

  useEffect(() => {
    const node = el.current;
    if (!node) return;
    const term = new Terminal({
      ...baseTerminalOptions(themeAtMount.current),
      cols: cast.header.width,
      rows: cast.header.height,
      disableStdin: true,
      cursorBlink: false,
      scrollback: 10000,
    });
    term.open(node);
    termRef.current = term;
    const player = new CastPlayer(
      {
        write: (d) => term.write(d),
        reset: () => term.reset(),
        resize: (c, r) => term.resize(c, r),
      },
      events,
      { cols: cast.header.width, rows: cast.header.height },
    );
    player.setSpeed(speedRef.current);
    playerRef.current = player;
    const unsub = player.subscribe(setSnap);
    return () => {
      unsub();
      player.dispose();
      playerRef.current = null;
      termRef.current = null;
      term.dispose();
    };
  }, [cast, events]);

  useEffect(() => {
    speedRef.current = speed;
    playerRef.current?.setSpeed(speed);
  }, [speed]);

  useEffect(() => {
    if (termRef.current) termRef.current.options.theme = xtermTheme(resolved);
  }, [resolved]);

  const onKey = (e: KeyboardEvent) => {
    if (e.key === ' ' || e.key === 'k') {
      e.preventDefault();
      playerRef.current?.toggle();
    } else if (e.key === 'ArrowRight') playerRef.current?.seek(snap.position + 5);
    else if (e.key === 'ArrowLeft') playerRef.current?.seek(snap.position - 5);
  };

  return (
    <div className="grid gap-2" onKeyDown={onKey}>
      {cast.skipped > 0 && (
        <p className="text-xs text-text-warning">{cast.skipped} malformed line(s) in the recording were skipped.</p>
      )}
      {cast.truncated && <p className="text-xs text-text-warning">The recording is very long; only the first part is shown.</p>}
      <div className="max-h-[60vh] overflow-auto rounded-md border p-2" style={{ background: 'var(--term-bg)' }}>
        <div ref={el} className="w-fit" aria-label="Recorded terminal output" />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" onClick={() => playerRef.current?.toggle()} aria-label={snap.playing ? 'Pause' : 'Play'} autoFocus>
          {snap.playing ? <PauseIcon /> : <PlayIcon />} {snap.playing ? 'Pause' : 'Play'}
        </Button>
        <Button size="icon-sm" variant="outline" onClick={() => playerRef.current?.seek(0)} aria-label="Restart">
          <RotateCcwIcon />
        </Button>
        <span className="w-24 text-xs tabular text-muted-foreground">
          {mmss(snap.position)} / {mmss(snap.duration)}
        </span>
        <input
          type="range"
          min={0}
          max={Math.max(0.1, snap.duration)}
          step={0.1}
          value={snap.position}
          onChange={(e) => playerRef.current?.seek(Number(e.target.value))}
          aria-label="Playback position"
          className={cn('min-w-40 flex-1 accent-[var(--primary)]')}
        />
        <NativeSelect aria-label="Speed" className="w-20" value={String(speed)} onChange={(e) => setSpeed(Number(e.target.value))}>
          {SPEEDS.map((s) => (
            <option key={s} value={s}>
              {s}×
            </option>
          ))}
        </NativeSelect>
        <label className="flex items-center gap-1.5 text-xs">
          <Checkbox checked={skipIdle} onCheckedChange={(v) => setSkipIdle(v === true)} /> Skip idle
        </label>
      </div>
      {markers.length > 0 && (
        <div className="flex flex-wrap items-center gap-1 text-xs">
          <BookmarkIcon className="size-3.5 text-muted-foreground" aria-hidden />
          {markers.slice(0, 30).map((m, i) => (
            <button
              key={i}
              type="button"
              className="rounded border px-1.5 py-0.5 hover:bg-accent"
              onClick={() => playerRef.current?.seek(m.time)}
            >
              {mmss(m.time)} {m.data.slice(0, 40)}
            </button>
          ))}
        </div>
      )}
      <p className="text-[11px] text-muted-foreground">Space: play/pause · ←/→: 5 s · Recorded input keystrokes are not displayed.</p>
    </div>
  );
}
