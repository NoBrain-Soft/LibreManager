import { ArrowDownToLineIcon, DownloadIcon } from 'lucide-react';
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { api, call } from '@/api/client';
import { errorMessage } from '@/api/errors';
import { Spinner } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { sanitizeOutput } from '@/lib/text';
import { cn } from '@/lib/utils';

interface Chunk {
  id: number;
  stream: 'stdout' | 'stderr' | 'info';
  text: string;
}

const MAX_CHARS = 2_000_000;
const POLL_ACTIVE_MS = 1500;

interface Props {
  jobId: string;
  hostId: string;
  hostname: string;
  /** Target still queued/dispatched/running: keep polling. */
  active: boolean;
}

/**
 * Per-target output viewer. Polls GET …/output?after=<last id> while the
 * target is active and once more after it finished. Remount (key) to reset.
 */
export function JobOutput({ jobId, hostId, hostname, active }: Props) {
  // Chunks and the "dropped old output" flag change together (pure updater).
  const [{ chunks, truncated }, setBuffer] = useState<{ chunks: Chunk[]; truncated: boolean }>({ chunks: [], truncated: false });
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [follow, setFollow] = useState(true);
  const lastId = useRef<number | undefined>(undefined);
  const pre = useRef<HTMLPreElement>(null);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const ctrl = new AbortController();

    const fetchMore = async (): Promise<number> => {
      const after = lastId.current;
      const data = await call(
        api.GET('/jobs/{jobId}/targets/{hostId}/output', {
          params: { path: { jobId, hostId }, query: after === undefined ? {} : { after } },
          signal: ctrl.signal,
        }),
      );
      if (cancelled || data.length === 0) return 0;
      const fresh = data
        .filter((c) => lastId.current === undefined || c.id > lastId.current)
        .map((c) => ({ id: c.id, stream: c.stream, text: sanitizeOutput(c.data) }));
      if (fresh.length === 0) return 0;
      lastId.current = Math.max(...fresh.map((c) => c.id), lastId.current ?? -Infinity);
      setBuffer((prev) => {
        let next = prev.chunks.concat(fresh);
        let size = next.reduce((n, c) => n + c.text.length, 0);
        let truncated = prev.truncated;
        while (size > MAX_CHARS && next.length > 1) {
          size -= next[0]?.text.length ?? 0;
          next = next.slice(1);
          truncated = true;
        }
        return { chunks: next, truncated };
      });
      return fresh.length;
    };

    const loop = async () => {
      try {
        // Drain everything available, then wait.
        let n: number;
        let guard = 0;
        do {
          n = await fetchMore();
        } while (n > 0 && !cancelled && guard++ < 50);
        if (!cancelled) {
          setError(null);
          setLoaded(true);
        }
      } catch (e) {
        if (cancelled || (e instanceof DOMException && e.name === 'AbortError')) return;
        setError(errorMessage(e));
        setLoaded(true);
      }
      if (!cancelled && active) timer = setTimeout(() => void loop(), POLL_ACTIVE_MS);
    };
    void loop();

    return () => {
      cancelled = true;
      ctrl.abort();
      if (timer) clearTimeout(timer);
    };
  }, [jobId, hostId, active]);

  useLayoutEffect(() => {
    const el = pre.current;
    if (el && follow) el.scrollTop = el.scrollHeight;
  }, [chunks, follow]);

  const onScroll = () => {
    const el = pre.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 32;
    if (atBottom !== follow) setFollow(atBottom);
  };

  const download = () => {
    const blob = new Blob([chunks.map((c) => c.text).join('')], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `job-${jobId.slice(0, 8)}-${hostname.replace(/[^A-Za-z0-9._-]/g, '_')}.log`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <div className="flex min-h-0 flex-col">
      <div className="flex items-center gap-2 border-b px-3 py-1.5 text-xs text-muted-foreground">
        {active && <Spinner className="size-3.5" label="Receiving output" />}
        <span>{active ? 'Live output' : 'Output'}</span>
        {truncated && <span className="text-text-warning">earlier output truncated</span>}
        <div className="flex-1" />
        {!follow && (
          <Button variant="ghost" size="sm" onClick={() => setFollow(true)}>
            <ArrowDownToLineIcon /> Follow
          </Button>
        )}
        <Button variant="ghost" size="sm" onClick={download} disabled={chunks.length === 0}>
          <DownloadIcon /> Download
        </Button>
      </div>
      {error && <div className="border-b bg-critical/8 px-3 py-1.5 text-xs text-text-critical">{error}</div>}
      <pre
        ref={pre}
        onScroll={onScroll}
        tabIndex={0}
        aria-label={`Output from ${hostname}`}
        aria-live={active ? 'polite' : 'off'}
        className="h-[28rem] overflow-auto whitespace-pre-wrap break-words bg-[var(--term-bg)] p-3 font-mono text-xs leading-relaxed text-[var(--term-fg)] scrollbar-thin"
      >
        {!loaded && <span className="text-muted-foreground">Loading output…</span>}
        {loaded && chunks.length === 0 && (
          <span className="text-muted-foreground">{active ? 'Waiting for output…' : 'No output was recorded.'}</span>
        )}
        {chunks.map((c) => (
          <span
            key={c.id}
            className={cn(c.stream === 'stderr' && 'text-text-critical', c.stream === 'info' && 'italic text-muted-foreground')}
          >
            {c.text}
          </span>
        ))}
      </pre>
    </div>
  );
}
