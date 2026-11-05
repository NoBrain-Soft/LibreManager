// Parser for asciicast recordings (https://docs.asciinema.org/manual/asciicast/v2/).
//
// The API returns decrypted asciicast v2 (newline-delimited JSON: a header
// object followed by `[time, code, data]` event arrays with absolute times).
// v3 (relative intervals, `term` object) is accepted as well so a future
// server change does not break playback. Recordings are untrusted input: the
// parser never evaluates anything, bounds the number of events, skips
// malformed lines (e.g. a truncated last line of a killed session) and
// reports how many were skipped.

export class AsciicastError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AsciicastError';
  }
}

export interface AsciicastHeader {
  version: 2 | 3;
  width: number;
  height: number;
  timestamp?: number;
  title?: string;
  idleTimeLimit?: number;
  env?: Record<string, string>;
}

/** o = output, i = input, r = resize ("COLSxROWS"), m = marker, x = exit (v3). */
export type AsciicastEventCode = 'o' | 'i' | 'r' | 'm' | 'x';

export interface AsciicastEvent {
  /** Seconds since the start of the recording (absolute, non-decreasing). */
  time: number;
  code: AsciicastEventCode;
  data: string;
}

export interface Asciicast {
  header: AsciicastHeader;
  events: AsciicastEvent[];
  /** Time of the last event in seconds. */
  duration: number;
  /** Number of malformed or unknown lines that were ignored. */
  skipped: number;
  /** True when maxEvents was reached and the rest was dropped. */
  truncated: boolean;
}

export interface ParseOptions {
  /** Upper bound on events kept (default 2,000,000). */
  maxEvents?: number;
}

const KNOWN_CODES = new Set<string>(['o', 'i', 'r', 'm', 'x']);
const MAX_DIMENSION = 10000;

function positiveInt(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isInteger(v) && v > 0 && v <= MAX_DIMENSION ? v : undefined;
}

function parseHeader(line: string): AsciicastHeader {
  let raw: unknown;
  try {
    raw = JSON.parse(line);
  } catch {
    throw new AsciicastError('Recording header is not valid JSON.');
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new AsciicastError('Recording header must be a JSON object.');
  }
  const h = raw as Record<string, unknown>;
  const version = h.version;
  let width: number | undefined;
  let height: number | undefined;
  if (version === 2) {
    width = positiveInt(h.width);
    height = positiveInt(h.height);
  } else if (version === 3) {
    const term = typeof h.term === 'object' && h.term !== null ? (h.term as Record<string, unknown>) : {};
    width = positiveInt(term.cols);
    height = positiveInt(term.rows);
  } else {
    throw new AsciicastError(`Unsupported asciicast version: ${String(version)}.`);
  }
  if (width === undefined || height === undefined) {
    throw new AsciicastError('Recording header has an invalid terminal size.');
  }
  const header: AsciicastHeader = { version, width, height };
  if (typeof h.timestamp === 'number' && Number.isFinite(h.timestamp)) header.timestamp = h.timestamp;
  if (typeof h.title === 'string') header.title = h.title;
  if (typeof h.idle_time_limit === 'number' && h.idle_time_limit > 0) header.idleTimeLimit = h.idle_time_limit;
  if (typeof h.env === 'object' && h.env !== null && !Array.isArray(h.env)) {
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(h.env as Record<string, unknown>)) {
      if (typeof v === 'string') env[k] = v;
    }
    header.env = env;
  }
  return header;
}

export function parseAsciicast(text: string, options: ParseOptions = {}): Asciicast {
  const maxEvents = options.maxEvents ?? 2_000_000;
  const lines = text.split('\n');
  let i = 0;
  // Skip leading blank lines (and BOM).
  while (i < lines.length && (lines[i] ?? '').replace(/^\uFEFF/, '').trim() === '') i++;
  if (i >= lines.length) throw new AsciicastError('Recording is empty.');
  const header = parseHeader((lines[i] ?? '').replace(/^\uFEFF/, ''));
  i++;

  const events: AsciicastEvent[] = [];
  let skipped = 0;
  let truncated = false;
  let clock = 0;

  for (; i < lines.length; i++) {
    const line = (lines[i] ?? '').trim();
    if (line === '') continue;
    if (header.version === 3 && line.startsWith('#')) continue; // v3 comment
    if (events.length >= maxEvents) {
      truncated = true;
      break;
    }
    let ev: unknown;
    try {
      ev = JSON.parse(line);
    } catch {
      skipped++;
      continue;
    }
    if (!Array.isArray(ev) || ev.length < 3) {
      skipped++;
      continue;
    }
    const [t, code, data] = ev as unknown[];
    if (typeof t !== 'number' || !Number.isFinite(t) || t < 0 || typeof code !== 'string' || !KNOWN_CODES.has(code)) {
      skipped++;
      continue;
    }
    const payload = typeof data === 'string' ? data : typeof data === 'number' ? String(data) : null;
    if (payload === null) {
      skipped++;
      continue;
    }
    // v2: absolute time; v3: interval since previous event.
    const abs = header.version === 2 ? Math.max(t, clock) : clock + t;
    clock = abs;
    events.push({ time: abs, code: code as AsciicastEventCode, data: payload });
  }

  const last = events[events.length - 1];
  return { header, events, duration: last ? last.time : 0, skipped, truncated };
}

/**
 * Compress pauses longer than `limit` seconds down to `limit`
 * (asciinema's idle_time_limit). Returns a new event list.
 */
export function applyIdleLimit(events: readonly AsciicastEvent[], limit: number | undefined): AsciicastEvent[] {
  if (!limit || limit <= 0) return events.slice();
  const out: AsciicastEvent[] = [];
  let prevOrig = 0;
  let prevNew = 0;
  for (const ev of events) {
    const gap = Math.min(ev.time - prevOrig, limit);
    prevNew += gap;
    prevOrig = ev.time;
    out.push({ ...ev, time: prevNew });
  }
  return out;
}

/** Parse a resize payload "COLSxROWS". */
export function parseResize(data: string): { cols: number; rows: number } | null {
  const m = /^(\d{1,5})x(\d{1,5})$/.exec(data.trim());
  if (!m) return null;
  const cols = Number(m[1]);
  const rows = Number(m[2]);
  if (cols < 1 || rows < 1 || cols > MAX_DIMENSION || rows > MAX_DIMENSION) return null;
  return { cols, rows };
}

/** Index of the first event with time > t (binary search); events.length if none. */
export function indexAfter(events: readonly AsciicastEvent[], t: number): number {
  let lo = 0;
  let hi = events.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if ((events[mid]?.time ?? Infinity) <= t) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}
