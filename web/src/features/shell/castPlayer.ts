// Playback engine for parsed asciicast events, independent of React.
// Drives any terminal-like sink (xterm.js in the UI, a fake in tests).

import { type AsciicastEvent, indexAfter, parseResize } from '@/lib/asciicast';

export interface CastSink {
  write(data: string): void;
  reset(): void;
  resize(cols: number, rows: number): void;
}

export interface PlayerSnapshot {
  playing: boolean;
  position: number;
  duration: number;
  speed: number;
}

type Listener = (s: PlayerSnapshot) => void;

export class CastPlayer {
  private idx = 0;
  private pos = 0;
  private playing = false;
  private speed = 1;
  private raf = 0;
  private last = 0;
  private lastEmit = -1;
  private readonly listeners = new Set<Listener>();
  private readonly sink: CastSink;
  private readonly events: readonly AsciicastEvent[];
  private readonly size: { cols: number; rows: number };
  private readonly now: () => number;
  private readonly schedule: (cb: (t: number) => void) => number;
  private readonly cancel: (id: number) => void;

  constructor(
    sink: CastSink,
    events: readonly AsciicastEvent[],
    size: { cols: number; rows: number },
    now: () => number = () => performance.now(),
    schedule: (cb: (t: number) => void) => number = (cb) => requestAnimationFrame(cb),
    cancel: (id: number) => void = (id) => cancelAnimationFrame(id),
  ) {
    this.sink = sink;
    this.events = events;
    this.size = size;
    this.now = now;
    this.schedule = schedule;
    this.cancel = cancel;
    this.sink.resize(size.cols, size.rows);
  }

  get duration(): number {
    return this.events[this.events.length - 1]?.time ?? 0;
  }

  snapshot(): PlayerSnapshot {
    return { playing: this.playing, position: this.pos, duration: this.duration, speed: this.speed };
  }

  subscribe(l: Listener): () => void {
    this.listeners.add(l);
    l(this.snapshot());
    return () => this.listeners.delete(l);
  }

  private emit(force = false) {
    // ~20 updates per second are plenty for the progress UI.
    const bucket = Math.floor(this.pos * 20);
    if (!force && bucket === this.lastEmit) return;
    this.lastEmit = bucket;
    const s = this.snapshot();
    for (const l of this.listeners) l(s);
  }

  private apply(from: number, to: number) {
    let out = '';
    for (let i = from; i < to; i++) {
      const ev = this.events[i];
      if (!ev) continue;
      if (ev.code === 'o') out += ev.data;
      else if (ev.code === 'r') {
        const size = parseResize(ev.data);
        if (size) {
          if (out) this.sink.write(out);
          out = '';
          this.sink.resize(size.cols, size.rows);
        }
      } else if (ev.code === 'x') {
        out += `\r\n\x1b[2m[process exited with status ${ev.data.replace(/[^\d-]/g, '')}]\x1b[0m\r\n`;
      }
    }
    if (out) this.sink.write(out);
  }

  play(): void {
    if (this.playing) return;
    if (this.idx >= this.events.length) this.seek(0);
    this.playing = true;
    this.last = this.now();
    this.emit(true);
    this.raf = this.schedule(this.tick);
  }

  pause(): void {
    if (!this.playing) return;
    this.playing = false;
    this.cancel(this.raf);
    this.emit(true);
  }

  toggle(): void {
    if (this.playing) this.pause();
    else this.play();
  }

  setSpeed(speed: number): void {
    this.speed = Math.min(16, Math.max(0.25, speed));
    this.emit(true);
  }

  /** Jump to `t` seconds: reset the terminal and replay everything before it. */
  seek(t: number): void {
    const target = Math.min(Math.max(0, t), this.duration);
    this.sink.reset();
    this.sink.resize(this.size.cols, this.size.rows);
    const end = indexAfter(this.events, target);
    this.apply(0, end);
    this.idx = end;
    this.pos = target;
    this.last = this.now();
    this.emit(true);
  }

  private tick = (ts: number) => {
    if (!this.playing) return;
    const dt = ((ts - this.last) / 1000) * this.speed;
    this.last = ts;
    this.pos = Math.min(this.duration, this.pos + Math.max(0, dt));
    const end = indexAfter(this.events, this.pos);
    if (end > this.idx) {
      this.apply(this.idx, end);
      this.idx = end;
    }
    if (this.idx >= this.events.length) {
      this.playing = false;
      this.pos = this.duration;
      this.emit(true);
      return;
    }
    this.emit();
    this.raf = this.schedule(this.tick);
  };

  dispose(): void {
    this.playing = false;
    this.cancel(this.raf);
    this.listeners.clear();
  }
}
