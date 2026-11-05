import { describe, expect, it } from 'vitest';
import { parseAsciicast } from '@/lib/asciicast';
import { type CastSink, CastPlayer } from './castPlayer';

const cast = parseAsciicast(
  [
    '{"version":2,"width":80,"height":24}',
    '[0.5,"o","a"]',
    '[1.0,"o","b"]',
    '[1.5,"r","100x30"]',
    '[2.0,"i","ignored"]',
    '[3.0,"o","c"]',
  ].join('\n'),
);

function fakeSink() {
  const log: string[] = [];
  const sink: CastSink = {
    write: (d) => log.push(`w:${d}`),
    reset: () => log.push('reset'),
    resize: (c, r) => log.push(`size:${c}x${r}`),
  };
  return { sink, log };
}

/** Manual clock + frame scheduler. */
function harness() {
  let t = 0;
  let pending: ((ts: number) => void) | null = null;
  return {
    now: () => t,
    schedule: (cb: (ts: number) => void) => {
      pending = cb;
      return 1;
    },
    cancel: () => {
      pending = null;
    },
    advance(ms: number) {
      t += ms;
      const cb = pending;
      pending = null;
      cb?.(t);
    },
  };
}

describe('CastPlayer', () => {
  it('replays output in real time and applies resizes', () => {
    const { sink, log } = fakeSink();
    const h = harness();
    const p = new CastPlayer(sink, cast.events, { cols: 80, rows: 24 }, h.now, h.schedule, h.cancel);
    expect(log).toEqual(['size:80x24']);
    p.play();
    h.advance(600);
    expect(log).toEqual(['size:80x24', 'w:a']);
    h.advance(1000);
    expect(log).toEqual(['size:80x24', 'w:a', 'w:b', 'size:100x30']);
    h.advance(2000);
    expect(log.at(-1)).toBe('w:c');
    expect(p.snapshot()).toMatchObject({ playing: false, position: 3 });
  });

  it('honours playback speed', () => {
    const { sink, log } = fakeSink();
    const h = harness();
    const p = new CastPlayer(sink, cast.events, { cols: 80, rows: 24 }, h.now, h.schedule, h.cancel);
    p.setSpeed(4);
    p.play();
    h.advance(300); // 1.2 s of recording
    expect(log).toEqual(['size:80x24', 'w:ab']);
  });

  it('seeks by resetting and replaying everything before the target', () => {
    const { sink, log } = fakeSink();
    const p = new CastPlayer(sink, cast.events, { cols: 80, rows: 24 }, () => 0, () => 1, () => undefined);
    log.length = 0;
    p.seek(2.5);
    expect(log).toEqual(['reset', 'size:80x24', 'w:ab', 'size:100x30']);
    expect(p.snapshot().position).toBe(2.5);
    log.length = 0;
    p.seek(99);
    expect(log).toEqual(['reset', 'size:80x24', 'w:ab', 'size:100x30', 'w:c']);
    expect(p.snapshot().position).toBe(3);
  });

  it('pauses and restarts from the beginning when finished', () => {
    const { sink, log } = fakeSink();
    const h = harness();
    const p = new CastPlayer(sink, cast.events, { cols: 80, rows: 24 }, h.now, h.schedule, h.cancel);
    p.play();
    h.advance(800);
    p.pause();
    h.advance(5000);
    expect(log).toEqual(['size:80x24', 'w:a']);
    p.seek(10);
    p.play(); // at end → restart
    expect(log.slice(-2)).toEqual(['reset', 'size:80x24']);
  });
});
