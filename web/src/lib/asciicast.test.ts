import { describe, expect, it } from 'vitest';
import { AsciicastError, applyIdleLimit, indexAfter, parseAsciicast, parseResize } from './asciicast';

const v2 = [
  '{"version": 2, "width": 120, "height": 32, "timestamp": 1730800000, "title": "ops@web-01", "env": {"TERM": "xterm-256color", "SHELL": 1}}',
  '[0.010, "o", "Session recorded by Stellwerk\\r\\n"]',
  '[0.5, "i", "l"]',
  '[0.52, "o", "l"]',
  '[1.25, "r", "100x30"]',
  '[2.0, "m", "checkpoint"]',
  '[9.75, "o", "$ "]',
  '',
].join('\n');

describe('parseAsciicast v2', () => {
  it('parses header and events', () => {
    const cast = parseAsciicast(v2);
    expect(cast.header).toEqual({
      version: 2,
      width: 120,
      height: 32,
      timestamp: 1730800000,
      title: 'ops@web-01',
      env: { TERM: 'xterm-256color' },
    });
    expect(cast.events).toHaveLength(6);
    expect(cast.events[0]).toEqual({ time: 0.01, code: 'o', data: 'Session recorded by Stellwerk\r\n' });
    expect(cast.events.map((e) => e.code)).toEqual(['o', 'i', 'o', 'r', 'm', 'o']);
    expect(cast.duration).toBe(9.75);
    expect(cast.skipped).toBe(0);
    expect(cast.truncated).toBe(false);
  });

  it('skips malformed lines, unknown codes and a truncated last line', () => {
    const text = [
      '{"version":2,"width":80,"height":24}',
      '[0.1,"o","ok"]',
      'garbage',
      '{"not":"an array"}',
      '[0.2,"z","unknown code"]',
      '["x","o","bad time"]',
      '[-1,"o","negative"]',
      '[0.3,"o"]',
      '[0.4,"o",null]',
      '[0.5,"o","fine"]',
      '[0.6,"o","trunc',
    ].join('\n');
    const cast = parseAsciicast(text);
    expect(cast.events.map((e) => e.data)).toEqual(['ok', 'fine']);
    expect(cast.skipped).toBe(8);
  });

  it('clamps out-of-order timestamps to be non-decreasing', () => {
    const cast = parseAsciicast('{"version":2,"width":80,"height":24}\n[2,"o","a"]\n[1,"o","b"]\n[3,"o","c"]');
    expect(cast.events.map((e) => e.time)).toEqual([2, 2, 3]);
  });

  it('tolerates a BOM, leading blank lines and CRLF', () => {
    const cast = parseAsciicast('\n\uFEFF{"version":2,"width":80,"height":24}\r\n[1,"o","x"]\r\n');
    expect(cast.events).toEqual([{ time: 1, code: 'o', data: 'x' }]);
  });

  it('enforces maxEvents', () => {
    const lines = ['{"version":2,"width":80,"height":24}'];
    for (let i = 0; i < 10; i++) lines.push(`[${i},"o","${i}"]`);
    const cast = parseAsciicast(lines.join('\n'), { maxEvents: 3 });
    expect(cast.events).toHaveLength(3);
    expect(cast.truncated).toBe(true);
  });

  it.each([
    ['empty input', ''],
    ['whitespace only', '  \n \n'],
    ['non-JSON header', 'hello'],
    ['array header', '[1,2]'],
    ['unsupported version', '{"version":1,"width":80,"height":24}'],
    ['missing size', '{"version":2}'],
    ['zero width', '{"version":2,"width":0,"height":24}'],
    ['absurd size', '{"version":2,"width":100000,"height":24}'],
    ['fractional size', '{"version":2,"width":80.5,"height":24}'],
  ])('rejects %s', (_name, text) => {
    expect(() => parseAsciicast(text)).toThrow(AsciicastError);
  });
});

describe('parseAsciicast v3', () => {
  it('converts relative intervals to absolute times and ignores comments', () => {
    const text = [
      '{"version":3,"term":{"cols":100,"rows":40},"idle_time_limit":2}',
      '# a comment',
      '[0.5,"o","a"]',
      '[0.25,"o","b"]',
      '[1.0,"x","0"]',
    ].join('\n');
    const cast = parseAsciicast(text);
    expect(cast.header).toMatchObject({ version: 3, width: 100, height: 40, idleTimeLimit: 2 });
    expect(cast.events.map((e) => [e.time, e.code, e.data])).toEqual([
      [0.5, 'o', 'a'],
      [0.75, 'o', 'b'],
      [1.75, 'x', '0'],
    ]);
  });
});

describe('applyIdleLimit', () => {
  it('compresses long pauses', () => {
    const cast = parseAsciicast(v2);
    const limited = applyIdleLimit(cast.events, 2);
    expect(limited.map((e) => Number(e.time.toFixed(3)))).toEqual([0.01, 0.5, 0.52, 1.25, 2, 4]);
    // input untouched
    expect(cast.events[5]!.time).toBe(9.75);
  });

  it('returns a copy when no limit is set', () => {
    const cast = parseAsciicast(v2);
    const same = applyIdleLimit(cast.events, undefined);
    expect(same).toEqual(cast.events);
    expect(same).not.toBe(cast.events);
  });
});

describe('parseResize', () => {
  it.each([
    ['80x24', { cols: 80, rows: 24 }],
    [' 200x50 ', { cols: 200, rows: 50 }],
    ['0x24', null],
    ['80x', null],
    ['80*24', null],
    ['999999x1', null],
  ])('%j -> %j', (input, expected) => {
    expect(parseResize(input)).toEqual(expected);
  });
});

describe('indexAfter', () => {
  const events = [0, 1, 1, 2, 5].map((time) => ({ time, code: 'o' as const, data: '' }));
  it.each([
    [-1, 0],
    [0, 1],
    [1, 3],
    [1.5, 3],
    [5, 5],
    [10, 5],
  ])('t=%d -> %d', (t, idx) => {
    expect(indexAfter(events, t)).toBe(idx);
  });
});
