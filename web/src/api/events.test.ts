import { describe, expect, it } from 'vitest';
import { eventsUrl, keysForEvent, parseEvent } from './events';

describe('parseEvent', () => {
  it('accepts documented events and keeps only known fields', () => {
    const ev = parseEvent(
      JSON.stringify({ type: 'job.target', ts: '2026-11-05T12:00:00Z', job_id: 'j1', host_id: 'h1', status: 'running', extra: 'x' }),
    );
    expect(ev).toEqual({ type: 'job.target', ts: '2026-11-05T12:00:00Z', job_id: 'j1', host_id: 'h1', status: 'running' });
  });

  it.each([
    ['non-JSON', 'hello'],
    ['unknown type', '{"type":"exec","ts":"x"}'],
    ['array', '[]'],
    ['binary frame', new ArrayBuffer(4)],
    ['oversize', JSON.stringify({ type: 'alert', ts: 'x', message: 'a'.repeat(70_000) })],
  ])('rejects %s', (_name, raw) => {
    expect(parseEvent(raw)).toBeNull();
  });

  it('truncates long messages and ignores non-string ids', () => {
    const ev = parseEvent(JSON.stringify({ type: 'alert', ts: 't', message: 'm'.repeat(5000), host_id: 42 }));
    expect(ev?.message).toHaveLength(1000);
    expect(ev && 'host_id' in ev).toBe(false);
  });
});

describe('keysForEvent', () => {
  it('maps host and job events to query keys', () => {
    expect(keysForEvent({ type: 'host.connected', ts: 't', host_id: 'h1' })).toContainEqual(['host', 'h1']);
    expect(keysForEvent({ type: 'job.target', ts: 't', job_id: 'j1' })).toEqual([['job', 'j1']]);
    expect(keysForEvent({ type: 'alert', ts: 't' })).toContainEqual(['alerts']);
  });
});

describe('eventsUrl', () => {
  it('uses wss on https and ws on http', () => {
    expect(eventsUrl({ protocol: 'https:', host: 'stellwerk.example' })).toBe('wss://stellwerk.example/api/v1/events');
    expect(eventsUrl({ protocol: 'http:', host: 'localhost:5173' })).toBe('ws://localhost:5173/api/v1/events');
  });
});
