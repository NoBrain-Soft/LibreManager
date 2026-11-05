// Live events over WebSocket (/api/v1/events). Messages are `Event` objects
// (see openapi.yaml). The socket only triggers cache invalidation; all data
// is still fetched over REST, so a missed event is never fatal and polling
// fallbacks in the views cover a disconnected socket.

import { useSyncExternalStore } from 'react';
import { API_BASE } from './client';
import { qk } from './keys';
import { queryClient } from './queryClient';
import type { ApiEvent } from './types';

export type EventsStatus = 'idle' | 'connecting' | 'open' | 'reconnecting';

type EventListener = (ev: ApiEvent) => void;

const MAX_MESSAGE_BYTES = 64 * 1024;
const EVENT_TYPES = new Set<string>([
  'host.connected',
  'host.disconnected',
  'host.enrolled',
  'host.updated',
  'job.created',
  'job.target',
  'job.finished',
  'alert',
]);

/** Validate an incoming message; returns null for anything unexpected. */
export function parseEvent(raw: unknown): ApiEvent | null {
  if (typeof raw !== 'string' || raw.length > MAX_MESSAGE_BYTES) return null;
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  if (typeof o.type !== 'string' || !EVENT_TYPES.has(o.type)) return null;
  const ev: ApiEvent = { type: o.type as ApiEvent['type'], ts: typeof o.ts === 'string' ? o.ts : new Date().toISOString() };
  if (typeof o.host_id === 'string') ev.host_id = o.host_id;
  if (typeof o.job_id === 'string') ev.job_id = o.job_id;
  if (typeof o.status === 'string') ev.status = o.status;
  if (typeof o.message === 'string') ev.message = o.message.slice(0, 1000);
  return ev;
}

/** Query keys to refresh for an event. */
export function keysForEvent(ev: ApiEvent): (readonly unknown[])[] {
  switch (ev.type) {
    case 'host.connected':
    case 'host.disconnected':
    case 'host.enrolled':
    case 'host.updated':
      return [qk.hostsRoot, qk.dashboard, qk.updates, ...(ev.host_id ? [qk.host(ev.host_id)] : [])];
    case 'job.created':
      return [qk.jobsRoot, qk.dashboard];
    case 'job.target':
      return ev.job_id ? [qk.job(ev.job_id)] : [qk.jobRoot];
    case 'job.finished':
      return [
        qk.jobsRoot,
        qk.dashboard,
        ...(ev.job_id ? [qk.job(ev.job_id)] : [qk.jobRoot]),
        // A finished job may have changed packages/updates/services on hosts.
        qk.updates,
        qk.hostRoot,
      ];
    case 'alert':
      return [qk.alertsRoot, qk.dashboard];
    default:
      return [];
  }
}

export function eventsUrl(loc: Pick<Location, 'protocol' | 'host'> = location): string {
  const proto = loc.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${loc.host}${API_BASE}/events`;
}

class EventsConnection {
  private ws: WebSocket | null = null;
  private status: EventsStatus = 'idle';
  private wanted = false;
  private attempt = 0;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private pendingKeys = new Map<string, readonly unknown[]>();
  private statusListeners = new Set<() => void>();
  private eventListeners = new Set<EventListener>();
  onAuthFailure: (() => void) | null = null;

  getStatus = (): EventsStatus => this.status;

  subscribeStatus = (l: () => void) => {
    this.statusListeners.add(l);
    return () => this.statusListeners.delete(l);
  };

  subscribe(l: EventListener): () => void {
    this.eventListeners.add(l);
    return () => this.eventListeners.delete(l);
  }

  start(): void {
    if (this.wanted) return;
    this.wanted = true;
    this.attempt = 0;
    this.open();
  }

  stop(): void {
    this.wanted = false;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = null;
    const ws = this.ws;
    this.ws = null;
    if (ws) {
      ws.onclose = null;
      ws.close(1000, 'logout');
    }
    this.setStatus('idle');
  }

  private setStatus(s: EventsStatus) {
    if (this.status === s) return;
    this.status = s;
    for (const l of this.statusListeners) l();
  }

  private open() {
    if (!this.wanted) return;
    this.setStatus(this.attempt === 0 ? 'connecting' : 'reconnecting');
    let ws: WebSocket;
    try {
      ws = new WebSocket(eventsUrl());
    } catch {
      this.scheduleRetry();
      return;
    }
    this.ws = ws;
    ws.onopen = () => {
      this.attempt = 0;
      this.setStatus('open');
      // We may have missed events while disconnected.
      void queryClient.invalidateQueries({ queryKey: qk.dashboard });
    };
    ws.onmessage = (msg: MessageEvent) => {
      const ev = parseEvent(msg.data);
      if (!ev) return;
      for (const k of keysForEvent(ev)) this.pendingKeys.set(JSON.stringify(k), k);
      this.scheduleFlush();
      for (const l of this.eventListeners) {
        try {
          l(ev);
        } catch {
          /* listener errors must not break the socket */
        }
      }
    };
    ws.onclose = (e: CloseEvent) => {
      this.ws = null;
      if (!this.wanted) return;
      // 4401/4403 (app-defined) or 1008 (policy) likely mean the session ended.
      if (e.code === 4401 || e.code === 4403 || e.code === 1008) this.onAuthFailure?.();
      this.scheduleRetry();
    };
    ws.onerror = () => {
      /* onclose follows */
    };
  }

  private scheduleRetry() {
    if (!this.wanted) return;
    this.setStatus('reconnecting');
    const base = Math.min(30_000, 1000 * 2 ** Math.min(this.attempt, 5));
    const delay = base / 2 + Math.random() * (base / 2);
    this.attempt++;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = setTimeout(() => this.open(), delay);
  }

  private scheduleFlush() {
    if (this.flushTimer) return;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      const keys = [...this.pendingKeys.values()];
      this.pendingKeys.clear();
      for (const queryKey of keys) void queryClient.invalidateQueries({ queryKey });
    }, 400);
  }
}

export const events = new EventsConnection();

export function useEventsStatus(): EventsStatus {
  return useSyncExternalStore(events.subscribeStatus, events.getStatus, events.getStatus);
}
