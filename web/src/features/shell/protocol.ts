// Shell WebSocket protocol (openapi.yaml, operation connectShell):
//   client → server: {"type":"input","data":"<base64>"}, {"type":"resize","cols":N,"rows":N}
//   server → client: {"type":"output","data":"<base64>"}, {"type":"ready"},
//                    {"type":"exit","code":N,"reason":"..."}
// Everything from the server is untrusted: messages are size-limited and
// validated; output bytes go straight to the terminal emulator.

import { API_BASE } from '@/api/client';
import type { ShellSession } from '@/api/types';
import { decodeBase64url, utf8ToBase64, binaryStringToBase64 } from '@/lib/base64url';

export const MAX_FRAME_CHARS = 1 << 20; // 1 MiB of JSON per frame

export type ServerMessage =
  | { type: 'output'; data: Uint8Array }
  | { type: 'ready' }
  | { type: 'exit'; code: number | null; reason: string }
  | { type: 'error'; message: string };

export function parseServerMessage(raw: unknown): ServerMessage | null {
  if (raw instanceof ArrayBuffer) return { type: 'output', data: new Uint8Array(raw) };
  if (typeof raw !== 'string' || raw.length > MAX_FRAME_CHARS) return null;
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof v !== 'object' || v === null) return null;
  const m = v as Record<string, unknown>;
  switch (m.type) {
    case 'output': {
      if (typeof m.data !== 'string') return null;
      try {
        return { type: 'output', data: decodeBase64url(m.data) };
      } catch {
        return null;
      }
    }
    case 'ready':
      return { type: 'ready' };
    case 'exit':
      return {
        type: 'exit',
        code: typeof m.code === 'number' && Number.isInteger(m.code) ? m.code : null,
        reason: typeof m.reason === 'string' ? m.reason.slice(0, 500) : '',
      };
    case 'error':
      return { type: 'error', message: typeof m.message === 'string' ? m.message.slice(0, 500) : 'Shell error' };
    default:
      return null;
  }
}

export function inputMessage(text: string): string {
  return JSON.stringify({ type: 'input', data: utf8ToBase64(text) });
}

export function binaryInputMessage(binary: string): string {
  return JSON.stringify({ type: 'input', data: binaryStringToBase64(binary) });
}

export function resizeMessage(cols: number, rows: number): string {
  return JSON.stringify({ type: 'resize', cols: clamp(cols, 10, 1000), rows: clamp(rows, 5, 1000) });
}

export function clamp(n: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, Math.floor(n)));
}

/**
 * WebSocket URL for a granted session. Only same-origin paths are accepted
 * (the server returns `websocket_path`); anything else falls back to the
 * documented path. Uses wss: on https pages.
 */
export function shellSocketUrl(
  session: Pick<ShellSession, 'id' | 'websocket_path'>,
  hostId: string,
  loc: Pick<Location, 'href' | 'origin' | 'protocol'> = location,
): string {
  const fallback = `${API_BASE}/hosts/${encodeURIComponent(hostId)}/shell/${encodeURIComponent(session.id)}`;
  let url: URL;
  try {
    const path = session.websocket_path;
    url = new URL(path && path.startsWith('/') && !path.startsWith('//') ? path : fallback, loc.href);
    if (url.origin !== loc.origin) url = new URL(fallback, loc.href);
  } catch {
    url = new URL(fallback, loc.href);
  }
  url.protocol = loc.protocol === 'https:' ? 'wss:' : 'ws:';
  url.hash = '';
  return url.toString();
}

/** Allowed unix account names (ShellSessionCreate.unix_user). */
export const UNIX_USER_RE = /^[a-z_][a-z0-9_.-]{0,31}$/;

/** Rough terminal size for the initial request; the terminal resizes after "ready". */
export function estimateSize(width: number, height: number): { cols: number; rows: number } {
  return { cols: clamp((width - 16) / 7.8, 10, 1000), rows: clamp((height - 16) / 17, 5, 1000) };
}
