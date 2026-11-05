import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { useEffect, useEffectEvent, useImperativeHandle, useRef, type Ref } from 'react';
import { useTheme } from '@/app/theme';
import { binaryInputMessage, inputMessage, parseServerMessage, resizeMessage } from './protocol';
import { baseTerminalOptions, xtermTheme } from './xterm';

export type TermStatus =
  | { state: 'connecting' }
  | { state: 'open' }
  | { state: 'exited'; code: number | null; reason: string }
  | { state: 'closed'; code: number; reason: string }
  | { state: 'error'; message: string };

export interface TerminalHandle {
  disconnect: () => void;
  focus: () => void;
}

interface Props {
  url: string;
  onStatus: (s: TermStatus) => void;
  ref?: Ref<TerminalHandle>;
  className?: string;
}

/** xterm.js bound to a shell WebSocket. Output is written as raw bytes. */
export function TerminalSession({ url, onStatus, ref, className }: Props) {
  const container = useRef<HTMLDivElement>(null);
  const term = useRef<Terminal | null>(null);
  const socket = useRef<WebSocket | null>(null);
  const { resolved } = useTheme();
  const report = useEffectEvent(onStatus);
  const initialTheme = useEffectEvent(() => resolved);

  useImperativeHandle(ref, () => ({
    disconnect: () => socket.current?.close(1000, 'disconnected by user'),
    focus: () => term.current?.focus(),
  }));

  useEffect(() => {
    const el = container.current;
    if (!el) return;
    const t = new Terminal({ ...baseTerminalOptions(initialTheme()), cursorBlink: true });
    const fit = new FitAddon();
    t.loadAddon(fit);
    t.open(el);
    try {
      fit.fit();
    } catch {
      /* container not measurable yet */
    }
    term.current = t;
    let finished = false;
    let ws: WebSocket | null = null;

    const send = (msg: string) => {
      if (ws && ws.readyState === WebSocket.OPEN) ws.send(msg);
    };
    const subs = [
      t.onData((d) => send(inputMessage(d))),
      t.onBinary((b) => send(binaryInputMessage(b))),
      t.onResize(({ cols, rows }) => send(resizeMessage(cols, rows))),
    ];

    // Deferred so React StrictMode's mount/unmount/mount in development does
    // not open (and immediately close, i.e. end) the session twice.
    const timer = setTimeout(() => {
      report({ state: 'connecting' });
      try {
        ws = new WebSocket(url);
      } catch (e) {
        report({ state: 'error', message: e instanceof Error ? e.message : 'Could not open WebSocket' });
        return;
      }
      ws.binaryType = 'arraybuffer';
      socket.current = ws;
      ws.onmessage = (ev: MessageEvent) => {
        const msg = parseServerMessage(ev.data);
        if (!msg) return;
        switch (msg.type) {
          case 'output':
            t.write(msg.data);
            break;
          case 'ready':
            report({ state: 'open' });
            send(resizeMessage(t.cols, t.rows));
            t.focus();
            break;
          case 'exit':
            finished = true;
            t.options.disableStdin = true;
            t.options.cursorBlink = false;
            report({ state: 'exited', code: msg.code, reason: msg.reason });
            ws?.close(1000);
            break;
          case 'error':
            // eslint-disable-next-line no-control-regex -- strip control chars from the server message
            t.write(`\r\n\x1b[31m${msg.message.replace(/[\x00-\x1f\x7f]/g, ' ')}\x1b[0m\r\n`);
            break;
        }
      };
      ws.onclose = (ev: CloseEvent) => {
        t.options.disableStdin = true;
        t.options.cursorBlink = false;
        if (!finished) {
          finished = true;
          report({ state: 'closed', code: ev.code, reason: ev.reason });
        }
      };
    }, 0);

    let raf = 0;
    const ro = new ResizeObserver(() => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        try {
          fit.fit();
        } catch {
          /* ignore */
        }
      });
    });
    ro.observe(el);

    return () => {
      clearTimeout(timer);
      cancelAnimationFrame(raf);
      ro.disconnect();
      subs.forEach((s) => s.dispose());
      if (ws) {
        ws.onclose = null;
        ws.onmessage = null;
        ws.close(1000, 'closed');
      }
      socket.current = null;
      term.current = null;
      t.dispose();
    };
  }, [url]);

  // Theme switch without reconnecting.
  useEffect(() => {
    if (term.current) term.current.options.theme = xtermTheme(resolved);
  }, [resolved]);

  return <div ref={container} className={className} style={{ background: 'var(--term-bg)' }} />;
}
