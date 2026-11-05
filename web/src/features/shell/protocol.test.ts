import { describe, expect, it } from 'vitest';
import {
  MAX_FRAME_CHARS,
  UNIX_USER_RE,
  binaryInputMessage,
  inputMessage,
  parseServerMessage,
  resizeMessage,
  shellSocketUrl,
} from './protocol';

const httpsLoc = { href: 'https://stellwerk.example/hosts/h1/shell', origin: 'https://stellwerk.example', protocol: 'https:' };
const httpLoc = { href: 'http://localhost:5173/x', origin: 'http://localhost:5173', protocol: 'http:' };

describe('parseServerMessage', () => {
  it('decodes output frames', () => {
    const msg = parseServerMessage(JSON.stringify({ type: 'output', data: btoa('hello\r\n') }));
    expect(msg?.type).toBe('output');
    expect(new TextDecoder().decode((msg as { data: Uint8Array }).data)).toBe('hello\r\n');
  });

  it('parses ready and exit', () => {
    expect(parseServerMessage('{"type":"ready"}')).toEqual({ type: 'ready' });
    expect(parseServerMessage('{"type":"exit","code":130,"reason":"idle timeout"}')).toEqual({
      type: 'exit',
      code: 130,
      reason: 'idle timeout',
    });
    expect(parseServerMessage('{"type":"exit"}')).toEqual({ type: 'exit', code: null, reason: '' });
  });

  it('treats binary frames as raw output', () => {
    const msg = parseServerMessage(new Uint8Array([104, 105]).buffer);
    expect(msg).toEqual({ type: 'output', data: new Uint8Array([104, 105]) });
  });

  it.each([
    ['not json', 'hello'],
    ['unknown type', '{"type":"eval","data":"x"}'],
    ['output without data', '{"type":"output"}'],
    ['bad base64', '{"type":"output","data":"!!!"}'],
    ['array', '[1,2]'],
    ['null', 'null'],
    ['oversize', JSON.stringify({ type: 'output', data: 'A'.repeat(MAX_FRAME_CHARS) })],
  ])('rejects %s', (_name, raw) => {
    expect(parseServerMessage(raw)).toBeNull();
  });
});

describe('client messages', () => {
  it('encodes input as base64 UTF-8', () => {
    expect(JSON.parse(inputMessage('ls\r'))).toEqual({ type: 'input', data: 'bHMN' });
    expect(JSON.parse(inputMessage('é'))).toEqual({ type: 'input', data: 'w6k=' });
    expect(JSON.parse(binaryInputMessage('\x1b\xff'))).toEqual({ type: 'input', data: 'G/8=' });
  });

  it('clamps resize to the API limits', () => {
    expect(JSON.parse(resizeMessage(120.7, 32.2))).toEqual({ type: 'resize', cols: 120, rows: 32 });
    expect(JSON.parse(resizeMessage(2, 1))).toEqual({ type: 'resize', cols: 10, rows: 5 });
    expect(JSON.parse(resizeMessage(5000, 5000))).toEqual({ type: 'resize', cols: 1000, rows: 1000 });
  });
});

describe('shellSocketUrl', () => {
  it('uses the returned same-origin path with wss on https', () => {
    expect(shellSocketUrl({ id: 's1', websocket_path: '/api/v1/hosts/h1/shell/s1' }, 'h1', httpsLoc)).toBe(
      'wss://stellwerk.example/api/v1/hosts/h1/shell/s1',
    );
  });

  it('uses ws on http (dev)', () => {
    expect(shellSocketUrl({ id: 's1', websocket_path: '/api/v1/hosts/h1/shell/s1' }, 'h1', httpLoc)).toBe(
      'ws://localhost:5173/api/v1/hosts/h1/shell/s1',
    );
  });

  it.each([
    ['absolute foreign URL', 'wss://evil.example/steal'],
    ['protocol-relative', '//evil.example/steal'],
    ['relative path', 'api/v1/x'],
    ['missing', undefined],
  ])('falls back to the documented path for %s', (_name, path) => {
    expect(shellSocketUrl({ id: 's 1', websocket_path: path }, 'h/1', httpsLoc)).toBe(
      'wss://stellwerk.example/api/v1/hosts/h%2F1/shell/s%201',
    );
  });
});

describe('UNIX_USER_RE', () => {
  it.each(['ops', 'deploy_user', '_svc', 'a.b-c', 'root'])('accepts %s', (u) => expect(UNIX_USER_RE.test(u)).toBe(true));
  it.each(['', 'Ops', '1abc', 'a b', 'x'.repeat(33), 'a;rm', '-x'])('rejects %j', (u) => expect(UNIX_USER_RE.test(u)).toBe(false));
});
