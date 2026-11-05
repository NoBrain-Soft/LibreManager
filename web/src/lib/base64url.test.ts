import { describe, expect, it } from 'vitest';
import {
  Base64Error,
  base64urlToBuffer,
  binaryStringToBase64,
  decodeBase64url,
  encodeBase64,
  encodeBase64url,
  utf8ToBase64,
} from './base64url';

const bytes = (...b: number[]) => new Uint8Array(b);

describe('encodeBase64url', () => {
  it.each([
    [bytes(), ''],
    [bytes(0x66), 'Zg'],
    [bytes(0x66, 0x6f), 'Zm8'],
    [bytes(0x66, 0x6f, 0x6f), 'Zm9v'],
    [bytes(0xfb, 0xff), '-_8'],
    [bytes(0xff, 0xfe, 0xfd, 0xfc), '__79_A'],
  ])('encodes %o as %s (unpadded, URL-safe)', (input, expected) => {
    expect(encodeBase64url(input)).toBe(expected);
  });

  it('accepts ArrayBuffer and views with offsets', () => {
    const buf = bytes(1, 2, 3, 4, 5).buffer;
    expect(encodeBase64url(buf)).toBe('AQIDBAU');
    expect(encodeBase64url(new Uint8Array(buf, 1, 3))).toBe('AgME');
    expect(encodeBase64url(new DataView(buf, 3))).toBe('BAU');
  });

  it('handles large inputs', () => {
    const big = new Uint8Array(200_000).map((_, i) => i & 0xff);
    const enc = encodeBase64url(big);
    expect(decodeBase64url(enc)).toEqual(big);
  });
});

describe('decodeBase64url', () => {
  it('round-trips all byte values', () => {
    const all = new Uint8Array(256).map((_, i) => i);
    expect(decodeBase64url(encodeBase64url(all))).toEqual(all);
  });

  it('accepts padded base64url and standard base64', () => {
    expect(decodeBase64url('Zm8=')).toEqual(bytes(0x66, 0x6f));
    expect(decodeBase64url('-_8')).toEqual(bytes(0xfb, 0xff));
    expect(decodeBase64url('+/8=')).toEqual(bytes(0xfb, 0xff));
    expect(decodeBase64url('  Zm9v \n')).toEqual(bytes(0x66, 0x6f, 0x6f));
  });

  it.each(['Zm9v!', 'a', 'Zm9v-+', 'é', 'Zm=9v'])('rejects invalid input %j', (input) => {
    expect(() => decodeBase64url(input)).toThrow(Base64Error);
  });

  it('returns a standalone ArrayBuffer for WebAuthn', () => {
    const buf = base64urlToBuffer('AQID');
    expect(buf).toBeInstanceOf(ArrayBuffer);
    expect(buf.byteLength).toBe(3);
  });
});

describe('shell frame helpers', () => {
  it('encodes UTF-8 text as standard base64', () => {
    expect(utf8ToBase64('ls -la\r')).toBe('bHMgLWxhDQ==');
    expect(utf8ToBase64('ü')).toBe(encodeBase64(bytes(0xc3, 0xbc)));
  });

  it('encodes binary strings byte-wise', () => {
    expect(binaryStringToBase64('\x00\xff')).toBe('AP8=');
  });
});
