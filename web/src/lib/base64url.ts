// base64url (RFC 4648 §5) <-> bytes. Used for WebAuthn options/responses
// (go-webauthn encodes all binary fields as unpadded base64url) and for the
// shell WebSocket payloads (standard base64, which decode() also accepts).

const URL_ALPHABET = /^[A-Za-z0-9_-]*$/;
const STD_ALPHABET = /^[A-Za-z0-9+/]*={0,2}$/;

export class Base64Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Base64Error';
  }
}

function toBytes(input: ArrayBuffer | ArrayBufferView): Uint8Array {
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
}

function bytesToBinaryString(bytes: Uint8Array): string {
  // Chunked to avoid call-stack limits on large inputs.
  let out = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    out += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return out;
}

/** Encode bytes as unpadded base64url. */
export function encodeBase64url(input: ArrayBuffer | ArrayBufferView): string {
  return btoa(bytesToBinaryString(toBytes(input)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** Encode bytes as standard, padded base64. */
export function encodeBase64(input: ArrayBuffer | ArrayBufferView): string {
  return btoa(bytesToBinaryString(toBytes(input)));
}

/**
 * Decode base64url (padded or unpadded). Standard base64 (+ / =) is accepted
 * too, since some servers emit it. Throws Base64Error on invalid input.
 */
export function decodeBase64url(input: string): Uint8Array<ArrayBuffer> {
  let s = input.trim();
  if (URL_ALPHABET.test(s.replace(/=+$/, ''))) {
    s = s.replace(/=+$/, '').replace(/-/g, '+').replace(/_/g, '/');
  } else if (!STD_ALPHABET.test(s)) {
    throw new Base64Error('invalid base64url string');
  } else {
    s = s.replace(/=+$/, '');
  }
  if (s.length % 4 === 1) throw new Base64Error('invalid base64url length');
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new Base64Error('invalid base64url string');
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Decode base64url into a fresh ArrayBuffer (as WebAuthn APIs expect). */
export function base64urlToBuffer(input: string): ArrayBuffer {
  return decodeBase64url(input).buffer;
}

const utf8Encoder = new TextEncoder();

/** UTF-8 encode a string and return standard base64 (shell input frames). */
export function utf8ToBase64(text: string): string {
  return encodeBase64(utf8Encoder.encode(text));
}

/** Latin-1 "binary string" (xterm onBinary) to standard base64. */
export function binaryStringToBase64(binary: string): string {
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i) & 0xff;
  return encodeBase64(bytes);
}
