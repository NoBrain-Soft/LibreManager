import { describe, expect, it } from 'vitest';
import { decodeBase64url, encodeBase64url } from './base64url';
import {
  type PublicKeyCredentialLike,
  WebAuthnError,
  describeWebAuthnError,
  serializeCredential,
  toCreationOptions,
  toRequestOptions,
} from './webauthn';

const u8 = (s: string) => new TextEncoder().encode(s);
const b64 = (s: string) => encodeBase64url(u8(s));
const text = (buf: BufferSource | undefined) =>
  new TextDecoder().decode(buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf);

describe('toCreationOptions (go-webauthn registration options)', () => {
  const serverOptions = {
    publicKey: {
      rp: { name: 'Stellwerk', id: 'stellwerk.example.internal' },
      user: { name: 'alice', displayName: 'Alice', id: b64('user-handle-1') },
      challenge: b64('challenge-bytes'),
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -8 },
      ],
      timeout: 60000,
      excludeCredentials: [{ type: 'public-key', id: b64('cred-1'), transports: ['usb'] }],
      authenticatorSelection: { residentKey: 'discouraged', userVerification: 'preferred' },
      attestation: 'none',
      extensions: null,
    },
  };

  it('decodes challenge, user.id and excludeCredentials ids to ArrayBuffers', () => {
    const { publicKey } = toCreationOptions(serverOptions);
    expect(publicKey).toBeDefined();
    expect(publicKey!.challenge).toBeInstanceOf(ArrayBuffer);
    expect(text(publicKey!.challenge)).toBe('challenge-bytes');
    expect(text(publicKey!.user.id)).toBe('user-handle-1');
    expect(publicKey!.user.name).toBe('alice');
    const ex = publicKey!.excludeCredentials!;
    expect(ex).toHaveLength(1);
    expect(text(ex[0]!.id)).toBe('cred-1');
    expect(ex[0]!.transports).toEqual(['usb']);
  });

  it('keeps other fields and drops null members', () => {
    const { publicKey } = toCreationOptions(serverOptions);
    expect(publicKey!.rp).toEqual({ name: 'Stellwerk', id: 'stellwerk.example.internal' });
    expect(publicKey!.pubKeyCredParams).toHaveLength(2);
    expect(publicKey!.attestation).toBe('none');
    expect('extensions' in publicKey!).toBe(false);
  });

  it('accepts options without the publicKey wrapper', () => {
    const { publicKey } = toCreationOptions(serverOptions.publicKey);
    expect(text(publicKey!.challenge)).toBe('challenge-bytes');
  });

  it('omits excludeCredentials when absent', () => {
    const { excludeCredentials: _ignored, ...rest } = serverOptions.publicKey;
    const { publicKey } = toCreationOptions({ publicKey: rest });
    expect(publicKey!.excludeCredentials).toBeUndefined();
  });

  it.each([
    ['not an object', 'nope'],
    ['missing challenge', { publicKey: { ...serverOptions.publicKey, challenge: undefined } }],
    ['missing user', { publicKey: { ...serverOptions.publicKey, user: undefined } }],
    ['missing user.id', { publicKey: { ...serverOptions.publicKey, user: { name: 'x' } } }],
    ['bad descriptor list', { publicKey: { ...serverOptions.publicKey, excludeCredentials: 'x' } }],
  ])('rejects %s', (_name, input) => {
    expect(() => toCreationOptions(input)).toThrow(WebAuthnError);
  });

  it('rejects invalid base64url', () => {
    expect(() => toCreationOptions({ publicKey: { ...serverOptions.publicKey, challenge: '***' } })).toThrow();
  });
});

describe('toRequestOptions (go-webauthn assertion options)', () => {
  it('decodes challenge and allowCredentials ids and passes mediation', () => {
    const opts = toRequestOptions({
      publicKey: {
        challenge: b64('assert-challenge'),
        timeout: 60000,
        rpId: 'stellwerk.example.internal',
        allowCredentials: [
          { type: 'public-key', id: b64('k1') },
          { id: b64('k2') },
        ],
        userVerification: 'preferred',
      },
      mediation: 'optional',
    });
    expect(text(opts.publicKey!.challenge)).toBe('assert-challenge');
    expect(opts.publicKey!.rpId).toBe('stellwerk.example.internal');
    const allow = opts.publicKey!.allowCredentials!;
    expect(allow.map((c) => text(c.id))).toEqual(['k1', 'k2']);
    expect(allow[1]!.type).toBe('public-key');
    expect(opts.mediation).toBe('optional');
  });

  it('omits mediation and allowCredentials when not provided', () => {
    const opts = toRequestOptions({ publicKey: { challenge: b64('c') } });
    expect(opts.mediation).toBeUndefined();
    expect(opts.publicKey!.allowCredentials).toBeUndefined();
  });
});

describe('serializeCredential', () => {
  it('serializes an attestation (registration) response', () => {
    const cred: PublicKeyCredentialLike = {
      id: b64('raw-id'),
      rawId: u8('raw-id').buffer,
      type: 'public-key',
      authenticatorAttachment: 'cross-platform',
      response: {
        clientDataJSON: u8('{"type":"webauthn.create"}').buffer,
        attestationObject: u8('attobj').buffer,
        getTransports: () => ['usb', 'nfc'],
        getAuthenticatorData: () => u8('authdata').buffer,
        getPublicKey: () => null,
        getPublicKeyAlgorithm: () => -7,
      },
      getClientExtensionResults: () => ({ credProps: { rk: false } }),
    };
    const json = serializeCredential(cred);
    expect(json).toEqual({
      id: b64('raw-id'),
      rawId: b64('raw-id'),
      type: 'public-key',
      authenticatorAttachment: 'cross-platform',
      transports: ['usb', 'nfc'],
      clientExtensionResults: { credProps: { rk: false } },
      response: {
        clientDataJSON: b64('{"type":"webauthn.create"}'),
        attestationObject: b64('attobj'),
        transports: ['usb', 'nfc'],
        authenticatorData: b64('authdata'),
        publicKeyAlgorithm: -7,
      },
    });
    // Must be plain JSON (no ArrayBuffers left).
    expect(JSON.parse(JSON.stringify(json))).toEqual(json);
  });

  it('serializes an assertion (login/step-up) response with userHandle', () => {
    const cred: PublicKeyCredentialLike = {
      id: 'abc',
      rawId: new Uint8Array([1, 2, 3]).buffer,
      type: 'public-key',
      response: {
        clientDataJSON: u8('cdj').buffer,
        authenticatorData: u8('ad').buffer,
        signature: new Uint8Array([0xfb, 0xff]).buffer,
        userHandle: u8('uh').buffer,
      },
      getClientExtensionResults: () => ({}),
    };
    const json = serializeCredential(cred) as { response: Record<string, string>; rawId: string };
    expect(json.rawId).toBe('AQID');
    expect(json.response).toEqual({
      clientDataJSON: b64('cdj'),
      authenticatorData: b64('ad'),
      signature: '-_8',
      userHandle: b64('uh'),
    });
  });

  it('omits a null userHandle and tolerates missing optional methods', () => {
    const cred: PublicKeyCredentialLike = {
      id: 'x',
      rawId: new Uint8Array([9]).buffer,
      type: 'public-key',
      authenticatorAttachment: null,
      response: {
        clientDataJSON: u8('c').buffer,
        authenticatorData: u8('a').buffer,
        signature: u8('s').buffer,
        userHandle: null,
      },
    };
    const json = serializeCredential(cred) as Record<string, unknown> & { response: Record<string, unknown> };
    expect('userHandle' in json.response).toBe(false);
    expect('authenticatorAttachment' in json).toBe(false);
    expect(json.clientExtensionResults).toEqual({});
  });

  it('converts binary extension results and survives throwing getters', () => {
    const cred: PublicKeyCredentialLike = {
      id: 'x',
      rawId: new Uint8Array([9]).buffer,
      type: 'public-key',
      response: {
        clientDataJSON: u8('c').buffer,
        attestationObject: u8('o').buffer,
        getTransports: () => {
          throw new Error('not supported');
        },
      },
      getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array([1, 2]) } } }),
    };
    const json = serializeCredential(cred) as Record<string, unknown> & { response: Record<string, unknown> };
    expect(json.clientExtensionResults).toEqual({ prf: { results: { first: 'AQI' } } });
    expect('transports' in json.response).toBe(false);
    expect('transports' in json).toBe(false);
    expect(decodeBase64url(json.response.attestationObject as string)).toEqual(u8('o'));
  });
});

describe('describeWebAuthnError', () => {
  it('maps DOMException names to friendly text', () => {
    expect(describeWebAuthnError(new DOMException('x', 'NotAllowedError'))).toMatch(/cancelled or timed out/);
    expect(describeWebAuthnError(new DOMException('x', 'InvalidStateError'))).toMatch(/already registered/);
    expect(describeWebAuthnError(new WebAuthnError('custom'))).toBe('custom');
    expect(describeWebAuthnError('weird')).toBe('Security key operation failed.');
  });
});
