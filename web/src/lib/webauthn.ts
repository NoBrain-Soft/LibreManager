// WebAuthn glue between the go-webauthn JSON format used by the API and the
// browser's navigator.credentials API.
//
// Server -> browser: options arrive as `{ publicKey: {...}, mediation? }`
// with base64url-encoded binary fields (challenge, user.id,
// allowCredentials[].id, excludeCredentials[].id). We convert those to
// ArrayBuffers. A bare options object (without the `publicKey` wrapper) is
// accepted as well.
//
// Browser -> server: the resulting PublicKeyCredential is serialized to JSON
// with base64url binary fields (WebAuthn Level 3 "toJSON" shape, which
// go-webauthn parses).

import { base64urlToBuffer, encodeBase64url } from './base64url';

type JsonObject = Record<string, unknown>;

export class WebAuthnError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WebAuthnError';
  }
}

function isObject(v: unknown): v is JsonObject {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function requireString(v: unknown, field: string): string {
  if (typeof v !== 'string' || v.length === 0) {
    throw new WebAuthnError(`WebAuthn options: missing or invalid "${field}"`);
  }
  return v;
}

/** Shallow copy without null/undefined members (browsers reject null sequences). */
function compact(obj: JsonObject): JsonObject {
  const out: JsonObject = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== null && v !== undefined) out[k] = v;
  }
  return out;
}

function unwrap(options: unknown): { publicKey: JsonObject; outer: JsonObject } {
  if (!isObject(options)) throw new WebAuthnError('WebAuthn options: expected an object');
  if (isObject(options.publicKey)) return { publicKey: options.publicKey, outer: options };
  return { publicKey: options, outer: {} };
}

function convertDescriptors(list: unknown, field: string): PublicKeyCredentialDescriptor[] | undefined {
  if (list === undefined || list === null) return undefined;
  if (!Array.isArray(list)) throw new WebAuthnError(`WebAuthn options: "${field}" must be an array`);
  return list.map((item: unknown, i) => {
    if (!isObject(item)) throw new WebAuthnError(`WebAuthn options: invalid ${field}[${i}]`);
    const d = compact(item);
    return {
      ...d,
      type: typeof d.type === 'string' ? d.type : 'public-key',
      id: base64urlToBuffer(requireString(d.id, `${field}[${i}].id`)),
    } as PublicKeyCredentialDescriptor;
  });
}

/** Convert server creation options to `navigator.credentials.create()` input. */
export function toCreationOptions(options: unknown): CredentialCreationOptions {
  const { publicKey } = unwrap(options);
  const pk = compact(publicKey);
  if (!isObject(pk.user)) throw new WebAuthnError('WebAuthn options: missing "user"');
  const user = compact(pk.user);
  const exclude = convertDescriptors(pk.excludeCredentials, 'excludeCredentials');
  const out: JsonObject = {
    ...pk,
    challenge: base64urlToBuffer(requireString(pk.challenge, 'challenge')),
    user: { ...user, id: base64urlToBuffer(requireString(user.id, 'user.id')) },
  };
  if (exclude) out.excludeCredentials = exclude;
  else delete out.excludeCredentials;
  return { publicKey: out as unknown as PublicKeyCredentialCreationOptions };
}

/** Convert server request options to `navigator.credentials.get()` input. */
export function toRequestOptions(options: unknown): CredentialRequestOptions {
  const { publicKey, outer } = unwrap(options);
  const pk = compact(publicKey);
  const allow = convertDescriptors(pk.allowCredentials, 'allowCredentials');
  const out: JsonObject = {
    ...pk,
    challenge: base64urlToBuffer(requireString(pk.challenge, 'challenge')),
  };
  if (allow) out.allowCredentials = allow;
  else delete out.allowCredentials;
  const result: CredentialRequestOptions = {
    publicKey: out as unknown as PublicKeyCredentialRequestOptions,
  };
  if (typeof outer.mediation === 'string' && outer.mediation !== '') {
    result.mediation = outer.mediation as CredentialMediationRequirement;
  }
  return result;
}

// Structural types so serialization can be unit-tested without a browser.
export interface AttestationResponseLike {
  clientDataJSON: ArrayBuffer;
  attestationObject: ArrayBuffer;
  getTransports?: () => string[];
  getAuthenticatorData?: () => ArrayBuffer;
  getPublicKey?: () => ArrayBuffer | null;
  getPublicKeyAlgorithm?: () => number;
}

export interface AssertionResponseLike {
  clientDataJSON: ArrayBuffer;
  authenticatorData: ArrayBuffer;
  signature: ArrayBuffer;
  userHandle: ArrayBuffer | null;
}

export interface PublicKeyCredentialLike {
  id: string;
  rawId: ArrayBuffer;
  type: string;
  authenticatorAttachment?: string | null;
  response: AttestationResponseLike | AssertionResponseLike;
  getClientExtensionResults?: () => unknown;
}

function isBinary(v: unknown): v is ArrayBuffer | ArrayBufferView {
  return v instanceof ArrayBuffer || ArrayBuffer.isView(v);
}

/** Recursively convert binary values (e.g. in extension results) to base64url. */
function jsonify(v: unknown, depth = 0): unknown {
  if (depth > 8) return undefined;
  if (isBinary(v)) return encodeBase64url(v);
  if (Array.isArray(v)) return v.map((x) => jsonify(x, depth + 1));
  if (isObject(v)) {
    const out: JsonObject = {};
    for (const [k, val] of Object.entries(v)) out[k] = jsonify(val, depth + 1);
    return out;
  }
  return v;
}

function isAttestation(r: AttestationResponseLike | AssertionResponseLike): r is AttestationResponseLike {
  return 'attestationObject' in r;
}

function safeCall<T>(fn: (() => T) | undefined): T | undefined {
  if (typeof fn !== 'function') return undefined;
  try {
    return fn();
  } catch {
    return undefined;
  }
}

/** Serialize a PublicKeyCredential (attestation or assertion) to JSON. */
export function serializeCredential(cred: PublicKeyCredentialLike): JsonObject {
  const r = cred.response;
  const response: JsonObject = { clientDataJSON: encodeBase64url(r.clientDataJSON) };
  let transports: string[] | undefined;

  if (isAttestation(r)) {
    response.attestationObject = encodeBase64url(r.attestationObject);
    transports = safeCall(r.getTransports?.bind(r));
    if (Array.isArray(transports)) response.transports = transports;
    const authData = safeCall(r.getAuthenticatorData?.bind(r));
    if (isBinary(authData)) response.authenticatorData = encodeBase64url(authData);
    const publicKey = safeCall(r.getPublicKey?.bind(r));
    if (isBinary(publicKey)) response.publicKey = encodeBase64url(publicKey);
    const alg = safeCall(r.getPublicKeyAlgorithm?.bind(r));
    if (typeof alg === 'number') response.publicKeyAlgorithm = alg;
  } else {
    response.authenticatorData = encodeBase64url(r.authenticatorData);
    response.signature = encodeBase64url(r.signature);
    if (r.userHandle && r.userHandle.byteLength > 0) {
      response.userHandle = encodeBase64url(r.userHandle);
    }
  }

  const out: JsonObject = {
    id: cred.id,
    rawId: encodeBase64url(cred.rawId),
    type: cred.type,
    response,
    clientExtensionResults: jsonify(safeCall(cred.getClientExtensionResults?.bind(cred)) ?? {}) ?? {},
  };
  if (cred.authenticatorAttachment) out.authenticatorAttachment = cred.authenticatorAttachment;
  // Older go-webauthn versions read transports from the top level.
  if (transports && transports.length > 0) out.transports = transports;
  return out;
}

export function isWebAuthnAvailable(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential === 'function' &&
    typeof navigator.credentials?.create === 'function'
  );
}

/** Run a registration ceremony with server-provided options. */
export async function createCredential(options: unknown): Promise<JsonObject> {
  if (!isWebAuthnAvailable()) throw new WebAuthnError('This browser does not support security keys (WebAuthn).');
  const cred = await navigator.credentials.create(toCreationOptions(options));
  if (!cred) throw new WebAuthnError('No credential was created.');
  return serializeCredential(cred as unknown as PublicKeyCredentialLike);
}

/** Run an authentication ceremony with server-provided options. */
export async function getAssertion(options: unknown): Promise<JsonObject> {
  if (!isWebAuthnAvailable()) throw new WebAuthnError('This browser does not support security keys (WebAuthn).');
  const cred = await navigator.credentials.get(toRequestOptions(options));
  if (!cred) throw new WebAuthnError('No credential was returned.');
  return serializeCredential(cred as unknown as PublicKeyCredentialLike);
}

/** Human-readable message for errors thrown by navigator.credentials. */
export function describeWebAuthnError(err: unknown): string {
  if (err instanceof WebAuthnError) return err.message;
  const name = err instanceof Error || (typeof DOMException !== 'undefined' && err instanceof DOMException)
    ? (err as Error).name
    : '';
  switch (name) {
    case 'NotAllowedError':
      return 'The security key request was cancelled or timed out.';
    case 'InvalidStateError':
      return 'This security key is already registered for your account.';
    case 'SecurityError':
      return 'Security keys are not available on this origin (HTTPS and a matching domain are required).';
    case 'NotSupportedError':
      return 'This security key does not support the requested options.';
    case 'AbortError':
      return 'The security key request was aborted.';
    default:
      return err instanceof Error && err.message ? err.message : 'Security key operation failed.';
  }
}
