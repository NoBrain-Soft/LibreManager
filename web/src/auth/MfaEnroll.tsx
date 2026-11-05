import { KeyRoundIcon, SmartphoneIcon } from 'lucide-react';
import { useId, useState } from 'react';
import { errorMessage } from '@/api/errors';
import type { LoginResult, TotpEnrollment } from '@/api/types';
import { CopyButton } from '@/components/common/CopyButton';
import { QrCode } from '@/components/common/QrCode';
import { Callout } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Field } from '@/components/ui/label';
import { describeWebAuthnError, isWebAuthnAvailable, WebAuthnError } from '@/lib/webauthn';
import {
  beginTotpEnrollment,
  confirmTotpEnrollment,
  normalizeTotp,
  registerSecurityKey,
  TOTP_PATTERN,
} from './mfa';

function message(e: unknown): string {
  if (e instanceof WebAuthnError || e instanceof DOMException) return describeWebAuthnError(e);
  return errorMessage(e);
}

export function SecurityKeyRegister({ onDone }: { onDone: (r: LoginResult) => Promise<void> | void }) {
  const [name, setName] = useState('Security key');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const id = useId();
  const available = isWebAuthnAvailable();

  const submit = async () => {
    const n = name.trim();
    if (!n || busy) return;
    setBusy(true);
    setError(null);
    try {
      await onDone(await registerSecurityKey(n));
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="grid gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      {!available && (
        <Callout tone="warning" title="Security keys unavailable">
          This browser or connection does not support WebAuthn (HTTPS is required).
        </Callout>
      )}
      <Field label="Name for this key" htmlFor={id} hint="Helps you tell keys apart later, e.g. “YubiKey blue”.">
        <Input id={id} value={name} onChange={(e) => setName(e.target.value)} maxLength={64} required disabled={!available} />
      </Field>
      {error && (
        <p role="alert" className="text-sm text-text-critical">
          {error}
        </p>
      )}
      <Button type="submit" disabled={!available || busy || !name.trim()}>
        <KeyRoundIcon /> {busy ? 'Touch your security key…' : 'Register security key'}
      </Button>
    </form>
  );
}

export function TotpEnroll({ onDone }: { onDone: (r: LoginResult) => Promise<void> | void }) {
  const [enrollment, setEnrollment] = useState<TotpEnrollment | null>(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const codeId = useId();

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      setEnrollment(await beginTotpEnrollment());
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    if (!TOTP_PATTERN.test(code) || busy) return;
    setBusy(true);
    setError(null);
    try {
      await onDone(await confirmTotpEnrollment(code));
    } catch (e) {
      setError(message(e));
      setCode('');
    } finally {
      setBusy(false);
    }
  };

  if (!enrollment) {
    return (
      <div className="grid gap-3">
        <p className="text-sm text-muted-foreground">
          Use an authenticator app (e.g. FreeOTP, Aegis, Google Authenticator) to generate 6-digit codes.
        </p>
        {error && (
          <p role="alert" className="text-sm text-text-critical">
            {error}
          </p>
        )}
        <Button onClick={() => void start()} disabled={busy}>
          <SmartphoneIcon /> {busy ? 'Generating…' : 'Set up authenticator app'}
        </Button>
      </div>
    );
  }

  return (
    <form
      className="grid gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        void confirm();
      }}
    >
      <div className="flex flex-col items-center gap-3 sm:flex-row sm:items-start">
        <QrCode value={enrollment.otpauth_url} size={168} label="TOTP enrollment QR code" />
        <div className="grid min-w-0 gap-2 text-sm">
          <p className="text-muted-foreground">Scan the code with your app, or enter this secret manually:</p>
          <div className="flex items-center gap-1.5">
            <code className="min-w-0 break-all rounded bg-muted px-2 py-1 font-mono text-xs">{enrollment.secret}</code>
            <CopyButton text={enrollment.secret} size="icon-sm" label="Copy secret" />
          </div>
          <p className="text-xs text-muted-foreground">The secret is shown only now. Do not share it.</p>
        </div>
      </div>
      <Field label="Enter the current 6-digit code to confirm" htmlFor={codeId}>
        <Input
          id={codeId}
          value={code}
          onChange={(e) => setCode(normalizeTotp(e.target.value))}
          inputMode="numeric"
          autoComplete="one-time-code"
          placeholder="123456"
          className="font-mono tracking-[0.3em]"
          autoFocus
        />
      </Field>
      {error && (
        <p role="alert" className="text-sm text-text-critical">
          {error}
        </p>
      )}
      <Button type="submit" disabled={!TOTP_PATTERN.test(code) || busy}>
        {busy ? 'Verifying…' : 'Confirm and enable'}
      </Button>
    </form>
  );
}
