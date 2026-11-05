import { KeyRoundIcon, SmartphoneIcon } from 'lucide-react';
import { useId, useState } from 'react';
import { errorMessage } from '@/api/errors';
import type { LoginResult } from '@/api/types';
import { Callout } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { describeWebAuthnError, isWebAuthnAvailable, WebAuthnError } from '@/lib/webauthn';
import { normalizeTotp, TOTP_PATTERN, verifyWithSecurityKey, verifyWithTotp } from './mfa';

export interface MfaMethods {
  webauthn: boolean;
  totp: boolean;
}

interface Props {
  methods: MfaMethods;
  onVerified: (result: LoginResult) => Promise<void> | void;
  /** Focus the most likely method. */
  autoFocus?: boolean;
}

function message(e: unknown): string {
  if (e instanceof WebAuthnError || e instanceof DOMException) return describeWebAuthnError(e);
  return errorMessage(e);
}

/** Verify with a security key and/or a TOTP code (login MFA and step-up). */
export function MfaVerifyPanel({ methods, onVerified, autoFocus = true }: Props) {
  const [busy, setBusy] = useState<'key' | 'totp' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const codeId = useId();
  const webauthnOk = methods.webauthn && isWebAuthnAvailable();

  const run = async (kind: 'key' | 'totp', fn: () => Promise<LoginResult>) => {
    setBusy(kind);
    setError(null);
    try {
      await onVerified(await fn());
    } catch (e) {
      setError(message(e));
      if (kind === 'totp') setCode('');
    } finally {
      setBusy(null);
    }
  };

  const submitTotp = () => {
    if (!TOTP_PATTERN.test(code) || busy) return;
    void run('totp', () => verifyWithTotp(code));
  };

  if (!methods.webauthn && !methods.totp) {
    return (
      <Callout tone="warning" title="No second factor available">
        Your account has no security key or authenticator app. Ask an administrator to reset your MFA.
      </Callout>
    );
  }

  return (
    <div className="grid gap-4">
      {methods.webauthn && (
        <div className="grid gap-2">
          <Button
            size="lg"
            className="w-full"
            onClick={() => void run('key', verifyWithSecurityKey)}
            disabled={busy !== null || !webauthnOk}
            autoFocus={autoFocus && webauthnOk}
          >
            <KeyRoundIcon />
            {busy === 'key' ? 'Waiting for security key…' : 'Use security key'}
          </Button>
          {!webauthnOk && (
            <p className="text-xs text-muted-foreground">
              Security keys need a browser with WebAuthn support and an HTTPS connection.
            </p>
          )}
        </div>
      )}

      {methods.webauthn && methods.totp && (
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span className="h-px flex-1 bg-border" />
          or
          <span className="h-px flex-1 bg-border" />
        </div>
      )}

      {methods.totp && (
        <form
          className="grid gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            submitTotp();
          }}
        >
          <Label htmlFor={codeId} className="flex items-center gap-1.5">
            <SmartphoneIcon className="size-3.5" /> Code from your authenticator app
          </Label>
          <div className="flex gap-2">
            <Input
              id={codeId}
              value={code}
              onChange={(e) => setCode(normalizeTotp(e.target.value))}
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
              maxLength={6}
              className="font-mono tracking-[0.3em]"
              autoFocus={autoFocus && !webauthnOk}
              aria-describedby={error ? `${codeId}-err` : undefined}
            />
            <Button type="submit" variant={methods.webauthn ? 'outline' : 'default'} disabled={!TOTP_PATTERN.test(code) || busy !== null}>
              {busy === 'totp' ? 'Verifying…' : 'Verify'}
            </Button>
          </div>
        </form>
      )}

      {error && (
        <p id={`${codeId}-err`} role="alert" className="text-sm text-text-critical">
          {error}
        </p>
      )}
    </div>
  );
}
