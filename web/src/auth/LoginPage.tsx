import { useQuery } from '@tanstack/react-query';
import { useRouter, useSearch } from '@tanstack/react-router';
import { KeyRoundIcon, LockKeyholeIcon, SmartphoneIcon } from 'lucide-react';
import { useEffect, useId, useState, type ReactNode } from 'react';
import { api, call } from '@/api/client';
import { errorMessage, hasCode } from '@/api/errors';
import { refreshSession, sessionQuery } from '@/api/session';
import type { LoginResult, SessionInfo } from '@/api/types';
import { Logo } from '@/app/Logo';
import { Callout, ErrorState, LoadingState } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Field } from '@/components/ui/label';
import { cn, safeRedirect } from '@/lib/utils';
import { isWebAuthnAvailable } from '@/lib/webauthn';
import { logout } from './mfa';
import { SecurityKeyRegister, TotpEnroll } from './MfaEnroll';
import { MfaVerifyPanel } from './MfaVerifyPanel';

const MIN_PASSWORD = 12;

/**
 * Login state machine driven by LoginResult.state / SessionInfo.state:
 * credentials → pending_password_change → pending_mfa_enrollment →
 * pending_mfa → active.
 */
export function LoginPage() {
  const search = useSearch({ strict: false });
  const router = useRouter();
  const session = useQuery({ ...sessionQuery, refetchInterval: false });
  const [lastResult, setLastResult] = useState<LoginResult | null>(null);
  // The password typed in step 1, kept in memory only so a forced password
  // change does not ask for it again. Cleared after use.
  const [typedPassword, setTypedPassword] = useState<string | null>(null);

  const sessionState = session.data?.state ?? null;
  // If GET /auth/session does not (yet) expose a pending session, continue
  // with the state the last login step reported.
  const state = sessionState ?? (lastResult && lastResult.state !== 'active' ? lastResult.state : null);
  const cookieProblem = lastResult?.state === 'active' && sessionState === null && !session.isFetching;
  const redirectTo = safeRedirect((search as { redirect?: unknown }).redirect);

  useEffect(() => {
    if (sessionState === 'active') {
      router.history.replace(redirectTo);
    }
  }, [sessionState, redirectTo, router]);

  const advance = async (result: LoginResult) => {
    setLastResult(result);
    await refreshSession();
  };

  const startOver = async () => {
    setTypedPassword(null);
    setLastResult(null);
    await logout();
  };

  let body: ReactNode;
  if (session.isPending) body = <LoadingState label="Checking session…" />;
  else if (session.isError) body = <ErrorState error={session.error} onRetry={() => void session.refetch()} compact />;
  else if (state === null)
    body = (
      <>
        {cookieProblem && (
          <Callout tone="warning" title="Session cookie not accepted" className="mb-4">
            The server accepted the sign-in, but the browser did not keep the session. Stellwerk must be served over
            HTTPS (or http://localhost in development).
          </Callout>
        )}
        <CredentialsStep
          onDone={async (res, password) => {
            setTypedPassword(password);
            await advance(res);
          }}
        />
      </>
    );
  else if (state === 'pending_password_change')
    body = (
      <PasswordChangeStep
        knownPassword={typedPassword}
        onDone={async (res) => {
          setTypedPassword(null);
          await advance(res);
        }}
      />
    );
  else if (state === 'pending_mfa_enrollment') body = <MfaEnrollmentStep methods={lastResult?.mfa_methods} onDone={advance} />;
  else if (state === 'pending_mfa') body = <MfaStep session={session.data} lastResult={lastResult} onDone={advance} />;
  else body = <LoadingState label="Signing in…" />;

  return (
    <div className="flex min-h-full items-center justify-center bg-background px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center justify-center gap-2">
          <Logo className="size-8" />
          <span className="text-xl font-semibold tracking-tight">Stellwerk</span>
        </div>
        <Card className="p-6">
          {state !== null && state !== 'active' && <StepIndicator state={state} />}
          {body}
          {state !== null && state !== 'active' && (
            <div className="mt-5 border-t pt-3 text-center">
              <button type="button" className="text-xs text-muted-foreground hover:text-foreground hover:underline" onClick={() => void startOver()}>
                Sign in as a different user
              </button>
            </div>
          )}
        </Card>
        <p className="mt-4 text-center text-xs text-muted-foreground">Access is logged and audited.</p>
      </div>
    </div>
  );
}

function StepIndicator({ state }: { state: SessionInfo['state'] }) {
  const steps = [
    { key: 'pending_password_change', label: 'Password' },
    { key: 'pending_mfa_enrollment', label: 'Second factor' },
    { key: 'pending_mfa', label: 'Verify' },
  ];
  const idx = steps.findIndex((s) => s.key === state);
  return (
    <ol className="mb-5 flex items-center gap-2 text-xs" aria-label="Sign-in progress">
      {steps.map((s, i) => (
        <li
          key={s.key}
          aria-current={i === idx ? 'step' : undefined}
          className={cn('flex-1 border-t-2 pt-1.5', i <= idx ? 'border-primary text-foreground' : 'border-border text-muted-foreground')}
        >
          {s.label}
        </li>
      ))}
    </ol>
  );
}

function StepTitle({ icon, title, children }: { icon: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="mb-4">
      <h1 className="flex items-center gap-2 text-base font-semibold">
        {icon}
        {title}
      </h1>
      {children && <p className="mt-1 text-sm text-muted-foreground">{children}</p>}
    </div>
  );
}

function CredentialsStep({ onDone }: { onDone: (r: LoginResult, password: string) => Promise<void> }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const uid = useId();
  const pid = useId();

  const submit = async () => {
    if (!username || !password || busy) return;
    setBusy(true);
    setError(null);
    try {
      const res = await call(api.POST('/auth/login', { body: { username: username.trim(), password } }));
      await onDone(res, password);
    } catch (e) {
      setPassword('');
      setError(
        hasCode(e, 'unauthenticated') || hasCode(e, 'invalid') || hasCode(e, 'forbidden')
          ? 'Invalid username or password, or the account is disabled.'
          : errorMessage(e),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="grid gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <StepTitle icon={<LockKeyholeIcon className="size-4 text-primary" />} title="Sign in" />
      <Field label="Username" htmlFor={uid}>
        <Input
          id={uid}
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          maxLength={64}
          autoFocus
          required
        />
      </Field>
      <Field label="Password" htmlFor={pid}>
        <Input
          id={pid}
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
          maxLength={1024}
          required
        />
      </Field>
      {error && (
        <p role="alert" className="text-sm text-text-critical">
          {error}
        </p>
      )}
      <Button type="submit" size="lg" disabled={busy || !username || !password}>
        {busy ? 'Signing in…' : 'Sign in'}
      </Button>
    </form>
  );
}

function PasswordChangeStep({
  knownPassword,
  onDone,
}: {
  knownPassword: string | null;
  onDone: (r: LoginResult) => Promise<void>;
}) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cid = useId();
  const nid = useId();
  const kid = useId();

  const currentValue = knownPassword ?? current;
  const problem =
    next.length > 0 && next.length < MIN_PASSWORD
      ? `At least ${MIN_PASSWORD} characters.`
      : next && next === currentValue
        ? 'The new password must differ from the current one.'
        : confirm && confirm !== next
          ? 'The passwords do not match.'
          : null;
  const ready = !!currentValue && next.length >= MIN_PASSWORD && next === confirm && next !== currentValue;

  const submit = async () => {
    if (!ready || busy) return;
    setBusy(true);
    setError(null);
    try {
      const res = await call(api.POST('/auth/password', { body: { current_password: currentValue, new_password: next } }));
      await onDone(res);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="grid gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <StepTitle icon={<LockKeyholeIcon className="size-4 text-primary" />} title="Choose a new password">
        Your password was set by an administrator and must be changed before you continue.
      </StepTitle>
      {knownPassword === null && (
        <Field label="Current (one-time) password" htmlFor={cid}>
          <Input id={cid} type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required />
        </Field>
      )}
      <Field label="New password" htmlFor={nid} hint={`At least ${MIN_PASSWORD} characters. A passphrase of several words works well.`}>
        <Input
          id={nid}
          type="password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          autoComplete="new-password"
          minLength={MIN_PASSWORD}
          maxLength={1024}
          autoFocus
          required
        />
      </Field>
      <Field label="Repeat new password" htmlFor={kid} error={problem}>
        <Input
          id={kid}
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password"
          maxLength={1024}
          aria-invalid={!!problem}
          required
        />
      </Field>
      {error && (
        <p role="alert" className="text-sm text-text-critical">
          {error}
        </p>
      )}
      <Button type="submit" size="lg" disabled={!ready || busy}>
        {busy ? 'Saving…' : 'Set password'}
      </Button>
    </form>
  );
}

function MfaEnrollmentStep({
  methods,
  onDone,
}: {
  methods: LoginResult['mfa_methods'];
  onDone: (r: LoginResult) => Promise<void>;
}) {
  // mfa_methods (when present) lists the factor types this user may enroll.
  const allowKey = !methods || methods.includes('webauthn');
  const allowTotp = !methods || methods.includes('totp');
  const [tab, setTab] = useState<'key' | 'totp'>(allowKey && isWebAuthnAvailable() ? 'key' : allowTotp ? 'totp' : 'key');

  return (
    <div>
      <StepTitle icon={<KeyRoundIcon className="size-4 text-primary" />} title="Set up a second factor">
        Multi-factor authentication is required. A hardware security key is recommended.
      </StepTitle>
      {allowKey && allowTotp && (
        <div role="tablist" aria-label="Second factor type" className="mb-4 grid grid-cols-2 rounded-md bg-muted p-0.5 text-sm">
          {(
            [
              ['key', 'Security key', KeyRoundIcon],
              ['totp', 'Authenticator app', SmartphoneIcon],
            ] as const
          ).map(([key, label, Icon]) => (
            <button
              key={key}
              type="button"
              role="tab"
              aria-selected={tab === key}
              onClick={() => setTab(key)}
              className={cn(
                'flex items-center justify-center gap-1.5 rounded px-2 py-1.5 text-xs font-medium',
                tab === key ? 'bg-card shadow-xs' : 'text-muted-foreground hover:text-foreground',
              )}
            >
              <Icon className="size-3.5" /> {label}
            </button>
          ))}
        </div>
      )}
      {tab === 'key' && allowKey ? <SecurityKeyRegister onDone={onDone} /> : <TotpEnroll onDone={onDone} />}
    </div>
  );
}

function MfaStep({
  session,
  lastResult,
  onDone,
}: {
  session: SessionInfo | null | undefined;
  lastResult: LoginResult | null;
  onDone: (r: LoginResult) => Promise<void>;
}) {
  // Prefer the methods the login step reported; fall back to the session's
  // MFA summary (e.g. after a page reload).
  const reported = lastResult?.mfa_methods;
  const methods = reported
    ? { webauthn: reported.includes('webauthn'), totp: reported.includes('totp') }
    : session
      ? { webauthn: session.mfa.webauthn > 0, totp: session.mfa.totp }
      : { webauthn: true, totp: true };
  return (
    <div>
      <StepTitle icon={<KeyRoundIcon className="size-4 text-primary" />} title="Verify it is you">
        Confirm the sign-in with your second factor.
      </StepTitle>
      <MfaVerifyPanel methods={methods} onVerified={onDone} />
    </div>
  );
}
