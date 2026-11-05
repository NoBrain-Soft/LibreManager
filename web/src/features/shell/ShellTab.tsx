import { useQuery } from '@tanstack/react-query';
import { CircleStopIcon, PlugIcon, RotateCwIcon, ShieldAlertIcon, TerminalIcon, VideoIcon } from 'lucide-react';
import { useId, useRef, useState } from 'react';
import { api } from '@/api/client';
import { errorMessage, StepUpCancelledError } from '@/api/errors';
import { groupsQuery, settingsQuery } from '@/api/queries';
import { request } from '@/api/request';
import type { ShellSession } from '@/api/types';
import { usePermissions } from '@/auth/usePermissions';
import { Callout } from '@/components/common/states';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Field } from '@/components/ui/label';
import { asArray, cn, field, str } from '@/lib/utils';
import { policyFlag, useCurrentHost } from '../hosts/hostUtils';
import { effectiveShell } from './identity';
import { estimateSize, shellSocketUrl, UNIX_USER_RE } from './protocol';
import { type TermStatus, type TerminalHandle, TerminalSession } from './TerminalSession';

type Phase =
  | { kind: 'idle' }
  | { kind: 'requesting' }
  | { kind: 'session'; session: ShellSession; url: string; status: TermStatus };

export function ShellTab() {
  const { data: host } = useCurrentHost();
  const perms = usePermissions();
  const groups = useQuery({ ...groupsQuery, retry: false });
  const settings = useQuery({ ...settingsQuery, enabled: perms.canAnywhere('admin.settings'), retry: false });
  const [phase, setPhase] = useState<Phase>({ kind: 'idle' });
  const [unixUser, setUnixUser] = useState('');
  const [error, setError] = useState<string | null>(null);
  const termRef = useRef<TerminalHandle>(null);
  const areaRef = useRef<HTMLDivElement>(null);
  const userId = useId();
  const listId = useId();

  if (!host) return null;

  const canShell = perms.canOnHost('shell.open', host);
  const canRoot = perms.canOnHost('shell.root', host);
  const policyShell = policyFlag(host, 'shell');
  const policyRoot = policyFlag(host, 'shell_allow_root');
  const allowedUsers = asArray(field(host.policy, 'shell_allowed_users'))
    .map(str)
    .filter((u) => u && !u.startsWith('%') && u !== '*');

  const eff = effectiveShell(
    host.groups.map((g) => g.id),
    groups.data,
    settings.data?.shell,
  );
  const username = perms.session?.user.username ?? '';
  const asksUser = eff.mode === 'choose' || eff.mode === null;
  const requiresUser = eff.mode === 'choose';
  const rootPossible = canRoot && eff.allowRoot !== false && policyRoot !== false;
  const typed = unixUser.trim();
  const userError =
    typed && !UNIX_USER_RE.test(typed)
      ? 'Lowercase letters, digits, "_", "." and "-" only (max 32).'
      : typed === 'root' && !rootPossible
        ? 'Root shells are not permitted for you on this host.'
        : null;

  const open = async () => {
    setError(null);
    if (requiresUser && !typed) {
      setError('Choose the unix account to log in as.');
      return;
    }
    if (userError) return;
    const area = areaRef.current?.getBoundingClientRect();
    const { cols, rows } = estimateSize(area?.width ?? 960, Math.max(420, (area?.height ?? 0) || 560));
    setPhase({ kind: 'requesting' });
    try {
      const session = await request(() =>
        api.POST('/hosts/{hostId}/shell', {
          params: { path: { hostId: host.id } },
          body: { cols, rows, ...(asksUser && typed ? { unix_user: typed } : {}) },
        }),
      );
      setPhase({ kind: 'session', session, url: shellSocketUrl(session, host.id), status: { state: 'connecting' } });
    } catch (e) {
      setPhase({ kind: 'idle' });
      if (!(e instanceof StepUpCancelledError)) setError(errorMessage(e));
    }
  };

  if (!canShell || policyShell === false) {
    return (
      <Card>
        <CardContent>
          <Callout tone="info" title="Shell not available">
            {!canShell ? 'Your role does not allow opening shells on this host.' : "The host's local policy disables remote shells."}
          </Callout>
        </CardContent>
      </Card>
    );
  }

  if (phase.kind !== 'session') {
    return (
      <div ref={areaRef} className="grid gap-4 lg:grid-cols-[minmax(0,28rem)_1fr]">
        <Card>
          <CardHeader>
            <div>
              <CardTitle className="flex items-center gap-2">
                <TerminalIcon className="size-4" /> Open a shell on {host.hostname}
              </CardTitle>
              <CardDescription>Requires a fresh step-up. The session runs through the agent; no inbound ports are opened.</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="grid gap-4">
            <RecordingNotice />
            <div className="text-sm">
              <div className="mb-1 text-xs font-medium text-muted-foreground">Login identity</div>
              {eff.mode === 'shared' && (
                <p>
                  Shared account <code className="rounded bg-muted px-1 font-mono">{eff.sharedAccount ?? 'configured account'}</code>
                </p>
              )}
              {eff.mode === 'per_user' && (
                <p>
                  Your own account <code className="rounded bg-muted px-1 font-mono">{username}</code>
                </p>
              )}
              {eff.mode === 'choose' && <p>Choose an account allowed by the host policy.</p>}
              {eff.mode === null && (
                <p className="text-muted-foreground">
                  {eff.ambiguous ? 'The host is in groups with different shell settings; the server decides.' : 'Decided by the server based on group settings.'}
                </p>
              )}
            </div>
            {asksUser && (
              <Field
                label={requiresUser ? 'Unix account' : 'Unix account (optional)'}
                htmlFor={userId}
                error={userError}
                hint={requiresUser ? undefined : 'Only used when your administrator lets users choose the account.'}
              >
                <Input
                  id={userId}
                  list={allowedUsers.length ? listId : undefined}
                  value={unixUser}
                  onChange={(e) => setUnixUser(e.target.value.toLowerCase())}
                  placeholder={allowedUsers[0] ?? 'ops'}
                  autoComplete="off"
                  spellCheck={false}
                  maxLength={32}
                  className="font-mono"
                  aria-invalid={!!userError}
                />
                {allowedUsers.length > 0 && (
                  <datalist id={listId}>
                    {allowedUsers.map((u) => (
                      <option key={u} value={u} />
                    ))}
                    {rootPossible && <option value="root" />}
                  </datalist>
                )}
              </Field>
            )}
            {rootPossible && asksUser && (
              <p className="flex items-center gap-1.5 text-xs text-text-warning">
                <ShieldAlertIcon className="size-3.5" /> Root shells are allowed for you here; prefer sudo from a personal account.
              </p>
            )}
            {!host.connected && <Callout tone="warning" title="Host offline">The agent must be connected to open a shell.</Callout>}
            {error && <Callout tone="critical" title="Could not open the shell">{error}</Callout>}
            <Button onClick={() => void open()} disabled={!host.connected || phase.kind === 'requesting' || !!userError}>
              <PlugIcon /> {phase.kind === 'requesting' ? 'Requesting session…' : 'Open shell'}
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const st = phase.status;
  const ended = st.state === 'exited' || st.state === 'closed' || st.state === 'error';
  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap items-center gap-2 rounded-md border border-warning/45 bg-warning/10 px-3 py-1.5 text-xs">
        <VideoIcon className="size-3.5 text-text-warning" aria-hidden />
        <span className="font-medium">This session is recorded</span>
        <span className="text-muted-foreground">and logged to the host's journal.</span>
        <div className="flex-1" />
        <span className="font-mono text-muted-foreground">
          {phase.session.unix_user}@{host.hostname}
        </span>
        <SessionBadge status={st} />
        {!ended ? (
          <Button size="sm" variant="outline" onClick={() => termRef.current?.disconnect()}>
            <CircleStopIcon /> Disconnect
          </Button>
        ) : (
          <Button size="sm" onClick={() => setPhase({ kind: 'idle' })}>
            <RotateCwIcon /> New session
          </Button>
        )}
      </div>
      {ended && <EndBanner status={st} />}
      <div className={cn('overflow-hidden rounded-md border p-2', ended && 'opacity-80')} style={{ background: 'var(--term-bg)' }}>
        <TerminalSession
          ref={termRef}
          url={phase.url}
          className="h-[calc(100vh-19rem)] min-h-80"
          onStatus={(status) => setPhase((p) => (p.kind === 'session' ? { ...p, status } : p))}
        />
      </div>
    </div>
  );
}

function RecordingNotice() {
  return (
    <div className="flex items-start gap-2 rounded-md border border-warning/45 bg-warning/10 px-3 py-2 text-xs">
      <VideoIcon className="mt-0.5 size-3.5 shrink-0 text-text-warning" aria-hidden />
      <span>
        <span className="font-medium">Sessions are recorded</span> (encrypted at rest), audited, and announced on the host. Idle and maximum
        durations are enforced.
      </span>
    </div>
  );
}

function SessionBadge({ status }: { status: TermStatus }) {
  switch (status.state) {
    case 'connecting':
      return <Badge variant="info">Connecting…</Badge>;
    case 'open':
      return <Badge variant="good">Connected</Badge>;
    case 'exited':
      return <Badge variant="neutral">Exited</Badge>;
    case 'closed':
      return <Badge variant="neutral">Disconnected</Badge>;
    case 'error':
      return <Badge variant="critical">Error</Badge>;
  }
}

function EndBanner({ status }: { status: TermStatus }) {
  if (status.state === 'exited') {
    return (
      <Callout tone={status.code === 0 || status.code === null ? 'info' : 'warning'} title={`Shell exited${status.code !== null ? ` with code ${status.code}` : ''}`}>
        {status.reason || 'The remote shell ended.'}
      </Callout>
    );
  }
  if (status.state === 'closed') {
    return (
      <Callout tone={status.code === 1000 ? 'info' : 'warning'} title="Connection closed">
        {status.reason || (status.code === 1000 ? 'The session was closed.' : `The connection was lost (code ${status.code}).`)}
      </Callout>
    );
  }
  if (status.state === 'error') return <Callout tone="critical" title="Terminal error">{status.message}</Callout>;
  return null;
}
