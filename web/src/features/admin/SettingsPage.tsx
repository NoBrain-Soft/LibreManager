import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { MailIcon, PlusIcon, SendIcon, Trash2Icon, WebhookIcon } from 'lucide-react';
import { useId, useState, type ReactNode } from 'react';
import { api } from '@/api/client';
import { qk } from '@/api/keys';
import { settingsQuery } from '@/api/queries';
import { request } from '@/api/request';
import type { Settings, ShellIdentityMode, WebhookTarget } from '@/api/types';
import { usePermissions } from '@/auth/usePermissions';
import { Page, PageHeader } from '@/components/common/PageHeader';
import { Callout, ErrorState, ForbiddenState, LoadingState } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input, NativeSelect, Textarea } from '@/components/ui/input';
import { Field, Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/misc';
import { notifyError, notifySuccess } from '@/lib/notify';
import { UNIX_USER_RE } from '../shell/protocol';
import { splitList } from '../jobs/jobForm';

export function SettingsPage() {
  const perms = usePermissions();
  const allowed = perms.canAnywhere('admin.settings');
  // No background refetch: it would reset the form while editing. The form
  // is re-keyed only when the cached settings change (e.g. after saving).
  const q = useQuery({ ...settingsQuery, enabled: allowed, staleTime: Infinity, refetchOnWindowFocus: false });

  if (!allowed) {
    return (
      <Page>
        <PageHeader title="Settings" />
        <Card>
          <ForbiddenState />
        </Card>
      </Page>
    );
  }
  return (
    <Page className="mx-0 max-w-4xl">
      <PageHeader title="Settings" description="Server-wide configuration. Changes are audited." />
      {q.isPending ? (
        <LoadingState />
      ) : q.isError ? (
        <Card>
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        </Card>
      ) : (
        <SettingsForm key={q.dataUpdatedAt} initial={q.data} />
      )}
    </Page>
  );
}

// Secrets are write-only: the server returns "", and "" means "keep".
function withoutSecrets(s: Settings): string {
  return JSON.stringify({
    ...s,
    notifications: {
      ...s.notifications,
      email: { ...s.notifications.email, smtp_password: '' },
      webhooks: s.notifications.webhooks.map((w) => ({ ...w, secret: '' })),
    },
  });
}

function validate(s: Settings): string | null {
  const inRange = (v: number, min: number, max: number) => Number.isInteger(v) && v >= min && v <= max;
  if (!inRange(s.session.idle_minutes, 5, 1440)) return 'Idle timeout must be 5–1440 minutes.';
  if (!inRange(s.session.absolute_hours, 1, 168)) return 'Absolute session lifetime must be 1–168 hours.';
  if (!inRange(s.retention.metrics_days, 1, 3650)) return 'Metrics retention must be 1–3650 days.';
  if (!inRange(s.retention.audit_days, 365, 36500)) return 'Audit retention must be at least 365 days.';
  if (!inRange(s.retention.recordings_days, 1, 3650)) return 'Recording retention must be 1–3650 days.';
  if (!inRange(s.retention.job_output_days, 1, 3650)) return 'Job output retention must be 1–3650 days.';
  if (!inRange(s.shell.max_duration_minutes, 1, 1440)) return 'Maximum shell duration must be 1–1440 minutes.';
  if (!inRange(s.shell.idle_timeout_minutes, 1, 1440)) return 'Shell idle timeout must be 1–1440 minutes.';
  if (s.shell.default_identity === 'shared' && !UNIX_USER_RE.test(s.shell.shared_account)) {
    return 'The shared shell account must be a valid unix user name.';
  }
  const e = s.notifications.email;
  if (e.enabled) {
    if (!e.smtp_host) return 'SMTP host is required when email is enabled.';
    if (e.smtp_port !== undefined && !inRange(e.smtp_port, 1, 65535)) return 'SMTP port must be 1–65535.';
    if (!e.from) return 'A sender address is required when email is enabled.';
    if (!e.to?.length) return 'Add at least one recipient.';
    if (e.to.length > 50) return 'At most 50 recipients.';
  }
  const names = new Set<string>();
  for (const w of s.notifications.webhooks) {
    if (!w.name.trim()) return 'Every webhook needs a name.';
    if (names.has(w.name)) return `Duplicate webhook name "${w.name}".`;
    names.add(w.name);
    let url: URL;
    try {
      url = new URL(w.url);
    } catch {
      return `Webhook "${w.name}": invalid URL.`;
    }
    if (url.protocol !== 'https:') return `Webhook "${w.name}": only https:// URLs are allowed.`;
    if (url.username || url.password) return `Webhook "${w.name}": do not put credentials in the URL; use the signing secret.`;
  }
  if (s.notifications.webhooks.length > 20) return 'At most 20 webhooks.';
  return null;
}

function Section({ title, description, children }: { title: string; description?: string; children: ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>{title}</CardTitle>
          {description && <CardDescription>{description}</CardDescription>}
        </div>
      </CardHeader>
      <CardContent className="grid gap-4">{children}</CardContent>
    </Card>
  );
}

function NumberField({
  label,
  value,
  onChange,
  min,
  max,
  hint,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
  min: number;
  max: number;
  hint?: string;
}) {
  const id = useId();
  return (
    <Field label={label} htmlFor={id} hint={hint ?? `${min}–${max}`}>
      <Input id={id} type="number" min={min} max={max} value={Number.isFinite(value) ? value : ''} onChange={(e) => onChange(e.target.valueAsNumber)} />
    </Field>
  );
}

function ToggleRow({ label, description, checked, onChange }: { label: string; description?: string; checked: boolean; onChange: (v: boolean) => void }) {
  const id = useId();
  return (
    <div className="flex items-center justify-between gap-4">
      <div>
        <Label htmlFor={id}>{label}</Label>
        {description && <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>}
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} />
    </div>
  );
}

function SettingsForm({ initial }: { initial: Settings }) {
  const qc = useQueryClient();
  const [s, setS] = useState<Settings>(() => structuredClone(initial));
  const [error, setError] = useState<string | null>(null);
  const [smtpPassword, setSmtpPassword] = useState('');
  const [secrets, setSecrets] = useState<string[]>(() => initial.notifications.webhooks.map(() => ''));
  const ids = { smtpHost: useId(), smtpUser: useId(), smtpPass: useId(), from: useId(), to: useId(), identity: useId(), account: useId() };
  const [toText, setToText] = useState((initial.notifications.email.to ?? []).join('\n'));

  const dirty =
    withoutSecrets(s) !== withoutSecrets(initial) ||
    splitList(toText).join(',') !== (initial.notifications.email.to ?? []).join(',') ||
    smtpPassword !== '' ||
    secrets.some(Boolean);

  const save = useMutation({
    mutationFn: (body: Settings) => request(() => api.PUT('/settings', { body })),
    onSuccess: (res) => {
      qc.setQueryData(qk.settings, res);
      notifySuccess('Settings saved');
    },
    onError: (e) => notifyError(e, 'Could not save settings'),
  });

  const test = useMutation({
    mutationFn: (body: { channel: 'email' | 'webhook'; webhook_name?: string }) =>
      request(() => api.POST('/settings/notifications/test', { body })),
    onSuccess: () => notifySuccess('Test notification sent'),
    onError: (e) => notifyError(e, 'Test notification failed'),
  });

  const set = (fn: (d: Settings) => void) =>
    setS((prev) => {
      const next = structuredClone(prev);
      fn(next);
      return next;
    });

  const submit = () => {
    const body = structuredClone(s);
    body.notifications.email.to = splitList(toText);
    body.notifications.email.smtp_password = smtpPassword;
    body.notifications.webhooks = body.notifications.webhooks.map((w, i) => ({ ...w, secret: secrets[i] ?? '' }));
    const err = validate(body);
    setError(err);
    if (!err) save.mutate(body);
  };

  const email = s.notifications.email;
  const hooks = s.notifications.webhooks;

  return (
    <form
      className="grid gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      <Section title="Sessions" description="Server-side web sessions. Step-up authentication stays valid for 5 minutes.">
        <div className="grid gap-3 sm:grid-cols-2">
          <NumberField label="Idle timeout (minutes)" value={s.session.idle_minutes} min={5} max={1440} onChange={(v) => set((d) => void (d.session.idle_minutes = v))} />
          <NumberField label="Absolute lifetime (hours)" value={s.session.absolute_hours} min={1} max={168} onChange={(v) => set((d) => void (d.session.absolute_hours = v))} />
        </div>
      </Section>

      <Section title="Multi-factor authentication">
        <ToggleRow
          label="Require MFA for all accounts"
          description="Users must enroll a security key (or an authenticator app, if allowed) before using Stellwerk."
          checked={s.security.mfa_required}
          onChange={(v) => set((d) => void (d.security.mfa_required = v))}
        />
        <ToggleRow
          label="Allow authenticator apps (TOTP)"
          description="When off, only WebAuthn security keys are accepted."
          checked={s.security.allow_totp}
          onChange={(v) => set((d) => void (d.security.allow_totp = v))}
        />
        {!s.security.mfa_required && <Callout tone="warning" title="MFA not enforced">Accounts without a second factor can sign in with a password only.</Callout>}
      </Section>

      <Section title="Retention" description="How long data is kept before it is deleted.">
        <div className="grid gap-3 sm:grid-cols-2">
          <NumberField label="Metrics (days)" value={s.retention.metrics_days} min={1} max={3650} onChange={(v) => set((d) => void (d.retention.metrics_days = v))} />
          <NumberField label="Audit log (days)" value={s.retention.audit_days} min={365} max={36500} hint="At least one year" onChange={(v) => set((d) => void (d.retention.audit_days = v))} />
          <NumberField label="Shell recordings (days)" value={s.retention.recordings_days} min={1} max={3650} onChange={(v) => set((d) => void (d.retention.recordings_days = v))} />
          <NumberField label="Job output (days)" value={s.retention.job_output_days} min={1} max={3650} onChange={(v) => set((d) => void (d.retention.job_output_days = v))} />
        </div>
      </Section>

      <Section title="Shell defaults" description="Fleet-wide defaults; host groups can override them.">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Login identity" htmlFor={ids.identity}>
            <NativeSelect
              id={ids.identity}
              value={s.shell.default_identity}
              onChange={(e) => set((d) => void (d.shell.default_identity = e.target.value as ShellIdentityMode))}
            >
              <option value="shared">Shared account for everyone</option>
              <option value="per_user">Per user (Stellwerk username)</option>
              <option value="choose">User chooses (within host policy)</option>
            </NativeSelect>
          </Field>
          <Field label="Shared account" htmlFor={ids.account} hint="Used when the identity is “shared”">
            <Input
              id={ids.account}
              value={s.shell.shared_account}
              onChange={(e) => set((d) => void (d.shell.shared_account = e.target.value.toLowerCase()))}
              maxLength={32}
              className="font-mono"
              spellCheck={false}
            />
          </Field>
          <NumberField label="Maximum duration (minutes)" value={s.shell.max_duration_minutes} min={1} max={1440} onChange={(v) => set((d) => void (d.shell.max_duration_minutes = v))} />
          <NumberField label="Idle timeout (minutes)" value={s.shell.idle_timeout_minutes} min={1} max={1440} onChange={(v) => set((d) => void (d.shell.idle_timeout_minutes = v))} />
        </div>
        <ToggleRow
          label="Allow root shells"
          description="Users with shell.root may request root sessions, if the host's local policy also allows it."
          checked={s.shell.allow_root}
          onChange={(v) => set((d) => void (d.shell.allow_root = v))}
        />
      </Section>

      <Section title="Email notifications" description="Alerts and job results via SMTP.">
        <ToggleRow label="Send email" checked={email.enabled} onChange={(v) => set((d) => void (d.notifications.email.enabled = v))} />
        {email.enabled && (
          <>
            <div className="grid gap-3 sm:grid-cols-[1fr_8rem]">
              <Field label="SMTP host" htmlFor={ids.smtpHost}>
                <Input id={ids.smtpHost} value={email.smtp_host ?? ''} onChange={(e) => set((d) => void (d.notifications.email.smtp_host = e.target.value))} maxLength={255} />
              </Field>
              <NumberField
                label="Port"
                value={email.smtp_port ?? 587}
                min={1}
                max={65535}
                hint="587 / 465"
                onChange={(v) => set((d) => void (d.notifications.email.smtp_port = v))}
              />
              <Field label="Username" htmlFor={ids.smtpUser}>
                <Input
                  id={ids.smtpUser}
                  value={email.smtp_username ?? ''}
                  onChange={(e) => set((d) => void (d.notifications.email.smtp_username = e.target.value))}
                  autoComplete="off"
                  maxLength={255}
                />
              </Field>
              <div className="flex items-end pb-1.5">
                <ToggleRow label="STARTTLS" checked={email.starttls ?? true} onChange={(v) => set((d) => void (d.notifications.email.starttls = v))} />
              </div>
            </div>
            <Field label="Password" htmlFor={ids.smtpPass} hint="Write-only. Leave empty to keep the stored password.">
              <Input
                id={ids.smtpPass}
                type="password"
                value={smtpPassword}
                onChange={(e) => setSmtpPassword(e.target.value)}
                autoComplete="new-password"
                placeholder="•••••••• (unchanged)"
                maxLength={255}
              />
            </Field>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="From" htmlFor={ids.from}>
                <Input id={ids.from} value={email.from ?? ''} onChange={(e) => set((d) => void (d.notifications.email.from = e.target.value))} placeholder="stellwerk@example.com" maxLength={255} />
              </Field>
              <Field label="Recipients" htmlFor={ids.to} hint="One per line or comma-separated">
                <Textarea id={ids.to} rows={2} value={toText} onChange={(e) => setToText(e.target.value)} />
              </Field>
            </div>
          </>
        )}
        <div className="flex items-center justify-end gap-2">
          {dirty && <span className="text-xs text-muted-foreground">Save first: tests use the stored settings.</span>}
          <Button variant="outline" size="sm" disabled={dirty || !initial.notifications.email.enabled || test.isPending} onClick={() => test.mutate({ channel: 'email' })}>
            <MailIcon /> Send test email
          </Button>
        </div>
      </Section>

      <Section title="Webhooks" description="JSON POSTs signed with HMAC-SHA256 (header X-Stellwerk-Signature).">
        {hooks.length === 0 && <p className="text-sm text-muted-foreground">No webhooks configured.</p>}
        {hooks.map((w, i) => (
          <WebhookRow
            key={i}
            hook={w}
            secret={secrets[i] ?? ''}
            onSecret={(v) => setSecrets((prev) => prev.map((x, idx) => (idx === i ? v : x)))}
            onChange={(patch) => set((d) => void Object.assign(d.notifications.webhooks[i] ?? {}, patch))}
            onRemove={() => {
              set((d) => void d.notifications.webhooks.splice(i, 1));
              setSecrets((prev) => prev.filter((_, idx) => idx !== i));
            }}
            canTest={!dirty && initial.notifications.webhooks.some((x) => x.name === w.name && x.enabled)}
            onTest={() => test.mutate({ channel: 'webhook', webhook_name: w.name })}
            testing={test.isPending}
          />
        ))}
        <Button
          variant="outline"
          size="sm"
          className="w-fit"
          disabled={hooks.length >= 20}
          onClick={() => {
            set((d) => void d.notifications.webhooks.push({ name: '', url: 'https://', enabled: true, min_severity: 'warning' }));
            setSecrets((prev) => [...prev, '']);
          }}
        >
          <PlusIcon /> Add webhook
        </Button>
      </Section>

      <div className="sticky bottom-0 -mx-1 flex items-center justify-end gap-3 border-t bg-background/95 px-1 py-3 backdrop-blur">
        {error && (
          <p role="alert" className="mr-auto text-sm text-text-critical">
            {error}
          </p>
        )}
        <Button
          variant="outline"
          disabled={!dirty || save.isPending}
          onClick={() => {
            setS(structuredClone(initial));
            setSmtpPassword('');
            setSecrets(initial.notifications.webhooks.map(() => ''));
            setToText((initial.notifications.email.to ?? []).join('\n'));
            setError(null);
          }}
        >
          Discard changes
        </Button>
        <Button type="submit" disabled={!dirty || save.isPending}>
          {save.isPending ? 'Saving…' : 'Save settings'}
        </Button>
      </div>
    </form>
  );
}

function WebhookRow({
  hook,
  secret,
  onSecret,
  onChange,
  onRemove,
  canTest,
  onTest,
  testing,
}: {
  hook: WebhookTarget;
  secret: string;
  onSecret: (v: string) => void;
  onChange: (patch: Partial<WebhookTarget>) => void;
  onRemove: () => void;
  canTest: boolean;
  onTest: () => void;
  testing: boolean;
}) {
  const ids = { n: useId(), u: useId(), s: useId(), sev: useId(), en: useId() };
  return (
    <div className="grid gap-3 rounded-md border p-3">
      <div className="flex items-center gap-2">
        <WebhookIcon className="size-4 text-muted-foreground" aria-hidden />
        <span className="flex-1 truncate text-sm font-medium">{hook.name || 'New webhook'}</span>
        <Label htmlFor={ids.en} className="text-xs text-muted-foreground">
          Enabled
        </Label>
        <Switch id={ids.en} checked={hook.enabled} onCheckedChange={(v) => onChange({ enabled: v })} />
        <Button variant="ghost" size="sm" onClick={onTest} disabled={!canTest || testing} title={canTest ? 'Send a test event' : 'Save first'}>
          <SendIcon /> Test
        </Button>
        <Button variant="ghost" size="icon-sm" onClick={onRemove} aria-label={`Remove webhook ${hook.name}`}>
          <Trash2Icon />
        </Button>
      </div>
      <div className="grid gap-3 sm:grid-cols-[12rem_1fr]">
        <Field label="Name" htmlFor={ids.n}>
          <Input id={ids.n} value={hook.name} onChange={(e) => onChange({ name: e.target.value })} maxLength={64} />
        </Field>
        <Field label="URL" htmlFor={ids.u} hint="https:// only">
          <Input id={ids.u} value={hook.url} onChange={(e) => onChange({ url: e.target.value })} maxLength={2048} className="font-mono text-xs" spellCheck={false} />
        </Field>
        <Field label="Minimum severity" htmlFor={ids.sev}>
          <NativeSelect
            id={ids.sev}
            value={hook.min_severity ?? 'warning'}
            onChange={(e) => onChange({ min_severity: e.target.value as WebhookTarget['min_severity'] })}
          >
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
          </NativeSelect>
        </Field>
        <Field label="Signing secret" htmlFor={ids.s} hint="Write-only. Leave empty to keep the stored secret.">
          <Input
            id={ids.s}
            type="password"
            value={secret}
            onChange={(e) => onSecret(e.target.value)}
            autoComplete="new-password"
            placeholder="•••••••• (unchanged)"
            maxLength={255}
          />
        </Field>
      </div>
    </div>
  );
}
