import { useQuery } from '@tanstack/react-query';
import { useId, useMemo, useState } from 'react';
import { groupsQuery, hostsQuery } from '@/api/queries';
import type { JobParams, JobType } from '@/api/types';
import { usePermissions } from '@/auth/usePermissions';
import { MultiSelect } from '@/components/common/MultiSelect';
import { Callout } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input, NativeSelect, Textarea } from '@/components/ui/input';
import { Field } from '@/components/ui/label';
import { JOB_TYPE_LABELS } from '@/lib/status';
import { pluralize } from '@/lib/utils';
import { buildParams, JOB_PERMISSION, JOB_TYPES, type JobFormValues, SERVICE_OPS, type ServiceOp } from './jobForm';
import { useCreateJob } from './useCreateJob';

export interface NewJobPreset {
  type?: JobType;
  hostIds?: string[];
  groupIds?: string[];
  params?: JobParams;
}

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  preset?: NewJobPreset;
}

export function NewJobDialog({ open, onOpenChange, preset }: Props) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && <NewJobForm preset={preset ?? {}} onClose={() => onOpenChange(false)} />}
    </Dialog>
  );
}

function NewJobForm({ preset, onClose }: { preset: NewJobPreset; onClose: () => void }) {
  const perms = usePermissions();
  const hosts = useQuery(hostsQuery({}));
  const groups = useQuery({ ...groupsQuery, retry: false });
  const create = useCreateJob({ navigateOnSuccess: true });
  const ids = { type: useId(), scope: useId(), pkgs: useId(), unit: useId(), op: useId(), delay: useId(), msg: useId(), checks: useId(), hosts: useId(), groups: useId() };

  const firstAllowed = JOB_TYPES.find((t) => perms.canAnywhere(JOB_PERMISSION[t])) ?? 'pkg_refresh';
  const p = preset.params ?? {};
  const [values, setValues] = useState<JobFormValues>({
    type: preset.type ?? firstAllowed,
    scope: p.scope ?? 'security',
    packages: (p.packages ?? []).join('\n'),
    unit: p.unit ?? '',
    op: p.op ?? 'restart',
    delay: String(p.delay_s ?? 0),
    message: p.message ?? '',
    checkIds: (p.check_ids ?? []).join(', '),
  });
  const [hostIds, setHostIds] = useState<string[]>(preset.hostIds ?? []);
  const [groupIds, setGroupIds] = useState<string[]>(preset.groupIds ?? []);
  const [submitted, setSubmitted] = useState(false);

  const set = <K extends keyof JobFormValues>(k: K, v: JobFormValues[K]) => setValues((s) => ({ ...s, [k]: v }));

  const hostOptions = useMemo(
    () =>
      (hosts.data ?? [])
        .filter((h) => h.status === 'active')
        .map((h) => ({ value: h.id, label: h.hostname, hint: h.connected ? undefined : 'offline' })),
    [hosts.data],
  );
  const groupOptions = useMemo(
    () => (groups.data ?? []).map((g) => ({ value: g.id, label: g.name, hint: pluralize(g.host_count, 'host') })),
    [groups.data],
  );

  const built = buildParams(values);
  const noTargets = hostIds.length === 0 && groupIds.length === 0;
  const error = built.error ?? (noTargets ? 'Choose at least one host or group.' : undefined);
  const highRisk = values.type === 'pkg_install' || values.type === 'pkg_remove';

  const submit = () => {
    setSubmitted(true);
    if (error || !built.params) return;
    create.mutate(
      {
        type: values.type,
        params: built.params,
        targets: {
          ...(hostIds.length ? { host_ids: hostIds } : {}),
          ...(groupIds.length ? { host_group_ids: groupIds } : {}),
        },
      },
      { onSuccess: onClose },
    );
  };

  return (
    <DialogContent size="lg">
      <form
        className="contents"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <DialogHeader>
          <DialogTitle>New job</DialogTitle>
          <DialogDescription>Jobs are signed centrally and verified by each host against its local policy.</DialogDescription>
        </DialogHeader>
        <DialogBody className="grid gap-4">
          <Field label="Action" htmlFor={ids.type}>
            <NativeSelect id={ids.type} value={values.type} onChange={(e) => set('type', e.target.value as JobType)}>
              {JOB_TYPES.map((t) => {
                const allowed = perms.canAnywhere(JOB_PERMISSION[t]);
                return (
                  <option key={t} value={t} disabled={!allowed}>
                    {JOB_TYPE_LABELS[t]}
                    {allowed ? '' : ' (no permission)'}
                  </option>
                );
              })}
            </NativeSelect>
          </Field>

          {values.type === 'pkg_upgrade' && (
            <Field label="Scope" htmlFor={ids.scope}>
              <NativeSelect id={ids.scope} value={values.scope} onChange={(e) => set('scope', e.target.value as JobFormValues['scope'])}>
                <option value="security">Security updates only</option>
                <option value="all">All updates</option>
                <option value="named">Named packages</option>
              </NativeSelect>
            </Field>
          )}

          {((values.type === 'pkg_upgrade' && values.scope === 'named') ||
            values.type === 'pkg_install' ||
            values.type === 'pkg_remove') && (
            <Field label="Packages" htmlFor={ids.pkgs} hint="One per line or separated by commas.">
              <Textarea
                id={ids.pkgs}
                rows={4}
                value={values.packages}
                onChange={(e) => set('packages', e.target.value)}
                className="font-mono text-xs"
                spellCheck={false}
              />
            </Field>
          )}

          {highRisk && (
            <Callout tone="warning" title="High-risk action">
              Installing or removing packages requires a fresh step-up and must be allowed by each host's local policy.
            </Callout>
          )}

          {values.type === 'service' && (
            <div className="grid grid-cols-[1fr_10rem] gap-3">
              <Field label="Unit" htmlFor={ids.unit}>
                <Input
                  id={ids.unit}
                  value={values.unit}
                  onChange={(e) => set('unit', e.target.value)}
                  placeholder="nginx.service"
                  className="font-mono"
                  spellCheck={false}
                />
              </Field>
              <Field label="Operation" htmlFor={ids.op}>
                <NativeSelect id={ids.op} value={values.op} onChange={(e) => set('op', e.target.value as ServiceOp)}>
                  {SERVICE_OPS.map((op) => (
                    <option key={op} value={op}>
                      {op}
                    </option>
                  ))}
                </NativeSelect>
              </Field>
            </div>
          )}

          {values.type === 'reboot' && (
            <div className="grid grid-cols-[8rem_1fr] gap-3">
              <Field label="Delay (seconds)" htmlFor={ids.delay}>
                <Input id={ids.delay} type="number" min={0} max={3600} value={values.delay} onChange={(e) => set('delay', e.target.value)} />
              </Field>
              <Field label="Message" htmlFor={ids.msg} hint="Optional, shown to logged-in users">
                <Input id={ids.msg} value={values.message} onChange={(e) => set('message', e.target.value)} maxLength={256} />
              </Field>
            </div>
          )}

          {values.type === 'run_check' && (
            <Field label="Check IDs" htmlFor={ids.checks} hint="Leave empty to run all checks, e.g. SSH-001, PKG-002.">
              <Input id={ids.checks} value={values.checkIds} onChange={(e) => set('checkIds', e.target.value)} className="font-mono" />
            </Field>
          )}

          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Hosts" htmlFor={ids.hosts}>
              <MultiSelect
                id={ids.hosts}
                options={hostOptions}
                value={hostIds}
                onChange={setHostIds}
                placeholder={hosts.isPending ? 'Loading hosts…' : 'Select hosts'}
              />
            </Field>
            <Field label="Host groups" htmlFor={ids.groups} hint={groups.isError ? 'Groups unavailable' : 'Includes all hosts in the group'}>
              <MultiSelect
                id={ids.groups}
                options={groupOptions}
                value={groupIds}
                onChange={setGroupIds}
                placeholder="Select groups"
                disabled={groups.isError}
              />
            </Field>
          </div>

          {submitted && error && <Callout tone="critical" title="Check the form">{error}</Callout>}
        </DialogBody>
        <DialogFooter>
          <span className="mr-auto text-xs text-muted-foreground">
            {JOB_TYPE_LABELS[values.type]} on {pluralize(hostIds.length, 'host')}
            {groupIds.length > 0 && ` + ${pluralize(groupIds.length, 'group')}`}
          </span>
          <Button variant="outline" onClick={onClose} disabled={create.isPending}>
            Cancel
          </Button>
          <Button type="submit" disabled={create.isPending || (submitted && !!error)}>
            {create.isPending ? 'Starting…' : 'Start job'}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
