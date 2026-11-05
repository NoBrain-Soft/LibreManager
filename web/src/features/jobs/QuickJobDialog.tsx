import { useId, useState } from 'react';
import type { JobCreate } from '@/api/types';
import { Callout } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Field } from '@/components/ui/label';
import { pluralize } from '@/lib/utils';
import { useCreateJob } from './useCreateJob';

export type QuickAction = 'refresh' | 'security' | 'all' | 'reboot' | 'named';

export interface QuickTarget {
  id: string;
  hostname: string;
}

const SPEC: Record<QuickAction, { title: string; verb: string; describe: string; destructive?: boolean }> = {
  refresh: {
    title: 'Refresh package lists',
    verb: 'Refresh',
    describe: 'Runs apt update / dnf makecache and re-checks pending updates.',
  },
  security: {
    title: 'Install security updates',
    verb: 'Upgrade',
    describe: 'Installs only updates classified as security fixes.',
  },
  all: {
    title: 'Install all updates',
    verb: 'Upgrade',
    describe: 'Installs every available package update.',
  },
  named: {
    title: 'Upgrade selected packages',
    verb: 'Upgrade',
    describe: 'Upgrades only the selected packages.',
  },
  reboot: {
    title: 'Reboot hosts',
    verb: 'Reboot',
    describe: 'Reboots the hosts. Running services will be interrupted.',
    destructive: true,
  },
};

interface Props {
  action: QuickAction | null;
  targets: readonly QuickTarget[];
  /** Hosts excluded because the user lacks permission on them. */
  excluded?: number;
  packages?: readonly string[];
  onOpenChange: (open: boolean) => void;
  onDone?: () => void;
}

export function QuickJobDialog({ action, targets, excluded = 0, packages, onOpenChange, onDone }: Props) {
  return (
    <Dialog open={action !== null} onOpenChange={onOpenChange}>
      {action !== null && (
        <QuickJobBody
          action={action}
          targets={targets}
          excluded={excluded}
          packages={packages}
          onClose={() => onOpenChange(false)}
          onDone={onDone}
        />
      )}
    </Dialog>
  );
}

function QuickJobBody({
  action,
  targets,
  excluded,
  packages,
  onClose,
  onDone,
}: {
  action: QuickAction;
  targets: readonly QuickTarget[];
  excluded: number;
  packages: readonly string[] | undefined;
  onClose: () => void;
  onDone: (() => void) | undefined;
}) {
  const spec = SPEC[action];
  const create = useCreateJob();
  const [delay, setDelay] = useState('0');
  const [message, setMessage] = useState('');
  const delayId = useId();
  const msgId = useId();
  const delayNum = Number(delay);
  const delayOk = Number.isInteger(delayNum) && delayNum >= 0 && delayNum <= 3600;

  const submit = () => {
    const host_ids = targets.map((t) => t.id);
    let body: JobCreate;
    switch (action) {
      case 'refresh':
        body = { type: 'pkg_refresh', targets: { host_ids } };
        break;
      case 'security':
        body = { type: 'pkg_upgrade', params: { scope: 'security' }, targets: { host_ids } };
        break;
      case 'all':
        body = { type: 'pkg_upgrade', params: { scope: 'all' }, targets: { host_ids } };
        break;
      case 'named':
        body = { type: 'pkg_upgrade', params: { scope: 'named', packages: [...(packages ?? [])] }, targets: { host_ids } };
        break;
      case 'reboot':
        body = {
          type: 'reboot',
          params: { delay_s: delayNum, ...(message.trim() ? { message: message.trim() } : {}) },
          targets: { host_ids },
        };
        break;
    }
    create.mutate(body, {
      onSuccess: () => {
        onClose();
        onDone?.();
      },
    });
  };

  const shown = targets.slice(0, 12);
  return (
    <DialogContent size="sm">
      <form
        className="contents"
        onSubmit={(e) => {
          e.preventDefault();
          if (targets.length > 0 && delayOk && !create.isPending) submit();
        }}
      >
        <DialogHeader>
          <DialogTitle>{spec.title}</DialogTitle>
          <DialogDescription>{spec.describe}</DialogDescription>
        </DialogHeader>
        <DialogBody className="grid gap-3">
          <div>
            <div className="mb-1 text-xs font-medium text-muted-foreground">{pluralize(targets.length, 'target host')}</div>
            <ul className="flex flex-wrap gap-1">
              {shown.map((t) => (
                <li key={t.id} className="rounded-sm bg-muted px-1.5 py-0.5 font-mono text-xs">
                  {t.hostname}
                </li>
              ))}
              {targets.length > shown.length && (
                <li className="px-1.5 py-0.5 text-xs text-muted-foreground">+{targets.length - shown.length} more</li>
              )}
            </ul>
          </div>
          {action === 'named' && packages && (
            <div>
              <div className="mb-1 text-xs font-medium text-muted-foreground">{pluralize(packages.length, 'package')}</div>
              <p className="max-h-24 overflow-y-auto font-mono text-xs">{packages.join(', ')}</p>
            </div>
          )}
          {excluded > 0 && (
            <Callout tone="warning" title={`${pluralize(excluded, 'host')} skipped`}>
              You do not have permission for this action on those hosts.
            </Callout>
          )}
          {action === 'reboot' && (
            <div className="grid grid-cols-[8rem_1fr] gap-3">
              <Field label="Delay (seconds)" htmlFor={delayId} error={delayOk ? undefined : '0 to 3600'}>
                <Input
                  id={delayId}
                  type="number"
                  min={0}
                  max={3600}
                  value={delay}
                  onChange={(e) => setDelay(e.target.value)}
                  aria-invalid={!delayOk}
                />
              </Field>
              <Field label="Message to logged-in users" htmlFor={msgId} hint="Optional">
                <Input id={msgId} value={message} onChange={(e) => setMessage(e.target.value)} maxLength={256} />
              </Field>
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={create.isPending}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant={spec.destructive ? 'destructive' : 'default'}
            disabled={targets.length === 0 || !delayOk || create.isPending}
          >
            {create.isPending ? 'Starting…' : `${spec.verb} ${pluralize(targets.length, 'host')}`}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
