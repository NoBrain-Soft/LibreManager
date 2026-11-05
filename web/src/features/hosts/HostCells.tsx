import { RotateCwIcon, ShieldCheckIcon } from 'lucide-react';
import type { Host } from '@/api/types';
import { Badge } from '@/components/ui/badge';
import { Tip } from '@/components/ui/tooltip';

export function UpdatesCell({ host }: { host: Pick<Host, 'updates'> }) {
  const u = host.updates;
  if (!u) return <span className="text-muted-foreground">–</span>;
  return (
    <div className="flex items-center gap-1.5">
      {(u.total ?? 0) === 0 ? (
        <span className="text-xs text-muted-foreground">Up to date</span>
      ) : (
        <span className="tabular">{u.total}</span>
      )}
      {(u.security ?? 0) > 0 && (
        <Badge variant="critical" title="Security updates">
          <ShieldCheckIcon aria-hidden /> {u.security}
        </Badge>
      )}
      {u.reboot_required && (
        <Tip content="Reboot required">
          <span tabIndex={0} className="inline-flex text-text-warning" aria-label="Reboot required">
            <RotateCwIcon className="size-3.5" />
          </span>
        </Tip>
      )}
    </div>
  );
}
