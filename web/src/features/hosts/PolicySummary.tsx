import type { PolicySummary as Policy } from '@/api/types';
import { YesNo } from '@/components/common/badges';
import { EmptyState } from '@/components/common/states';
import { Badge } from '@/components/ui/badge';
import { humanize } from '@/lib/format';
import { str } from '@/lib/utils';

// Friendly labels for the agent's PolicySummary (inventory.proto). Unknown
// keys are still rendered, so a newer agent never hides information.
const LABELS: Record<string, string> = {
  metrics: 'Metrics collection',
  inventory: 'Inventory collection',
  security_checks: 'Security checks',
  pkg_upgrade: 'Package upgrades',
  pkg_install: 'Package install',
  pkg_remove: 'Package removal',
  service_control: 'Service control',
  reboot: 'Reboot',
  shell: 'Remote shell',
  shell_allow_root: 'Root shell',
  shell_allowed_users: 'Shell accounts',
  exec_scripts: 'Signed scripts',
  self_update: 'Agent self-update',
};

const ORDER = Object.keys(LABELS);

function snake(k: string): string {
  return k.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
}

/** Flatten nested objects to dotted keys (in case the full policy is sent). */
function flattenPolicy(obj: Record<string, unknown>, prefix = '', depth = 0): [string, unknown][] {
  const out: [string, unknown][] = [];
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${snake(k)}` : snake(k);
    if (v && typeof v === 'object' && !Array.isArray(v) && depth < 3) out.push(...flattenPolicy(v as Record<string, unknown>, key, depth + 1));
    else out.push([key, v]);
  }
  return out.sort(([a], [b]) => {
    const ia = ORDER.indexOf(a);
    const ib = ORDER.indexOf(b);
    if (ia !== -1 || ib !== -1) return (ia === -1 ? 999 : ia) - (ib === -1 ? 999 : ib);
    return a.localeCompare(b);
  });
}

export function PolicySummaryView({ policy }: { policy: Policy | undefined }) {
  const entries = policy ? flattenPolicy(policy) : [];
  if (entries.length === 0) {
    return (
      <EmptyState
        title="No policy reported"
        description="The agent reports its local policy (/etc/stellwerk/agent.yaml) after connecting."
        className="py-6"
      />
    );
  }
  return (
    <dl className="grid gap-x-4 gap-y-2 text-sm sm:grid-cols-[minmax(10rem,auto)_1fr]">
      {entries.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="text-muted-foreground">{LABELS[key] ?? humanize(key)}</dt>
          <dd className="min-w-0">
            {typeof value === 'boolean' ? (
              <YesNo value={value} />
            ) : Array.isArray(value) ? (
              value.length === 0 ? (
                <span className="text-muted-foreground">none</span>
              ) : (
                <span className="flex flex-wrap gap-1">
                  {value.map((v, i) => (
                    <Badge key={i} variant="outline" className="font-mono">
                      {str(v)}
                    </Badge>
                  ))}
                </span>
              )
            ) : (
              <span className="break-all font-mono text-xs">{str(value) || '–'}</span>
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}
