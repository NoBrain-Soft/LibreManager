import { PlusIcon, Trash2Icon } from 'lucide-react';
import type { HostGroup, Role, RoleBindingInput } from '@/api/types';
import { Button } from '@/components/ui/button';
import { NativeSelect } from '@/components/ui/input';

interface Props {
  value: RoleBindingInput[];
  onChange: (v: RoleBindingInput[]) => void;
  roles: readonly Role[];
  groups: readonly HostGroup[];
  disabled?: boolean;
}

/** Rows of (role, scope). Scope "global" = host_group_id null. */
export function RoleBindingsEditor({ value, onChange, roles, groups, disabled }: Props) {
  const update = (i: number, patch: Partial<RoleBindingInput>) => onChange(value.map((b, idx) => (idx === i ? { ...b, ...patch } : b)));
  const roleById = new Map(roles.map((r) => [r.id, r]));

  return (
    <div className="grid gap-2">
      {value.length === 0 && <p className="text-xs text-muted-foreground">No roles: the user can sign in but sees nothing.</p>}
      {value.map((b, i) => {
        const role = roleById.get(b.role_id);
        return (
          <div key={i} className="rounded-md border p-2">
            <div className="flex items-center gap-2">
              <NativeSelect
                aria-label={`Role ${i + 1}`}
                value={b.role_id}
                onChange={(e) => update(i, { role_id: e.target.value })}
                disabled={disabled}
              >
                {!role && <option value={b.role_id}>Unknown role</option>}
                {roles.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                    {r.builtin ? '' : ' (custom)'}
                  </option>
                ))}
              </NativeSelect>
              <span className="text-xs text-muted-foreground">on</span>
              <NativeSelect
                aria-label={`Scope of role ${i + 1}`}
                value={b.host_group_id ?? ''}
                onChange={(e) => update(i, { host_group_id: e.target.value || null })}
                disabled={disabled}
              >
                <option value="">All hosts (global)</option>
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    Group: {g.name}
                  </option>
                ))}
              </NativeSelect>
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={() => onChange(value.filter((_, idx) => idx !== i))}
                disabled={disabled}
                aria-label={`Remove role ${i + 1}`}
              >
                <Trash2Icon />
              </Button>
            </div>
            {role && (
              <p className="mt-1.5 text-[11px] leading-relaxed text-muted-foreground">
                {role.description && <span>{role.description} · </span>}
                <span className="font-mono">{role.permissions.join(', ') || 'no permissions'}</span>
              </p>
            )}
          </div>
        );
      })}
      <Button
        variant="outline"
        size="sm"
        className="w-fit"
        disabled={disabled || roles.length === 0}
        onClick={() => {
          const first = roles[0];
          if (first) onChange([...value, { role_id: first.id, host_group_id: null }]);
        }}
      >
        <PlusIcon /> Add role
      </Button>
    </div>
  );
}
