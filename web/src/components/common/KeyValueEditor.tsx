import { PlusIcon, Trash2Icon } from 'lucide-react';
import { useId } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import type { KV } from '@/lib/kv';

interface Props {
  rows: KV[];
  onChange: (rows: KV[]) => void;
  disabled?: boolean;
  keyPlaceholder?: string;
  valuePlaceholder?: string;
}

export function KeyValueEditor({ rows, onChange, disabled, keyPlaceholder = 'key', valuePlaceholder = 'value' }: Props) {
  const id = useId();
  const update = (i: number, patch: Partial<KV>) =>
    onChange(rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));
  return (
    <div className="grid gap-1.5">
      {rows.map((row, i) => (
        <div key={i} className="flex items-center gap-1.5">
          <Input
            aria-label={`Label ${i + 1} key`}
            id={`${id}-k-${i}`}
            value={row.key}
            placeholder={keyPlaceholder}
            onChange={(e) => update(i, { key: e.target.value })}
            disabled={disabled}
            className="font-mono text-xs"
            maxLength={63}
          />
          <span className="text-muted-foreground">=</span>
          <Input
            aria-label={`Label ${i + 1} value`}
            value={row.value}
            placeholder={valuePlaceholder}
            onChange={(e) => update(i, { value: e.target.value })}
            disabled={disabled}
            className="font-mono text-xs"
            maxLength={256}
          />
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => onChange(rows.filter((_, idx) => idx !== i))}
            disabled={disabled}
            aria-label={`Remove label ${i + 1}`}
          >
            <Trash2Icon />
          </Button>
        </div>
      ))}
      <Button
        variant="outline"
        size="sm"
        className="w-fit"
        onClick={() => onChange([...rows, { key: '', value: '' }])}
        disabled={disabled}
      >
        <PlusIcon /> Add label
      </Button>
    </div>
  );
}
