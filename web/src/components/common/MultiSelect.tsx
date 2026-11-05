import { ChevronsUpDownIcon, XIcon } from 'lucide-react';
import { useId, useMemo, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox, Popover, PopoverContent, PopoverTrigger } from '@/components/ui/misc';
import { cn } from '@/lib/utils';

export interface Option {
  value: string;
  label: string;
  hint?: string;
  disabled?: boolean;
}

interface Props {
  options: readonly Option[];
  value: readonly string[];
  onChange: (value: string[]) => void;
  placeholder?: string;
  emptyText?: string;
  id?: string;
  disabled?: boolean;
  className?: string;
  /** Max chips shown in the trigger before "+N". */
  maxChips?: number;
}

/** Searchable checkbox list in a popover. Keyboard: Tab into list, Space toggles. */
export function MultiSelect({
  options,
  value,
  onChange,
  placeholder = 'Select…',
  emptyText = 'Nothing found',
  id,
  disabled,
  className,
  maxChips = 4,
}: Props) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const listId = useId();
  const selected = useMemo(() => new Set(value), [value]);
  const labelOf = useMemo(() => new Map(options.map((o) => [o.value, o.label])), [options]);
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return needle
      ? options.filter((o) => o.label.toLowerCase().includes(needle) || o.hint?.toLowerCase().includes(needle))
      : options;
  }, [options, q]);

  const toggle = (v: string) => {
    const next = new Set(selected);
    if (next.has(v)) next.delete(v);
    else next.add(v);
    onChange([...next]);
  };

  const chips = value.slice(0, maxChips);
  return (
    <Popover
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (!o) setQ('');
      }}
    >
      <PopoverTrigger asChild>
        <button
          id={id}
          type="button"
          disabled={disabled}
          aria-haspopup="listbox"
          aria-expanded={open}
          className={cn(
            'flex min-h-8 w-full items-center gap-1 rounded-md border border-input bg-card px-2 py-1 text-left text-sm shadow-xs focus-visible:outline-2 focus-visible:outline-ring disabled:opacity-50',
            className,
          )}
        >
          <span className="flex min-w-0 flex-1 flex-wrap gap-1">
            {value.length === 0 && <span className="text-muted-foreground">{placeholder}</span>}
            {chips.map((v) => (
              <Badge key={v} variant="secondary" className="max-w-48 truncate">
                {labelOf.get(v) ?? v}
              </Badge>
            ))}
            {value.length > maxChips && <Badge variant="outline">+{value.length - maxChips}</Badge>}
          </span>
          <ChevronsUpDownIcon className="size-3.5 shrink-0 text-muted-foreground" />
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-[var(--radix-popover-trigger-width)] min-w-64 p-0">
        <div className="flex items-center gap-1 border-b p-1.5">
          <Input
            autoFocus
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter…"
            aria-label="Filter options"
            aria-controls={listId}
            className="h-7"
          />
          {value.length > 0 && (
            <Button variant="ghost" size="sm" onClick={() => onChange([])}>
              <XIcon /> Clear
            </Button>
          )}
        </div>
        <div id={listId} role="listbox" aria-multiselectable className="max-h-64 overflow-y-auto p-1 scrollbar-thin">
          {filtered.length === 0 && <div className="px-2 py-3 text-center text-xs text-muted-foreground">{emptyText}</div>}
          {filtered.map((o) => {
            const checked = selected.has(o.value);
            return (
              <label
                key={o.value}
                role="option"
                aria-selected={checked}
                className={cn(
                  'flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent',
                  o.disabled && 'pointer-events-none opacity-50',
                )}
              >
                <Checkbox checked={checked} onCheckedChange={() => toggle(o.value)} disabled={o.disabled} />
                <span className="min-w-0 flex-1 truncate">{o.label}</span>
                {o.hint && <span className="truncate text-xs text-muted-foreground">{o.hint}</span>}
              </label>
            );
          })}
        </div>
        {options.length > 0 && (
          <div className="flex items-center justify-between border-t px-2 py-1.5 text-xs text-muted-foreground">
            <span>{value.length} selected</span>
            <button
              type="button"
              className="hover:text-foreground"
              onClick={() => onChange([...new Set([...value, ...filtered.filter((o) => !o.disabled).map((o) => o.value)])])}
            >
              Select all{q ? ' matching' : ''}
            </button>
          </div>
        )}
      </PopoverContent>
    </Popover>
  );
}
