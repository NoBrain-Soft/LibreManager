import { SearchIcon, XIcon } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

interface Props {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  className?: string;
  /** Debounce in ms before onChange fires (0 = immediate). */
  debounce?: number;
  'aria-label'?: string;
}

export function SearchInput({ value, onChange, placeholder = 'Search…', className, debounce = 0, ...rest }: Props) {
  const [local, setLocal] = useState(value);
  const [prevValue, setPrevValue] = useState(value);
  // Adopt external changes (e.g. URL navigation) without an effect.
  if (value !== prevValue) {
    setPrevValue(value);
    setLocal(value);
  }

  useEffect(() => {
    if (debounce <= 0 || local === value) return;
    const t = setTimeout(() => onChange(local), debounce);
    return () => clearTimeout(t);
  }, [local, value, debounce, onChange]);

  const update = (v: string) => {
    setLocal(v);
    if (debounce <= 0) onChange(v);
  };

  return (
    <div className={cn('relative w-full max-w-xs', className)}>
      <SearchIcon className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
      <Input
        type="search"
        value={local}
        onChange={(e) => update(e.target.value)}
        placeholder={placeholder}
        aria-label={rest['aria-label'] ?? placeholder}
        className="pl-8 pr-7 [&::-webkit-search-cancel-button]:hidden"
        maxLength={128}
      />
      {local && (
        <button
          type="button"
          onClick={() => {
            setLocal('');
            onChange('');
          }}
          className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
          aria-label="Clear search"
        >
          <XIcon className="size-3.5" />
        </button>
      )}
    </div>
  );
}
