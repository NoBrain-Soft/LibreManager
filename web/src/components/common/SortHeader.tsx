import { ArrowDownIcon, ArrowUpIcon, ChevronsUpDownIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { TH } from '@/components/ui/table';
import type { SortState } from '@/lib/sort';
import { cn } from '@/lib/utils';

interface Props<K extends string> {
  sort: SortState<K>;
  k: K;
  children: ReactNode;
  className?: string;
}

export function SortHeader<K extends string>({ sort, k, children, className }: Props<K>) {
  const active = sort.key === k;
  const Icon = !active ? ChevronsUpDownIcon : sort.dir === 'asc' ? ArrowUpIcon : ArrowDownIcon;
  return (
    <TH className={className} aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button
        type="button"
        onClick={() => sort.toggle(k)}
        className={cn('-mx-1 inline-flex items-center gap-1 rounded px-1 hover:text-foreground', active && 'text-foreground')}
      >
        {children}
        <Icon className={cn('size-3', !active && 'opacity-40')} aria-hidden />
      </button>
    </TH>
  );
}
