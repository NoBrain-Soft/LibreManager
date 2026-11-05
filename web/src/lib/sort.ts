import { useCallback, useState } from 'react';

export type SortDir = 'asc' | 'desc';
export type SortValue = string | number | boolean | null | undefined;

export interface SortState<K extends string> {
  key: K;
  dir: SortDir;
  toggle: (key: K) => void;
}

export function useSort<K extends string>(initial: K, initialDir: SortDir = 'asc'): SortState<K> {
  const [state, setState] = useState<{ key: K; dir: SortDir }>({ key: initial, dir: initialDir });
  const toggle = useCallback(
    (key: K) => setState((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' })),
    [],
  );
  return { ...state, toggle };
}

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

export function compareValues(a: SortValue, b: SortValue): number {
  const an = a === null || a === undefined || a === '';
  const bn = b === null || b === undefined || b === '';
  if (an && bn) return 0;
  if (an) return 1; // empty last
  if (bn) return -1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'boolean' && typeof b === 'boolean') return Number(a) - Number(b);
  return collator.compare(String(a), String(b));
}

export function sortItems<T>(items: readonly T[], get: (item: T) => SortValue, dir: SortDir): T[] {
  const sign = dir === 'asc' ? 1 : -1;
  return [...items].sort((x, y) => {
    const c = compareValues(get(x), get(y));
    // keep empties last regardless of direction
    const xe = get(x);
    const ye = get(y);
    if (xe === null || xe === undefined || xe === '' || ye === null || ye === undefined || ye === '') return c;
    return c * sign;
  });
}
