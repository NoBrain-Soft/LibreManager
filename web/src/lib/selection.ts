import { useCallback, useMemo, useState } from 'react';

/** Row selection limited to the currently visible ids. */
export function useSelection(visibleIds: readonly string[]) {
  const [raw, setRaw] = useState<ReadonlySet<string>>(new Set());
  const visible = useMemo(() => new Set(visibleIds), [visibleIds]);
  const selected = useMemo(() => new Set([...raw].filter((id) => visible.has(id))), [raw, visible]);

  const toggle = useCallback((id: string, on?: boolean) => {
    setRaw((prev) => {
      const next = new Set(prev);
      const want = on ?? !next.has(id);
      if (want) next.add(id);
      else next.delete(id);
      return next;
    });
  }, []);

  const allChecked = visibleIds.length > 0 && selected.size === visibleIds.length;
  const someChecked = selected.size > 0 && !allChecked;

  const toggleAll = useCallback(() => {
    setRaw(allChecked ? new Set() : new Set(visibleIds));
  }, [allChecked, visibleIds]);

  const clear = useCallback(() => setRaw(new Set()), []);

  return {
    selected,
    toggle,
    toggleAll,
    clear,
    headerState: allChecked ? (true as const) : someChecked ? ('indeterminate' as const) : (false as const),
  };
}
