export interface KV {
  key: string;
  value: string;
}

export function toKVs(record: Record<string, string> | undefined | null): KV[] {
  return Object.entries(record ?? {}).map(([key, value]) => ({ key, value }));
}

/** Rows -> record; returns an error string for duplicates/invalid keys. */
export function fromKVs(rows: readonly KV[], maxEntries = 64): { record: Record<string, string>; error?: string } {
  const record: Record<string, string> = {};
  for (const { key, value } of rows) {
    const k = key.trim();
    if (k === '' && value.trim() === '') continue;
    if (k === '') return { record, error: 'Every label needs a key.' };
    if (!/^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,62}$/.test(k)) {
      return { record, error: `Invalid key "${k}" (letters, digits, . _ - /; max 63 chars).` };
    }
    if (Object.hasOwn(record, k)) return { record, error: `Duplicate key "${k}".` };
    if (value.length > 256) return { record, error: `Value of "${k}" is longer than 256 characters.` };
    record[k] = value;
  }
  if (Object.keys(record).length > maxEntries) return { record, error: `At most ${maxEntries} labels.` };
  return { record };
}
