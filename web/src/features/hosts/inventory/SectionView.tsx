import { useMemo, useState } from 'react';
import { SearchInput } from '@/components/common/SearchInput';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { humanize } from '@/lib/format';
import { useNow } from '@/lib/now';
import { cn, str } from '@/lib/utils';
import { columnsOf, formatValue, isPlainObject, isScalar, labelFor, rowText, secondsUntil } from './values';

const PAGE = 200;

function Value({ k, v }: { k: string; v: unknown }) {
  const now = useNow();
  const f = formatValue(k, v);
  if (f.kind === 'empty') return <span className="text-muted-foreground">–</span>;
  if (f.kind === 'bool')
    return <span className={cn('text-xs', f.value ? 'text-foreground' : 'text-muted-foreground')}>{f.value ? 'yes' : 'no'}</span>;
  // Expiry hints for certificates and the like.
  if (/not_?after/i.test(k)) {
    const s = secondsUntil(v, now);
    if (s !== undefined && s < 30 * 86400) {
      return (
        <span className="inline-flex items-center gap-1.5">
          {f.text}
          <Badge variant={s < 0 ? 'critical' : 'warning'}>{s < 0 ? 'expired' : `${Math.ceil(s / 86400)} d left`}</Badge>
        </span>
      );
    }
  }
  return <span className={cn(/fingerprint|sha256|mac|id$/i.test(k) && 'font-mono text-xs')}>{f.text}</span>;
}

function ObjectTable({ rows, title }: { rows: Record<string, unknown>[]; title: string }) {
  const [q, setQ] = useState('');
  const [limit, setLimit] = useState(PAGE);
  const cols = useMemo(() => columnsOf(rows), [rows]);
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return needle ? rows.filter((r) => rowText(r).includes(needle)) : rows;
  }, [rows, q]);
  const shown = filtered.slice(0, limit);

  return (
    <div className="rounded-md border">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b px-3 py-2">
        <div className="text-sm font-medium">
          {title} <span className="font-normal text-muted-foreground">({filtered.length === rows.length ? rows.length : `${filtered.length} of ${rows.length}`})</span>
        </div>
        {rows.length > 8 && <SearchInput value={q} onChange={setQ} placeholder={`Filter ${title.toLowerCase()}…`} className="max-w-56" />}
      </div>
      <Table>
        <THead>
          <TR className="hover:bg-transparent">
            {cols.map((c) => (
              <TH key={c}>{labelFor(c)}</TH>
            ))}
          </TR>
        </THead>
        <TBody>
          {shown.map((r, i) => (
            <TR key={i}>
              {cols.map((c) => (
                <TD key={c} className="max-w-96 break-words">
                  {isScalar(r[c]) || Array.isArray(r[c]) ? <Value k={c} v={r[c]} /> : <span className="font-mono text-xs">{str(r[c])}</span>}
                </TD>
              ))}
            </TR>
          ))}
          {shown.length === 0 && (
            <TR>
              <TD colSpan={cols.length} className="py-6 text-center text-sm text-muted-foreground">
                No matching entries
              </TD>
            </TR>
          )}
        </TBody>
      </Table>
      {filtered.length > limit && (
        <div className="border-t p-2 text-center">
          <Button variant="ghost" size="sm" onClick={() => setLimit((l) => l + PAGE)}>
            Show more ({filtered.length - limit} remaining)
          </Button>
        </div>
      )}
    </div>
  );
}

/** Generic renderer for one inventory section's `data` object. */
export function SectionView({ data, depth = 0 }: { data: Record<string, unknown>; depth?: number }) {
  const entries = Object.entries(data);
  const scalars = entries.filter(([, v]) => isScalar(v));
  const primitiveLists = entries.filter(([, v]) => Array.isArray(v) && v.every((x) => isScalar(x)) && v.length > 0);
  const tables = entries.filter(([, v]) => Array.isArray(v) && v.length > 0 && v.every((x) => isPlainObject(x)));
  const emptyLists = entries.filter(([, v]) => Array.isArray(v) && v.length === 0);
  const nested = entries.filter(([, v]) => isPlainObject(v));

  return (
    <div className="grid gap-4">
      {scalars.length > 0 && (
        <dl className="grid gap-x-6 gap-y-1.5 text-sm sm:grid-cols-[minmax(9rem,auto)_1fr]">
          {scalars.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-muted-foreground">{labelFor(k)}</dt>
              <dd className="min-w-0 break-words">
                <Value k={k} v={v} />
              </dd>
            </div>
          ))}
        </dl>
      )}
      {primitiveLists.map(([k, v]) => (
        <div key={k}>
          <div className="mb-1 text-xs font-medium text-muted-foreground">{humanize(k)}</div>
          <div className="flex flex-wrap gap-1">
            {(v as unknown[]).slice(0, 300).map((x, i) => (
              <Badge key={i} variant="outline" className="font-mono">
                {str(x)}
              </Badge>
            ))}
          </div>
        </div>
      ))}
      {tables.map(([k, v]) => (
        <ObjectTable key={k} title={humanize(k)} rows={v as Record<string, unknown>[]} />
      ))}
      {depth < 3 &&
        nested.map(([k, v]) => (
          <div key={k} className="rounded-md border p-3">
            <div className="mb-2 text-sm font-medium">{humanize(k)}</div>
            <SectionView data={v as Record<string, unknown>} depth={depth + 1} />
          </div>
        ))}
      {emptyLists.length > 0 && (
        <p className="text-xs text-muted-foreground">Empty: {emptyLists.map(([k]) => humanize(k)).join(', ')}</p>
      )}
    </div>
  );
}
