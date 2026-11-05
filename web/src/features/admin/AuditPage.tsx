import { useInfiniteQuery, useMutation } from '@tanstack/react-query';
import { ChevronRightIcon, ScrollTextIcon, ShieldCheckIcon } from 'lucide-react';
import { Fragment, useState } from 'react';
import { api, call } from '@/api/client';
import { qk } from '@/api/keys';
import { request } from '@/api/request';
import type { AuditEntry } from '@/api/types';
import { usePermissions } from '@/auth/usePermissions';
import { Page, PageHeader } from '@/components/common/PageHeader';
import { RelativeTime } from '@/components/common/RelativeTime';
import { SearchInput } from '@/components/common/SearchInput';
import { Callout, EmptyState, ErrorState, ForbiddenState, TableSkeleton } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { formatNumber } from '@/lib/format';
import { notifyError } from '@/lib/notify';
import { cn } from '@/lib/utils';

const PAGE = 100;

function prettyDetails(d: AuditEntry['details']): string {
  try {
    return JSON.stringify(d, null, 2);
  } catch {
    return '[details could not be displayed]';
  }
}

export function AuditPage() {
  const perms = usePermissions();
  const [actor, setActor] = useState('');
  const [action, setAction] = useState('');
  const [open, setOpen] = useState<ReadonlySet<number>>(new Set());

  const q = useInfiniteQuery({
    queryKey: qk.audit({ actor, action }),
    initialPageParam: undefined as number | undefined,
    queryFn: ({ pageParam, signal }) =>
      call(
        api.GET('/audit', {
          params: {
            query: {
              limit: PAGE,
              ...(pageParam !== undefined ? { before_id: pageParam } : {}),
              ...(actor ? { actor } : {}),
              ...(action ? { action } : {}),
            },
          },
          signal,
        }),
      ),
    getNextPageParam: (last) => (last.length < PAGE ? undefined : last[last.length - 1]?.id),
    enabled: perms.canAnywhere('audit.view'),
  });

  const verify = useMutation({
    mutationFn: () => request(() => api.GET('/audit/verify')),
    onError: (e) => notifyError(e, 'Verification failed to run'),
  });

  if (!perms.canAnywhere('audit.view')) {
    return (
      <Page>
        <PageHeader title="Audit log" />
        <Card>
          <ForbiddenState />
        </Card>
      </Page>
    );
  }

  const entries = q.data?.pages.flat() ?? [];
  const toggle = (id: number) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <Page>
      <PageHeader
        title="Audit log"
        description="Every state-changing action, hash-chained so tampering is detectable."
        actions={
          <Button variant="outline" onClick={() => verify.mutate()} disabled={verify.isPending}>
            <ShieldCheckIcon /> {verify.isPending ? 'Verifying…' : 'Verify chain'}
          </Button>
        }
      />
      {verify.data && (
        <Callout
          className="mb-3"
          tone={verify.data.ok ? 'good' : 'critical'}
          title={verify.data.ok ? 'Hash chain intact' : 'Hash chain broken'}
        >
          {formatNumber(verify.data.checked)} entries checked.
          {!verify.data.ok && verify.data.first_bad_id !== null && verify.data.first_bad_id !== undefined && (
            <> First mismatch at entry #{verify.data.first_bad_id}.</>
          )}
          {verify.data.message && <> {verify.data.message}</>}
        </Callout>
      )}
      <div className="mb-3 flex flex-wrap gap-2">
        <SearchInput value={actor} onChange={setActor} debounce={300} placeholder="Actor (e.g. alice)" aria-label="Filter by actor" />
        <SearchInput value={action} onChange={setAction} debounce={300} placeholder="Action (e.g. job.create)" aria-label="Filter by action" />
      </div>
      <Card>
        {q.isPending ? (
          <TableSkeleton rows={10} cols={5} />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : entries.length === 0 ? (
          <EmptyState icon={ScrollTextIcon} title="No audit entries" description={actor || action ? 'Nothing matches the filters.' : undefined} />
        ) : (
          <>
            <Table>
              <THead>
                <TR className="hover:bg-transparent">
                  <TH className="w-8" />
                  <TH>#</TH>
                  <TH>Time</TH>
                  <TH>Actor</TH>
                  <TH>Action</TH>
                  <TH>Target</TH>
                  <TH>Hash</TH>
                </TR>
              </THead>
              <TBody>
                {entries.map((e) => {
                  const expanded = open.has(e.id);
                  return (
                    <Fragment key={e.id}>
                      <TR className="cursor-pointer" onClick={() => toggle(e.id)}>
                        <TD>
                          <button
                            type="button"
                            aria-expanded={expanded}
                            aria-label={`${expanded ? 'Hide' : 'Show'} details of entry ${e.id}`}
                            className="rounded p-0.5 hover:bg-accent"
                            onClick={(ev) => {
                              ev.stopPropagation();
                              toggle(e.id);
                            }}
                          >
                            <ChevronRightIcon className={cn('size-3.5 transition-transform', expanded && 'rotate-90')} />
                          </button>
                        </TD>
                        <TD className="font-mono text-xs text-muted-foreground">{e.id}</TD>
                        <TD>
                          <RelativeTime value={e.ts} />
                        </TD>
                        <TD>
                          <div>{e.actor}</div>
                          {e.actor_ip && <div className="font-mono text-xs text-muted-foreground">{e.actor_ip}</div>}
                        </TD>
                        <TD className="font-mono text-xs">{e.action}</TD>
                        <TD className="max-w-80 truncate font-mono text-xs text-muted-foreground" title={e.target}>
                          {e.target || '–'}
                        </TD>
                        <TD className="font-mono text-xs text-muted-foreground" title={e.hash}>
                          {e.hash ? `${e.hash.slice(0, 12)}…` : '–'}
                        </TD>
                      </TR>
                      {expanded && (
                        <TR className="bg-muted/40 hover:bg-muted/40">
                          <TD />
                          <TD colSpan={6}>
                            <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all py-1 font-mono text-xs scrollbar-thin">
                              {prettyDetails(e.details)}
                            </pre>
                            {e.hash && <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">hash {e.hash}</div>}
                          </TD>
                        </TR>
                      )}
                    </Fragment>
                  );
                })}
              </TBody>
            </Table>
            <div className="flex items-center justify-between border-t px-3 py-2 text-xs text-muted-foreground">
              <span>{formatNumber(entries.length)} entries loaded</span>
              {q.hasNextPage && (
                <Button variant="ghost" size="sm" onClick={() => void q.fetchNextPage()} disabled={q.isFetchingNextPage}>
                  {q.isFetchingNextPage ? 'Loading…' : 'Load older entries'}
                </Button>
              )}
            </div>
          </>
        )}
      </Card>
    </Page>
  );
}
