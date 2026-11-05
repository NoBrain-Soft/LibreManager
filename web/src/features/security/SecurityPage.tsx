import { useQuery } from '@tanstack/react-query';
import { ShieldCheckIcon } from 'lucide-react';
import { useMemo } from 'react';
import { securitySummaryQuery } from '@/api/queries';
import { SeverityBadge } from '@/components/common/badges';
import { Page, PageHeader } from '@/components/common/PageHeader';
import { EmptyState, ErrorState, TableSkeleton } from '@/components/common/states';
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress, Skeleton } from '@/components/ui/misc';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { formatNumber } from '@/lib/format';
import { severityRank } from '@/lib/status';

export function SecurityPage() {
  const q = useQuery(securitySummaryQuery);
  const failing = useMemo(
    () =>
      [...(q.data?.failing_checks ?? [])].sort(
        (a, b) => severityRank(b.severity) - severityRank(a.severity) || b.host_count - a.host_count || a.check_id.localeCompare(b.check_id),
      ),
    [q.data],
  );
  const pct = q.data?.compliance_percent;
  const tone = pct === undefined ? 'primary' : pct >= 90 ? 'good' : pct >= 70 ? 'warning' : 'critical';
  const critical = failing.filter((f) => severityRank(f.severity) >= 4).length;

  return (
    <Page>
      <PageHeader title="Security" description="Hardening checks across the fleet (CIS-inspired built-in checks)." />
      {q.isError ? (
        <Card>
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        </Card>
      ) : (
        <>
          <div className="mb-4 grid gap-3 md:grid-cols-3">
            <Card className="p-4">
              <div className="text-xs text-muted-foreground">Compliance</div>
              {q.data ? (
                <>
                  <div className="text-2xl font-semibold">{pct !== undefined ? `${Math.round(pct)} %` : '–'}</div>
                  {pct !== undefined && <Progress value={pct} tone={tone} className="mt-2" label="Compliance" />}
                </>
              ) : (
                <Skeleton className="mt-1 h-8 w-24" />
              )}
            </Card>
            <Card className="p-4">
              <div className="text-xs text-muted-foreground">Hosts evaluated</div>
              <div className="text-2xl font-semibold">{q.data ? formatNumber(q.data.hosts) : '–'}</div>
            </Card>
            <Card className={critical > 0 ? 'border-l-[3px] border-l-critical p-4' : 'p-4'}>
              <div className="text-xs text-muted-foreground">Failing checks</div>
              <div className="text-2xl font-semibold">{q.data ? formatNumber(failing.length) : '–'}</div>
              {critical > 0 && <div className="text-xs text-muted-foreground">{critical} high or critical</div>}
            </Card>
          </div>
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Failing checks</CardTitle>
                <CardDescription>Open a host's Security tab for evidence and remediation details.</CardDescription>
              </div>
            </CardHeader>
            {q.isPending ? (
              <TableSkeleton rows={6} cols={4} />
            ) : failing.length === 0 ? (
              <EmptyState icon={ShieldCheckIcon} title="No failing checks" description="Every evaluated host passes all applicable checks." />
            ) : (
              <Table>
                <THead>
                  <TR className="hover:bg-transparent">
                    <TH>Check</TH>
                    <TH>Severity</TH>
                    <TH className="text-right">Affected hosts</TH>
                    <TH className="w-48">Share of fleet</TH>
                  </TR>
                </THead>
                <TBody>
                  {failing.map((f) => (
                    <TR key={f.check_id}>
                      <TD>
                        <div className="font-medium">{f.title}</div>
                        <div className="font-mono text-xs text-muted-foreground">{f.check_id}</div>
                      </TD>
                      <TD>
                        <SeverityBadge severity={f.severity} />
                      </TD>
                      <TD className="text-right">{formatNumber(f.host_count)}</TD>
                      <TD>
                        <Progress value={f.host_count} max={Math.max(1, q.data?.hosts ?? 1)} tone="critical" label={`${f.check_id} share`} />
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            )}
          </Card>
        </>
      )}
    </Page>
  );
}
