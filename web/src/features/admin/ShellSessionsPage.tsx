import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getRouteApi, Link } from '@tanstack/react-router';
import { CircleStopIcon, PlayIcon, TerminalIcon } from 'lucide-react';
import { lazy, Suspense, useMemo, useState } from 'react';
import { api } from '@/api/client';
import { qk } from '@/api/keys';
import { hostsQuery, shellSessionsQuery } from '@/api/queries';
import { request } from '@/api/request';
import type { ShellSession } from '@/api/types';
import { usePermissions } from '@/auth/usePermissions';
import { ConfirmDialog } from '@/components/common/ConfirmDialog';
import { Page, PageHeader } from '@/components/common/PageHeader';
import { RelativeTime } from '@/components/common/RelativeTime';
import { EmptyState, ErrorState, ForbiddenState, LoadingState, TableSkeleton } from '@/components/common/states';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { NativeSelect } from '@/components/ui/input';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { durationBetween, formatDateTime, formatElapsed } from '@/lib/format';
import { useNow } from '@/lib/now';
import { notifySuccess } from '@/lib/notify';

const RecordingPlayer = lazy(() => import('../shell/RecordingPlayer').then((m) => ({ default: m.RecordingPlayer })));

const route = getRouteApi('/app/admin/shell-sessions');

export function ShellSessionsPage() {
  const perms = usePermissions();
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const qc = useQueryClient();
  const now = useNow();
  const allowed = perms.canAnywhere('shell.review');
  const q = useQuery({ ...shellSessionsQuery(search.host), enabled: allowed });
  const hosts = useQuery({ ...hostsQuery({}), enabled: allowed });
  const [playing, setPlaying] = useState<ShellSession | null>(null);
  const [terminate, setTerminate] = useState<ShellSession | null>(null);

  const rows = useMemo(() => q.data ?? [], [q.data]);
  const active = rows.filter((s) => !s.ended_at).length;

  if (!allowed) {
    return (
      <Page>
        <PageHeader title="Shell sessions" />
        <Card>
          <ForbiddenState />
        </Card>
      </Page>
    );
  }

  return (
    <Page>
      <PageHeader
        title="Shell sessions"
        description={active > 0 ? `${active} active now. Recordings are encrypted at rest and replayed here.` : 'Remote shell history with recordings.'}
      />
      <div className="mb-3">
        <NativeSelect
          aria-label="Host"
          className="w-64"
          value={search.host ?? ''}
          onChange={(e) => void navigate({ search: e.target.value ? { host: e.target.value } : {}, replace: true })}
        >
          <option value="">All hosts</option>
          {(hosts.data ?? []).map((h) => (
            <option key={h.id} value={h.id}>
              {h.hostname}
            </option>
          ))}
        </NativeSelect>
      </div>
      <Card>
        {q.isPending ? (
          <TableSkeleton rows={6} cols={6} />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState icon={TerminalIcon} title="No shell sessions" />
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <TH>User</TH>
                <TH>Host</TH>
                <TH>Started</TH>
                <TH>Duration</TH>
                <TH>Status</TH>
                <TH className="w-44">
                  <span className="sr-only">Actions</span>
                </TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((s) => {
                const running = !s.ended_at;
                return (
                  <TR key={s.id}>
                    <TD>
                      <div className="font-medium">{s.username}</div>
                      <div className="font-mono text-xs text-muted-foreground">as {s.unix_user}</div>
                    </TD>
                    <TD>
                      <Link to="/hosts/$hostId" params={{ hostId: s.host_id }} className="hover:text-primary hover:underline">
                        {s.hostname || s.host_id.slice(0, 8)}
                      </Link>
                    </TD>
                    <TD>
                      <RelativeTime value={s.started_at} />
                    </TD>
                    <TD className="text-muted-foreground">{formatElapsed(durationBetween(s.started_at, s.ended_at, now))}</TD>
                    <TD>
                      {running ? (
                        <Badge variant="info">active</Badge>
                      ) : (
                        <span className="text-xs text-muted-foreground">{s.end_reason || 'ended'}</span>
                      )}
                    </TD>
                    <TD>
                      <div className="flex justify-end gap-1">
                        {s.has_recording && (
                          <Button size="sm" variant="outline" onClick={() => setPlaying(s)}>
                            <PlayIcon /> Replay
                          </Button>
                        )}
                        {running && (
                          <Button size="sm" variant="destructive" onClick={() => setTerminate(s)}>
                            <CircleStopIcon /> Kill
                          </Button>
                        )}
                      </div>
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        )}
      </Card>

      <Dialog open={playing !== null} onOpenChange={(o) => !o && setPlaying(null)}>
        {playing && (
          <DialogContent size="full">
            <DialogHeader>
              <DialogTitle>
                {playing.username} as {playing.unix_user} on {playing.hostname || playing.host_id}
              </DialogTitle>
              <DialogDescription>
                {formatDateTime(playing.started_at)}
                {playing.ended_at ? ` – ${formatDateTime(playing.ended_at)}` : ' (still running)'}
              </DialogDescription>
            </DialogHeader>
            <DialogBody>
              <Suspense fallback={<LoadingState label="Loading player…" />}>
                <RecordingPlayer sessionId={playing.id} />
              </Suspense>
            </DialogBody>
          </DialogContent>
        )}
      </Dialog>

      <ConfirmDialog
        open={terminate !== null}
        onOpenChange={(o) => !o && setTerminate(null)}
        title="Kill this shell session?"
        description={terminate ? `${terminate.username} (${terminate.unix_user}) on ${terminate.hostname ?? terminate.host_id} is disconnected immediately.` : ''}
        confirmLabel="Kill session"
        destructive
        onConfirm={async () => {
          if (!terminate) return;
          await request(() => api.DELETE('/shell-sessions/{sessionId}', { params: { path: { sessionId: terminate.id } } }));
          void qc.invalidateQueries({ queryKey: qk.shellSessionsRoot });
          notifySuccess('Session terminated');
        }}
      />
    </Page>
  );
}
