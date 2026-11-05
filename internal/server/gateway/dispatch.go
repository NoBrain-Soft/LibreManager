package gateway

import (
	"context"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	"github.com/nobrain-soft/libremanager/internal/server/events"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

var dispatchLocks sync.Map // host id -> *sync.Mutex

// dispatchHost delivers queued, unexpired envelopes to a connected host.
// A target is claimed (queued -> dispatched) before sending, so concurrent
// dispatchers never deliver the same envelope twice.
func (g *Gateway) dispatchHost(ctx context.Context, hostID uuid.UUID) {
	conn := g.registry.get(hostID)
	if conn == nil {
		return
	}
	mu, _ := dispatchLocks.LoadOrStore(hostID, &sync.Mutex{})
	m := mu.(*sync.Mutex)
	m.Lock()
	defer m.Unlock()

	q := g.cfg.Store.Q
	rows, err := q.ListQueuedForHost(ctx, hostID)
	if err != nil {
		slog.WarnContext(ctx, "list queued jobs", "host_id", hostID, "err", err)
		return
	}
	for _, r := range rows {
		var sj agentv1.SignedJob
		if err := proto.Unmarshal(r.SignedEnvelope, &sj); err != nil {
			slog.ErrorContext(ctx, "stored envelope corrupt", "job_id", r.JobID, "err", err)
			continue
		}
		n, err := q.MarkTargetDispatched(ctx, db.MarkTargetDispatchedParams{JobID: r.JobID, HostID: hostID})
		if err != nil || n == 0 {
			continue
		}
		if err := conn.send(ctx, &agentv1.ConnectResponse{Payload: &agentv1.ConnectResponse_Job{Job: &sj}}); err != nil {
			slog.WarnContext(ctx, "send job failed, requeueing", "job_id", r.JobID, "host_id", hostID, "err", err)
			_ = q.RequeueTarget(context.WithoutCancel(ctx), db.RequeueTargetParams{JobID: r.JobID, HostID: hostID})
			return
		}
		events.Publish(ctx, g.cfg.Store, events.Event{Type: events.JobTarget, JobID: r.JobID.String(), HostID: hostID.String(), Status: "dispatched"})
	}
}

// CancelJob asks a connected agent to cancel a running job.
func (g *Gateway) CancelJob(ctx context.Context, hostID uuid.UUID, jobID string) bool {
	err := g.registry.Send(ctx, hostID, &agentv1.ConnectResponse{Payload: &agentv1.ConnectResponse_CancelJob{
		CancelJob: &agentv1.CancelJob{JobId: jobID}}})
	return err == nil
}
