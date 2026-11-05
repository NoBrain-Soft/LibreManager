package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nobrain-soft/libremanager/internal/common/validate"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	"github.com/nobrain-soft/libremanager/internal/server/auth"
	"github.com/nobrain-soft/libremanager/internal/server/events"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

// Per-connection message rate limit (DoS protection from a compromised host).
const (
	msgsPerMinute = 3000
	msgsBurst     = 300
)

// Connect implements GatewayService: the long-lived control stream.
func (g *Gateway) Connect(stream agentv1.GatewayService_ConnectServer) error {
	ctx := stream.Context()
	hostID := hostFromCtx(ctx)
	log := slog.With("host_id", hostID)

	hello, err := recvHello(stream)
	if err != nil {
		return err
	}
	facts := sanitizeFacts(hello.GetFacts())
	policyJSON, err := jsonOpts.Marshal(hello.GetPolicy())
	if err != nil || len(policyJSON) > 16<<10 {
		policyJSON = []byte(`{}`)
	}
	if err := g.cfg.Store.Q.UpdateHostHello(ctx, db.UpdateHostHelloParams{
		ID: hostID, Hostname: facts.Hostname, Fqdn: facts.FQDN, OsFamily: facts.OSFamily, OsID: facts.OSID,
		OsVersion: facts.OSVersion, Kernel: facts.Kernel, Arch: facts.Arch,
		AgentVersion: validate.Text(hello.GetAgentVersion(), 64), MachineID: facts.MachineID,
		BootID: validate.Text(hello.GetBootId(), 64), Policy: json.RawMessage(policyJSON),
	}); err != nil {
		log.ErrorContext(ctx, "update host on hello", "err", err)
		return status.Error(codes.Unavailable, "database unavailable")
	}

	cctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	conn := &agentConn{
		hostID: hostID, out: make(chan outMsg, 64), ctx: cctx, cancel: cancel,
		connectedAt: g.cfg.Now(), remote: peerIP(ctx), version: validate.Text(hello.GetAgentVersion(), 64),
	}
	g.registry.add(conn)
	g.hostUp(ctx, hostID)
	log.InfoContext(ctx, "agent connected", "remote", conn.remote, "version", conn.version)
	defer func() {
		if g.registry.remove(conn) {
			bg := context.WithoutCancel(ctx)
			if err := g.cfg.Store.Q.SetHostDisconnected(bg, hostID); err != nil {
				log.WarnContext(bg, "set disconnected", "err", err)
			}
			events.Publish(bg, g.cfg.Store, events.Event{Type: events.HostDisconnected, HostID: hostID.String()})
			g.hostDownLater(bg, hostID)
		}
		log.InfoContext(ctx, "agent disconnected", "cause", context.Cause(cctx))
	}()

	sendErr := make(chan error, 1)
	go func() { sendErr <- sendLoop(cctx, stream, conn.out) }()

	if err := conn.send(cctx, &agentv1.ConnectResponse{Payload: &agentv1.ConnectResponse_Welcome{Welcome: &agentv1.Welcome{
		HostId: hostID.String(), ServerTimeMs: g.cfg.Now().UnixMilli(), Settings: g.cfg.AgentSettings(ctx),
		RenewBeforeS: int64(RenewBefore.Seconds()),
	}}}); err != nil {
		return err
	}
	events.Publish(ctx, g.cfg.Store, events.Event{Type: events.HostConnected, HostID: hostID.String()})
	go g.dispatchHost(cctx, hostID)

	in := &ingest{g: g, hostID: hostID, hostname: facts.Hostname, series: map[uint32]seriesMeta{}}
	if err := in.loadGroups(ctx); err != nil {
		log.WarnContext(ctx, "load groups", "err", err)
	}
	limiter := auth.NewKeyedLimiter(msgsPerMinute, msgsBurst)
	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			if !limiter.Allow("") {
				in.dropped++
				if in.dropped > 10*msgsBurst {
					recvErr <- status.Error(codes.ResourceExhausted, "message rate limit exceeded")
					return
				}
				continue
			}
			if err := in.handle(cctx, conn, msg); err != nil {
				recvErr <- err
				return
			}
		}
	}()

	select {
	case err := <-recvErr:
		if errors.Is(err, io.EOF) || status.Code(err) == codes.Canceled {
			return nil
		}
		return err
	case err := <-sendErr:
		return err
	case <-cctx.Done():
		cause := context.Cause(cctx)
		if errors.Is(cause, context.Canceled) {
			return nil
		}
		return status.Error(codes.Aborted, cause.Error())
	}
}

func recvHello(stream agentv1.GatewayService_ConnectServer) (*agentv1.Hello, error) {
	type res struct {
		msg *agentv1.ConnectRequest
		err error
	}
	ch := make(chan res, 1)
	go func() {
		m, err := stream.Recv()
		ch <- res{m, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		h := r.msg.GetHello()
		if h == nil {
			return nil, status.Error(codes.InvalidArgument, "first message must be Hello")
		}
		return h, nil
	case <-time.After(HelloTimeout):
		return nil, status.Error(codes.DeadlineExceeded, "no Hello received")
	case <-stream.Context().Done():
		return nil, stream.Context().Err()
	}
}

func sendLoop(ctx context.Context, stream agentv1.GatewayService_ConnectServer, out <-chan outMsg) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case m := <-out:
			err := stream.Send(m.msg)
			m.done <- err
			if err != nil {
				return fmt.Errorf("gateway: send: %w", err)
			}
		}
	}
}

// --- host down state alerts (ARCHITECTURE.md §7.3: host down after 2 min)

func hostDownFingerprint(id uuid.UUID) string { return "hostdown:" + id.String() }

func (g *Gateway) hostUp(ctx context.Context, id uuid.UUID) {
	g.downMu.Lock()
	if t, ok := g.downTimers[id]; ok {
		t.Stop()
		delete(g.downTimers, id)
	}
	g.downMu.Unlock()
	g.setHostDownAlert(ctx, id, false)
}

func (g *Gateway) hostDownLater(ctx context.Context, id uuid.UUID) {
	g.downMu.Lock()
	defer g.downMu.Unlock()
	if t, ok := g.downTimers[id]; ok {
		t.Stop()
	}
	g.downTimers[id] = time.AfterFunc(HostDownGrace, func() {
		g.downMu.Lock()
		delete(g.downTimers, id)
		g.downMu.Unlock()
		if g.registry.Connected(id) {
			return
		}
		st, err := g.cfg.Store.Q.GetHostStatus(ctx, id)
		if err != nil || st != "active" {
			return
		}
		g.setHostDownAlert(ctx, id, true)
	})
}

func (g *Gateway) scheduleInitialHostDown(ctx context.Context) {
	hosts, err := g.cfg.Store.Q.ListHosts(ctx, db.ListHostsParams{})
	if err != nil {
		return
	}
	for _, h := range hosts {
		if h.Status == "active" {
			g.hostDownLater(ctx, h.ID)
		}
	}
}

func (g *Gateway) setHostDownAlert(ctx context.Context, id uuid.UUID, firing bool) {
	now := g.cfg.Now()
	statusStr := "resolved"
	var ends *time.Time
	if firing {
		statusStr = "firing"
	} else {
		ends = &now
	}
	h, err := g.cfg.Store.Q.GetHost(ctx, id)
	if err != nil {
		return
	}
	labels, _ := json.Marshal(map[string]string{"alertname": "HostDown", "host_id": id.String(), "hostname": h.Hostname, "severity": "critical"})
	if !firing {
		// Only resolve an existing firing alert; don't create resolved noise.
		rows, err := g.cfg.Store.Q.ListAlerts(ctx, ptr("firing"))
		if err != nil {
			return
		}
		found := false
		for _, a := range rows {
			if a.Fingerprint == hostDownFingerprint(id) {
				found = true
				break
			}
		}
		if !found {
			return
		}
	}
	a, err := g.cfg.Store.Q.UpsertAlert(ctx, db.UpsertAlertParams{
		ID: uuid.Must(uuid.NewV7()), Fingerprint: hostDownFingerprint(id), HostID: &id, Name: "HostDown", Severity: "critical",
		Status: statusStr, Summary: fmt.Sprintf("Agent on %s has not been connected for %s", h.Hostname, HostDownGrace),
		Labels: labels, Annotations: json.RawMessage(`{}`), StartsAt: now, EndsAt: ends,
	})
	if err != nil {
		slog.WarnContext(ctx, "host down alert", "err", err)
		return
	}
	events.Publish(ctx, g.cfg.Store, events.Event{Type: events.Alert, HostID: id.String(), Status: a.Status, Message: a.Summary})
}

func ptr[T any](v T) *T { return &v }
