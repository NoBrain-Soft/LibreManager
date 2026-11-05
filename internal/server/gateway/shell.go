package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/status"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	centralv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/central/v1"
)

// ShellAttachTimeout bounds the time between delivering a grant and the
// agent opening its ShellSession stream.
const ShellAttachTimeout = 30 * time.Second

type pendingShell struct {
	hostID   uuid.UUID
	attached chan agentv1.GatewayService_ShellSessionServer
	done     chan struct{}
}

type shellBroker struct {
	mu      sync.Mutex
	pending map[string]*pendingShell
}

func newShellBroker() *shellBroker { return &shellBroker{pending: map[string]*pendingShell{}} }

func (b *shellBroker) register(sessionID string, hostID uuid.UUID) (*pendingShell, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.pending[sessionID]; exists {
		return nil, errors.New("session already active")
	}
	p := &pendingShell{hostID: hostID, attached: make(chan agentv1.GatewayService_ShellSessionServer, 1), done: make(chan struct{})}
	b.pending[sessionID] = p
	return p, nil
}

func (b *shellBroker) remove(sessionID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if p, ok := b.pending[sessionID]; ok {
		close(p.done)
		delete(b.pending, sessionID)
	}
}

func (b *shellBroker) lookup(sessionID string) *pendingShell {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pending[sessionID]
}

// ShellSession implements GatewayService: the agent's side of a shell.
func (g *Gateway) ShellSession(stream agentv1.GatewayService_ShellSessionServer) error {
	ctx := stream.Context()
	hostID := hostFromCtx(ctx)
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	att := first.GetAttach()
	if att == nil || !ids.Valid(att.GetSessionId()) {
		return status.Error(codes.InvalidArgument, "first message must be ShellAttach")
	}
	p := g.shells.lookup(att.GetSessionId())
	// The session must have been granted for exactly this host.
	if p == nil || p.hostID != hostID {
		return status.Error(codes.PermissionDenied, "no such shell session for this host")
	}
	select {
	case p.attached <- stream:
	default:
		return status.Error(codes.AlreadyExists, "session already attached")
	}
	select {
	case <-p.done:
	case <-ctx.Done():
	}
	return nil
}

// ShellRelay implements GatewayControlService for the API.
func (g *Gateway) ShellRelay(relay centralv1.GatewayControlService_ShellRelayServer) error {
	ctx := relay.Context()
	first, err := relay.Recv()
	if err != nil {
		return err
	}
	att := first.GetAttach()
	if att == nil || !ids.Valid(att.GetSessionId()) || !ids.Valid(att.GetHostId()) || att.GetGrant() == nil {
		return status.Error(codes.InvalidArgument, "first message must be a complete attach")
	}
	hostID := uuid.MustParse(att.GetHostId())
	conn := g.registry.get(hostID)
	if conn == nil {
		return status.Error(codes.Unavailable, "host not connected")
	}
	p, err := g.shells.register(att.GetSessionId(), hostID)
	if err != nil {
		return status.Error(codes.AlreadyExists, err.Error())
	}
	defer g.shells.remove(att.GetSessionId())

	if err := conn.send(ctx, &agentv1.ConnectResponse{Payload: &agentv1.ConnectResponse_Job{Job: att.GetGrant()}}); err != nil {
		return status.Error(codes.Unavailable, "could not deliver grant")
	}
	var agent agentv1.GatewayService_ShellSessionServer
	select {
	case agent = <-p.attached:
	case <-time.After(ShellAttachTimeout):
		return status.Error(codes.DeadlineExceeded, "agent did not open the shell (rejected by host policy?)")
	case <-ctx.Done():
		return ctx.Err()
	case <-conn.ctx.Done():
		return status.Error(codes.Unavailable, "agent disconnected")
	}
	if err := relay.Send(&centralv1.ShellRelayResponse{Payload: &centralv1.ShellRelayResponse_Ready{Ready: &centralv1.ShellRelayReady{}}}); err != nil {
		return err
	}
	slog.InfoContext(ctx, "shell relay established", "session_id", att.GetSessionId(), "host_id", hostID)

	errc := make(chan error, 2)
	// agent -> API
	go func() {
		for {
			m, err := agent.Recv()
			if err != nil {
				errc <- err
				return
			}
			var out *centralv1.ShellRelayResponse
			switch pl := m.GetPayload().(type) {
			case *agentv1.ShellSessionRequest_Output:
				if len(pl.Output) > 64<<10 {
					pl.Output = pl.Output[:64<<10]
				}
				out = &centralv1.ShellRelayResponse{Payload: &centralv1.ShellRelayResponse_Output{Output: pl.Output}}
			case *agentv1.ShellSessionRequest_Exit:
				_ = relay.Send(&centralv1.ShellRelayResponse{Payload: &centralv1.ShellRelayResponse_Exit{Exit: pl.Exit}})
				errc <- nil
				return
			default:
				continue
			}
			if err := relay.Send(out); err != nil {
				errc <- err
				return
			}
		}
	}()
	// API -> agent
	go func() {
		for {
			m, err := relay.Recv()
			if err != nil {
				errc <- err
				return
			}
			var out *agentv1.ShellSessionResponse
			switch pl := m.GetPayload().(type) {
			case *centralv1.ShellRelayRequest_Input:
				out = &agentv1.ShellSessionResponse{Payload: &agentv1.ShellSessionResponse_Input{Input: pl.Input}}
			case *centralv1.ShellRelayRequest_Resize:
				out = &agentv1.ShellSessionResponse{Payload: &agentv1.ShellSessionResponse_Resize{Resize: pl.Resize}}
			case *centralv1.ShellRelayRequest_Close:
				_ = agent.Send(&agentv1.ShellSessionResponse{Payload: &agentv1.ShellSessionResponse_Close{Close: pl.Close}})
				errc <- nil
				return
			default:
				continue
			}
			if err := agent.Send(out); err != nil {
				errc <- err
				return
			}
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		return nil
	}
}

// --- control service (API -> gateway over a unix socket)

type controlServer struct {
	centralv1.UnimplementedGatewayControlServiceServer
	g *Gateway
}

func (c *controlServer) ShellRelay(s centralv1.GatewayControlService_ShellRelayServer) error {
	return c.g.ShellRelay(s)
}

func (c *controlServer) CancelJob(ctx context.Context, req *centralv1.CancelJobRequest) (*centralv1.CancelJobResponse, error) {
	id, err := uuid.Parse(req.GetHostId())
	if err != nil || !ids.Valid(req.GetJobId()) {
		return nil, status.Error(codes.InvalidArgument, "invalid ids")
	}
	return &centralv1.CancelJobResponse{Delivered: c.g.CancelJob(ctx, id, req.GetJobId())}, nil
}

func (c *controlServer) ListConnected(context.Context, *centralv1.ListConnectedRequest) (*centralv1.ListConnectedResponse, error) {
	resp := &centralv1.ListConnectedResponse{}
	for _, ci := range c.g.registry.List() {
		resp.Agents = append(resp.Agents, &centralv1.ConnectedAgent{
			HostId: ci.HostID.String(), ConnectedAtMs: ci.ConnectedAt.UnixMilli(), RemoteAddr: ci.Remote, AgentVersion: ci.Version,
		})
	}
	return resp, nil
}

// ServeControl serves GatewayControlService on a unix socket.
func (g *Gateway) ServeControl(ctx context.Context, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("gateway: control dir: %w", err)
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("gateway: control listen: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		return fmt.Errorf("gateway: control chmod: %w", err)
	}
	srv := grpc.NewServer(grpc.Creds(local.NewCredentials()), grpc.MaxRecvMsgSize(1<<20))
	centralv1.RegisterGatewayControlServiceServer(srv, &controlServer{g: g})
	go func() {
		<-ctx.Done()
		srv.Stop()
	}()
	if err := srv.Serve(ln); err != nil {
		return fmt.Errorf("gateway: control serve: %w", err)
	}
	return nil
}

// DialControl connects to the gateway control socket.
func DialControl(path string) (centralv1.GatewayControlServiceClient, *grpc.ClientConn, error) {
	cc, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(local.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("gateway: dial control: %w", err)
	}
	return centralv1.NewGatewayControlServiceClient(cc), cc, nil
}
