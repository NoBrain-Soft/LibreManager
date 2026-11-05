package gateway

import (
	"context"
	"net"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/nobrain-soft/libremanager/internal/pki"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	"github.com/nobrain-soft/libremanager/internal/server/store"
)

type ctxKey int

const (
	keyHostID ctxKey = iota
	keySerial
)

// hostFromCtx returns the authenticated host id (set by the interceptors).
func hostFromCtx(ctx context.Context) uuid.UUID {
	id, _ := ctx.Value(keyHostID).(uuid.UUID)
	return id
}

func serialFromCtx(ctx context.Context) string {
	s, _ := ctx.Value(keySerial).(string)
	return s
}

// peerIP returns the remote IP (for rate limiting enrollment).
func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}

// authenticate derives host identity from the verified client certificate
// and enforces revocation and host status. The TLS layer already verified
// the chain against the pinned root (VerifyClientCertIfGiven).
func (g *Gateway) authenticate(ctx context.Context) (context.Context, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, status.Error(codes.Unauthenticated, "client certificate required")
	}
	leaf := tlsInfo.State.PeerCertificates[0]
	idStr, err := pki.HostIDFromCert(leaf)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "certificate carries no host identity")
	}
	serial := pki.SerialHex(leaf)
	if g.deny.Revoked(serial) {
		return nil, status.Error(codes.PermissionDenied, "certificate revoked")
	}
	id := uuid.MustParse(idStr)
	st, err := g.cfg.Store.Q.GetHostStatus(ctx, id)
	if store.IsNotFound(err) {
		return nil, status.Error(codes.PermissionDenied, "unknown host")
	}
	if err != nil {
		return nil, status.Error(codes.Unavailable, "database unavailable")
	}
	if st != "active" {
		return nil, status.Error(codes.PermissionDenied, "host is "+st)
	}
	ctx = context.WithValue(ctx, keyHostID, id)
	ctx = context.WithValue(ctx, keySerial, serial)
	return ctx, nil
}

const enrollMethod = "/" + "stellwerk.agent.v1.GatewayService" + "/Enroll"

func (g *Gateway) unaryAuth(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if info.FullMethod == enrollMethod {
		return handler(ctx, req)
	}
	actx, err := g.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	return handler(actx, req)
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }

func (g *Gateway) streamAuth(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	actx, err := g.authenticate(ss.Context())
	if err != nil {
		return err
	}
	return handler(srv, &wrappedStream{ServerStream: ss, ctx: actx})
}

var _ = agentv1.GatewayService_ServiceDesc // keep the method name constant honest
