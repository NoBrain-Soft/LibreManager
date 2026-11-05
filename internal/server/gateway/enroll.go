package gateway

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/validate"
	"github.com/nobrain-soft/libremanager/internal/pki"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/auth"
	"github.com/nobrain-soft/libremanager/internal/server/events"
	"github.com/nobrain-soft/libremanager/internal/server/store"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

// tokenLen is len(prefix) + base64url(32 bytes).
var tokenLen = len(auth.PrefixEnrollment) + 43

// sanitizedFacts truncates and cleans agent-reported facts.
type sanitizedFacts struct {
	Hostname, FQDN, OSFamily, OSID, OSVersion, Kernel, Arch, AgentVersion, MachineID string
}

func sanitizeFacts(f *agentv1.HostFacts) sanitizedFacts {
	host := validate.Text(f.GetHostname(), 253)
	if !validate.Hostname(host) {
		host = "unknown"
	}
	fqdn := validate.Text(f.GetFqdn(), 253)
	if fqdn != "" && !validate.Hostname(fqdn) {
		fqdn = ""
	}
	return sanitizedFacts{
		Hostname: host, FQDN: fqdn,
		OSFamily:     validate.Text(f.GetOsFamily(), 32),
		OSID:         validate.Text(f.GetOsId(), 64),
		OSVersion:    validate.Text(f.GetOsVersion(), 64),
		Kernel:       validate.Text(f.GetKernel(), 128),
		Arch:         validate.Text(f.GetArch(), 32),
		AgentVersion: validate.Text(f.GetAgentVersion(), 64),
		MachineID:    validate.Text(f.GetMachineId(), 64),
	}
}

// Enroll implements GatewayService. It is the only RPC without a client
// certificate.
func (g *Gateway) Enroll(ctx context.Context, req *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	ip := peerIP(ctx)
	if !g.enrollLimit.Allow(ip) {
		return nil, status.Error(codes.ResourceExhausted, "too many enrollment attempts")
	}
	tok := req.GetToken()
	if len(tok) != tokenLen || !strings.HasPrefix(tok, auth.PrefixEnrollment) {
		return nil, status.Error(codes.PermissionDenied, "invalid enrollment token")
	}
	pub, err := pki.ParseCSR(req.GetCsrDer())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid CSR")
	}
	facts := sanitizeFacts(req.GetFacts())
	hostID := ids.NewUUID()
	now := g.cfg.Now()

	var (
		cert  *x509.Certificate
		tokID uuid.UUID
	)
	err = g.cfg.Store.InTx(ctx, func(q *db.Queries, _ pgx.Tx) error {
		t, err := q.ConsumeEnrollmentToken(ctx, g.cfg.Pepper.HashToken(tok))
		if store.IsNotFound(err) {
			return status.Error(codes.PermissionDenied, "invalid enrollment token")
		}
		if err != nil {
			return err
		}
		tokID = t.ID
		cert, err = g.cfg.CA.IssueAgentCert(pub, hostID.String(), pki.AgentCertValidity, now)
		if err != nil {
			return err
		}
		labels := t.Labels
		if len(labels) == 0 {
			labels = json.RawMessage(`{}`)
		}
		if _, err := q.CreateHost(ctx, db.CreateHostParams{
			ID: hostID, Hostname: facts.Hostname, Fqdn: facts.FQDN, OsFamily: facts.OSFamily, OsID: facts.OSID,
			OsVersion: facts.OSVersion, Kernel: facts.Kernel, Arch: facts.Arch, AgentVersion: facts.AgentVersion,
			MachineID: facts.MachineID, Labels: labels, CertSerial: pki.SerialHex(cert), CertNotAfter: &cert.NotAfter,
		}); err != nil {
			return err
		}
		if t.HostGroupID != nil {
			if err := q.AddHostToGroup(ctx, db.AddHostToGroupParams{HostID: hostID, HostGroupID: *t.HostGroupID}); err != nil {
				return err
			}
		}
		if err := q.InsertAgentCert(ctx, db.InsertAgentCertParams{
			Serial: pki.SerialHex(cert), HostID: hostID, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		}); err != nil {
			return err
		}
		_, err = g.cfg.Audit.LogTx(ctx, q, audit.Entry{
			Actor: "enrollment-token:" + t.ID.String(), ActorIP: ip, Action: "host.enroll", Target: "host:" + hostID.String(),
			Details: map[string]any{"hostname": facts.Hostname, "os": facts.OSID + " " + facts.OSVersion, "serial": pki.SerialHex(cert)},
		})
		return err
	})
	if err != nil {
		var st interface{ GRPCStatus() *status.Status }
		if errors.As(err, &st) {
			slog.WarnContext(ctx, "enrollment rejected", "ip", ip, "reason", st.GRPCStatus().Message())
			return nil, err
		}
		slog.ErrorContext(ctx, "enrollment failed", "ip", ip, "err", err)
		return nil, status.Error(codes.Internal, "enrollment failed")
	}
	keys, err := g.jobKeys(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "job keys unavailable")
	}
	slog.InfoContext(ctx, "host enrolled", "host_id", hostID, "hostname", facts.Hostname, "token", tokID, "ip", ip)
	events.Publish(ctx, g.cfg.Store, events.Event{Type: events.HostEnrolled, HostID: hostID.String(), Message: facts.Hostname})
	return &agentv1.EnrollResponse{
		HostId:       hostID.String(),
		CertChainDer: g.cfg.CA.ChainDER(cert),
		JobKeys:      keys,
		Settings:     g.cfg.AgentSettings(ctx),
	}, nil
}

func (g *Gateway) jobKeys(ctx context.Context) ([]*agentv1.JobKey, error) {
	rows, err := g.cfg.Store.Q.ListActiveJobSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*agentv1.JobKey, 0, len(rows))
	for _, r := range rows {
		out = append(out, &agentv1.JobKey{KeyId: r.KeyID, PublicKey: r.PublicKey})
	}
	return out, nil
}

// Renew implements GatewayService: a new certificate for the same host,
// over the existing mTLS identity.
func (g *Gateway) Renew(ctx context.Context, req *agentv1.RenewRequest) (*agentv1.RenewResponse, error) {
	hostID := hostFromCtx(ctx)
	if !g.renewLimit.Allow(hostID.String()) {
		return nil, status.Error(codes.ResourceExhausted, "renewal rate limit")
	}
	pub, err := pki.ParseCSR(req.GetCsrDer())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid CSR")
	}
	cert, err := g.cfg.CA.IssueAgentCert(pub, hostID.String(), pki.AgentCertValidity, g.cfg.Now())
	if err != nil {
		return nil, status.Error(codes.Internal, "issue failed")
	}
	err = g.cfg.Store.InTx(ctx, func(q *db.Queries, _ pgx.Tx) error {
		if err := q.InsertAgentCert(ctx, db.InsertAgentCertParams{
			Serial: pki.SerialHex(cert), HostID: hostID, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		}); err != nil {
			return err
		}
		if err := q.SetHostCert(ctx, db.SetHostCertParams{ID: hostID, CertSerial: pki.SerialHex(cert), CertNotAfter: &cert.NotAfter}); err != nil {
			return err
		}
		_, err := g.cfg.Audit.LogTx(ctx, q, audit.Entry{
			Actor: "host:" + hostID.String(), ActorIP: peerIP(ctx), Action: "host.cert_renew", Target: "host:" + hostID.String(),
			Details: map[string]any{"old_serial": serialFromCtx(ctx), "serial": pki.SerialHex(cert)},
		})
		return err
	})
	if err != nil {
		slog.ErrorContext(ctx, "renew failed", "host_id", hostID, "err", err)
		return nil, status.Error(codes.Internal, "renew failed")
	}
	return &agentv1.RenewResponse{CertChainDer: g.cfg.CA.ChainDER(cert)}, nil
}
