// Package enroll performs agent enrollment (ARCHITECTURE.md §8.2): generate
// a key pair locally (the private key never leaves the host), send a CSR
// plus host facts with the one-time token over server-authenticated TLS
// against the pinned root, and persist the returned identity.
package enroll

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/nobrain-soft/libremanager/internal/agent/state"
	"github.com/nobrain-soft/libremanager/internal/pki"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Options configure enrollment.
type Options struct {
	Central       string // host:port
	CAFingerprint string
	Token         string
	Paths         state.Paths
	Facts         *agentv1.HostFacts
	Timeout       time.Duration
	// Chown is called on the state dir files so the unprivileged agent
	// user owns them (enroll runs as root). May be nil.
	Chown func(path string) error
}

// Result of an enrollment.
type Result struct {
	HostID string
	KeyIDs []string
}

// Enroll runs the enrollment exchange and writes all state.
func Enroll(ctx context.Context, o Options) (*Result, error) {
	if !strings.HasPrefix(o.Token, "swk_enr_") {
		return nil, errors.New("enroll: invalid token format")
	}
	host, _, err := net.SplitHostPort(o.Central)
	if err != nil {
		return nil, fmt.Errorf("enroll: central: %w", err)
	}
	_, roots, err := state.LoadPinnedRoot(o.Paths, o.CAFingerprint)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	key, err := pki.GenerateKey()
	if err != nil {
		return nil, err
	}
	csr, err := pki.NewCSR(key, o.Facts.GetHostname())
	if err != nil {
		return nil, err
	}
	timeout := o.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cc, err := grpc.NewClient(o.Central, grpc.WithTransportCredentials(credentials.NewTLS(pki.ClientTLSConfig(roots, host, nil))))
	if err != nil {
		return nil, fmt.Errorf("enroll: dial: %w", err)
	}
	defer cc.Close()
	resp, err := agentv1.NewGatewayServiceClient(cc).Enroll(ctx, &agentv1.EnrollRequest{Token: o.Token, CsrDer: csr, Facts: o.Facts})
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	tc, err := pki.TLSCertificate(resp.GetCertChainDer(), key)
	if err != nil {
		return nil, fmt.Errorf("enroll: returned certificate: %w", err)
	}
	if id, err := pki.HostIDFromCert(tc.Leaf); err != nil || id != resp.GetHostId() {
		return nil, errors.New("enroll: certificate identity does not match host id")
	}
	keys := map[string][]byte{}
	var keyIDs []string
	for _, k := range resp.GetJobKeys() {
		keys[k.GetKeyId()] = k.GetPublicKey()
		keyIDs = append(keyIDs, k.GetKeyId())
	}
	if len(keys) == 0 {
		return nil, errors.New("enroll: central returned no job-signing keys")
	}
	if err := state.WriteJobKeys(o.Paths, keys); err != nil {
		return nil, err
	}
	if err := state.WriteHostID(o.Paths, resp.GetHostId()); err != nil {
		return nil, err
	}
	if err := state.SaveIdentity(o.Paths, key, resp.GetCertChainDer()); err != nil {
		return nil, err
	}
	if o.Chown != nil {
		if err := o.Chown(o.Paths.StateDir); err != nil {
			return nil, fmt.Errorf("enroll: chown state dir: %w", err)
		}
	}
	return &Result{HostID: resp.GetHostId(), KeyIDs: keyIDs}, nil
}
