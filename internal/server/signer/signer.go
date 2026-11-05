// Package signer implements `stellwerk-server signer`: the only process that
// holds the Ed25519 job-signing key (CLAUDE.md rule 4, ARCHITECTURE.md §5.4).
//
// It is reachable exclusively via a unix socket. Before signing, it
// independently validates the job (schema, target count, validity window)
// and rate-limits per requesting user, then appends every signature to its
// own append-only log.
package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nobrain-soft/libremanager/internal/common/envelope"
	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/secretbox"
	"github.com/nobrain-soft/libremanager/internal/common/validate"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	centralv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/central/v1"
)

// Limits enforced by the signer.
const (
	MaxTargets          = 1000
	DefaultTTL          = 10 * time.Minute
	MaxTTL              = envelope.DefaultMaxValidity
	ShellMaxTTL         = 2 * time.Minute
	MaxNotBeforeFuture  = 24 * time.Hour
	DefaultUserPerMin   = 600
	DefaultGlobalPerMin = 5000
	// KeyPurpose binds the sealed job key file.
	KeyPurpose = "signer/jobkey"
)

// GenerateKeyFile creates a new sealed Ed25519 job key. It returns the
// public key.
func GenerateKeyFile(master *secretbox.Key, path string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signer: generate: %w", err)
	}
	if err := secretbox.SealFile(master, KeyPurpose, path, priv); err != nil {
		return nil, err
	}
	return pub, nil
}

// LoadKeyFile opens a sealed job key.
func LoadKeyFile(master *secretbox.Key, path string) (*envelope.Signer, error) {
	b, err := secretbox.OpenFile(master, KeyPurpose, path)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, errors.New("signer: invalid key file")
	}
	return envelope.NewSigner(ed25519.PrivateKey(b))
}

// Service implements centralv1.SignerServiceServer.
type Service struct {
	centralv1.UnimplementedSignerServiceServer

	signer *envelope.Signer
	log    *signatureLog
	now    func() time.Time

	mu     sync.Mutex
	perUsr map[string][]time.Time
	global []time.Time
	// Per-minute limits.
	UserPerMin   int
	GlobalPerMin int
}

// NewService creates the service. logPath is the append-only signature log.
func NewService(s *envelope.Signer, logPath string) (*Service, error) {
	l, err := openLog(logPath)
	if err != nil {
		return nil, err
	}
	return &Service{signer: s, log: l, now: time.Now, perUsr: map[string][]time.Time{},
		UserPerMin: DefaultUserPerMin, GlobalPerMin: DefaultGlobalPerMin}, nil
}

// Close closes the signature log.
func (s *Service) Close() error { return s.log.Close() }

// ListKeys implements SignerService.
func (s *Service) ListKeys(context.Context, *centralv1.ListKeysRequest) (*centralv1.ListKeysResponse, error) {
	return &centralv1.ListKeysResponse{Keys: []*agentv1.JobKey{{KeyId: s.signer.KeyID(), PublicKey: s.signer.PublicKey()}}}, nil
}

// SignJobs implements SignerService.
func (s *Service) SignJobs(ctx context.Context, req *centralv1.SignJobsRequest) (*centralv1.SignJobsResponse, error) {
	tmpl := req.GetTemplate()
	if err := validateTemplate(tmpl); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	hosts, err := validateHosts(req.GetHostIds())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	now := s.now()
	ttl := DefaultTTL
	if req.GetTtlS() > 0 {
		ttl = time.Duration(req.GetTtlS()) * time.Second
	}
	maxTTL := MaxTTL
	if _, ok := tmpl.GetAction().(*agentv1.Job_Shell); ok {
		maxTTL = ShellMaxTTL
		if len(hosts) != 1 {
			return nil, status.Error(codes.InvalidArgument, "shell grants target exactly one host")
		}
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	notBefore := now
	if req.GetNotBefore() > 0 {
		nb := time.Unix(req.GetNotBefore(), 0)
		if nb.After(now.Add(MaxNotBeforeFuture)) {
			return nil, status.Error(codes.InvalidArgument, "not_before too far in the future")
		}
		if nb.After(now) {
			notBefore = nb
		}
	}
	if !s.allow(tmpl.GetRequestedBy(), len(hosts), now) {
		return nil, status.Error(codes.ResourceExhausted, "signing rate limit exceeded")
	}

	resp := &centralv1.SignJobsResponse{}
	for _, h := range hosts {
		nonce := make([]byte, envelope.NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, status.Error(codes.Internal, "nonce")
		}
		job := proto.CloneOf(tmpl)
		job.HostId = h
		job.Nonce = nonce
		job.NotBefore = notBefore.Unix()
		job.ExpiresAt = notBefore.Add(ttl).Unix()
		sj, err := s.signer.SignJob(job)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		if err := s.log.append(logEntry{
			Ts: now.UTC().Format(time.RFC3339Nano), KeyID: sj.GetKeyId(), JobID: job.GetJobId(), HostID: h,
			Action: envelope.ActionName(job), RequestedBy: job.GetRequestedBy(), ExpiresAt: job.GetExpiresAt(),
			Digest: digest(sj.GetJob()),
		}); err != nil {
			// Never hand out a signature that was not logged.
			slog.ErrorContext(ctx, "signature log write failed", "err", err)
			return nil, status.Error(codes.Internal, "signature log unavailable")
		}
		resp.Envelopes = append(resp.Envelopes, &centralv1.SignedEnvelope{HostId: h, Signed: sj})
	}
	return resp, nil
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (s *Service) allow(user string, n int, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := now.Add(-time.Minute)
	prune := func(ts []time.Time) []time.Time {
		i := 0
		for i < len(ts) && !ts[i].After(cut) {
			i++
		}
		return ts[i:]
	}
	s.global = prune(s.global)
	u := prune(s.perUsr[user])
	if len(u)+n > s.UserPerMin || len(s.global)+n > s.GlobalPerMin {
		s.perUsr[user] = u
		return false
	}
	for range n {
		u = append(u, now)
		s.global = append(s.global, now)
	}
	s.perUsr[user] = u
	return true
}

func validateHosts(in []string) ([]string, error) {
	if len(in) == 0 || len(in) > MaxTargets {
		return nil, fmt.Errorf("between 1 and %d target hosts required", MaxTargets)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, h := range in {
		c, err := ids.Canonical(h)
		if err != nil || c != h {
			return nil, fmt.Errorf("invalid host id %q", h)
		}
		if seen[h] {
			return nil, fmt.Errorf("duplicate host id %q", h)
		}
		seen[h] = true
		out = append(out, h)
	}
	return out, nil
}

// validateTemplate checks the action schema independently of the API.
func validateTemplate(j *agentv1.Job) error {
	if j == nil {
		return errors.New("missing template")
	}
	if !ids.Valid(j.GetJobId()) {
		return errors.New("invalid job_id")
	}
	if j.GetRequestedBy() == "" || len(j.GetRequestedBy()) > 64 {
		return errors.New("invalid requested_by")
	}
	if len(j.GetApprovedBy()) > 10 {
		return errors.New("too many approvers")
	}
	pkgs := func(p []string, required bool) error {
		if required && len(p) == 0 {
			return errors.New("package list required")
		}
		if len(p) > 500 {
			return errors.New("too many packages")
		}
		for _, n := range p {
			if !validate.PackageName(n) {
				return fmt.Errorf("invalid package name %q", n)
			}
		}
		return nil
	}
	switch a := j.GetAction().(type) {
	case *agentv1.Job_PkgRefresh, *agentv1.Job_CollectInventory:
	case *agentv1.Job_PkgUpgrade:
		switch a.PkgUpgrade.GetScope() {
		case agentv1.UpgradeScope_UPGRADE_SCOPE_ALL, agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY:
			if len(a.PkgUpgrade.GetPackages()) > 0 {
				return errors.New("packages only allowed with named scope")
			}
		case agentv1.UpgradeScope_UPGRADE_SCOPE_NAMED:
			return pkgs(a.PkgUpgrade.GetPackages(), true)
		default:
			return errors.New("invalid upgrade scope")
		}
	case *agentv1.Job_PkgInstall:
		return pkgs(a.PkgInstall.GetPackages(), true)
	case *agentv1.Job_PkgRemove:
		return pkgs(a.PkgRemove.GetPackages(), true)
	case *agentv1.Job_Service:
		if !validate.UnitName(a.Service.GetUnit()) {
			return errors.New("invalid unit name")
		}
		if _, ok := agentv1.ServiceOp_name[int32(a.Service.GetOp())]; !ok || a.Service.GetOp() == agentv1.ServiceOp_SERVICE_OP_UNSPECIFIED {
			return errors.New("invalid service op")
		}
	case *agentv1.Job_Reboot:
		if a.Reboot.GetDelayS() > 3600 || len(a.Reboot.GetMessage()) > 256 {
			return errors.New("invalid reboot parameters")
		}
	case *agentv1.Job_Shell:
		g := a.Shell
		if !ids.Valid(g.GetSessionId()) || !validate.AccountName(g.GetUnixUser()) {
			return errors.New("invalid shell grant")
		}
		if g.GetMaxDurationS() == 0 || g.GetMaxDurationS() > 24*3600 || g.GetCols() > 1000 || g.GetRows() > 1000 {
			return errors.New("invalid shell grant limits")
		}
	case *agentv1.Job_RunCheck:
		if len(a.RunCheck.GetCheckIds()) > 200 {
			return errors.New("too many checks")
		}
		for _, c := range a.RunCheck.GetCheckIds() {
			if !validate.CheckID(c) {
				return fmt.Errorf("invalid check id %q", c)
			}
		}
	case *agentv1.Job_FileRead:
		p := a.FileRead.GetPath()
		if len(p) == 0 || len(p) > 4096 || p[0] != '/' || filepath.Clean(p) != p {
			return errors.New("invalid path")
		}
	case *agentv1.Job_ProbeConfig:
		if len(a.ProbeConfig.GetProbes()) > 100 {
			return errors.New("too many probes")
		}
	case *agentv1.Job_Script, *agentv1.Job_AgentUpdate:
		return errors.New("action not enabled in this release")
	default:
		return errors.New("missing or unknown action")
	}
	return nil
}

// Serve listens on a unix socket at path (mode 0660) and serves until ctx
// is done.
func Serve(ctx context.Context, svc *Service, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("signer: %w", err)
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("signer: listen: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		return fmt.Errorf("signer: chmod: %w", err)
	}
	srv := grpc.NewServer(grpc.Creds(local.NewCredentials()), grpc.MaxRecvMsgSize(1<<20))
	centralv1.RegisterSignerServiceServer(srv, svc)
	go func() {
		<-ctx.Done()
		srv.GracefulStop()
	}()
	slog.InfoContext(ctx, "signer listening", "socket", path, "key_id", svc.signer.KeyID())
	if err := srv.Serve(ln); err != nil {
		return fmt.Errorf("signer: serve: %w", err)
	}
	return nil
}

// Dial connects to the signer socket.
func Dial(path string) (centralv1.SignerServiceClient, *grpc.ClientConn, error) {
	cc, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(local.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("signer: dial: %w", err)
	}
	return centralv1.NewSignerServiceClient(cc), cc, nil
}

// --- append-only signature log

type logEntry struct {
	Ts          string `json:"ts"`
	KeyID       string `json:"key_id"`
	JobID       string `json:"job_id"`
	HostID      string `json:"host_id"`
	Action      string `json:"action"`
	RequestedBy string `json:"requested_by"`
	ExpiresAt   int64  `json:"expires_at"`
	Digest      string `json:"job_sha256"`
}

type signatureLog struct {
	mu sync.Mutex
	f  *os.File
}

func openLog(path string) (*signatureLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("signer: log dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("signer: log: %w", err)
	}
	return &signatureLog{f: f}, nil
}

func (l *signatureLog) append(e logEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("signer: log: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("signer: log: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("signer: log: %w", err)
	}
	return nil
}

func (l *signatureLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
