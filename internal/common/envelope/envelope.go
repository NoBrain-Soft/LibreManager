// Package envelope implements domain-separated Ed25519 signatures and the
// verification of SignedJob envelopes (ARCHITECTURE.md §6.3).
//
// It is shared by the central signer (signing), the agent core and the
// agent helper (verification). The helper repeats every check the core
// performs, so a compromised core cannot execute anything that central did
// not sign for exactly this host within the validity window.
package envelope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Signature domains. A signature produced for one domain never verifies
// for another one.
const (
	DomainJob = "stellwerk-job-v1"
	// DomainKeyRotation is used to announce a new job key signed by the old one.
	DomainKeyRotation = "stellwerk-jobkey-rotation-v1"
)

// Limits.
const (
	// MaxJobBytes bounds the serialized Job inside an envelope.
	MaxJobBytes = 256 << 10
	// NonceSize is the required nonce length.
	NonceSize = 16
	// KeyIDLen is the length of a key id (hex characters).
	KeyIDLen = 16
	// DefaultMaxSkew is the tolerated clock skew between central and host.
	DefaultMaxSkew = 2 * time.Minute
	// DefaultMaxValidity bounds expires_at - not_before.
	DefaultMaxValidity = 1 * time.Hour
)

// Verification errors. Callers can match them with errors.Is.
var (
	ErrMalformed     = errors.New("envelope: malformed")
	ErrOversize      = errors.New("envelope: oversize")
	ErrUnknownKey    = errors.New("envelope: unknown signing key")
	ErrBadSignature  = errors.New("envelope: invalid signature")
	ErrWrongHost     = errors.New("envelope: job is for a different host")
	ErrNotYetValid   = errors.New("envelope: job not yet valid")
	ErrExpired       = errors.New("envelope: job expired")
	ErrWindowInvalid = errors.New("envelope: invalid validity window")
	ErrReplay        = errors.New("envelope: replayed job")
	ErrNoAction      = errors.New("envelope: job has no action")
)

// message builds domain || 0x00 || payload.
func message(domain string, payload []byte) ([]byte, error) {
	if domain == "" || strings.IndexByte(domain, 0) >= 0 {
		return nil, fmt.Errorf("envelope: invalid domain %q", domain)
	}
	m := make([]byte, 0, len(domain)+1+len(payload))
	m = append(m, domain...)
	m = append(m, 0)
	m = append(m, payload...)
	return m, nil
}

// SignBytes signs payload under domain.
func SignBytes(priv ed25519.PrivateKey, domain string, payload []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("envelope: invalid private key size %d", len(priv))
	}
	m, err := message(domain, payload)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, m), nil
}

// VerifyBytes reports whether sig is a valid signature of payload under domain.
func VerifyBytes(pub ed25519.PublicKey, domain string, payload, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	m, err := message(domain, payload)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, m, sig)
}

// KeyID derives the key id of an Ed25519 public key: the first 16 hex
// characters of SHA-256(pub).
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:KeyIDLen]
}

// Signer signs jobs with one Ed25519 key.
type Signer struct {
	priv  ed25519.PrivateKey
	keyID string
}

// NewSigner wraps an Ed25519 private key.
func NewSigner(priv ed25519.PrivateKey) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("envelope: invalid private key size %d", len(priv))
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("envelope: unexpected public key type")
	}
	return &Signer{priv: priv, keyID: KeyID(pub)}, nil
}

// KeyID returns the id of the signing key.
func (s *Signer) KeyID() string { return s.keyID }

// PublicKey returns the public half of the signing key.
func (s *Signer) PublicKey() ed25519.PublicKey {
	pub, _ := s.priv.Public().(ed25519.PublicKey)
	return pub
}

// SignJob serializes job deterministically and signs it under DomainJob.
// It performs structural validation only; policy decisions (who may sign
// what) belong to the signer service.
func (s *Signer) SignJob(job *agentv1.Job) (*agentv1.SignedJob, error) {
	if err := validateJobFields(job); err != nil {
		return nil, err
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(job)
	if err != nil {
		return nil, fmt.Errorf("envelope: marshal job: %w", err)
	}
	if len(b) > MaxJobBytes {
		return nil, ErrOversize
	}
	sig, err := SignBytes(s.priv, DomainJob, b)
	if err != nil {
		return nil, err
	}
	return &agentv1.SignedJob{Job: b, KeyId: s.keyID, Sig: sig}, nil
}

// KeyRing maps key ids to pinned public keys.
type KeyRing map[string]ed25519.PublicKey

// Add inserts pub under its derived key id and returns the id.
func (k KeyRing) Add(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("envelope: invalid public key size %d", len(pub))
	}
	id := KeyID(pub)
	k[id] = append(ed25519.PublicKey(nil), pub...)
	return id, nil
}

// NonceStore remembers nonces of accepted jobs until they expire.
type NonceStore interface {
	// CheckAndStore atomically records nonce until `until` and returns
	// ErrReplay if it was already recorded and has not yet expired.
	CheckAndStore(nonce []byte, until time.Time) error
}

// Verifier verifies SignedJob envelopes for one host.
type Verifier struct {
	Keys   KeyRing
	HostID string
	Nonces NonceStore
	// Now defaults to time.Now.
	Now func() time.Time
	// MaxSkew defaults to DefaultMaxSkew.
	MaxSkew time.Duration
	// MaxValidity defaults to DefaultMaxValidity.
	MaxValidity time.Duration
}

// Verify checks, in order: size, key, signature (over the raw bytes), job
// structure, target host, validity window, and finally records the nonce.
// The nonce is only consumed when every other check passed, so a rejected
// envelope cannot poison the cache. The returned Job is safe to act upon as
// far as authenticity is concerned; local policy must still be applied.
func (v *Verifier) Verify(sj *agentv1.SignedJob) (*agentv1.Job, error) {
	job, err := v.verifyNoNonce(sj)
	if err != nil {
		return nil, err
	}
	if v.Nonces == nil {
		return nil, errors.New("envelope: verifier has no nonce store")
	}
	until := time.Unix(job.GetExpiresAt(), 0).Add(v.skew())
	if err := v.Nonces.CheckAndStore(job.GetNonce(), until); err != nil {
		return nil, err
	}
	return job, nil
}

func (v *Verifier) skew() time.Duration {
	if v.MaxSkew > 0 {
		return v.MaxSkew
	}
	return DefaultMaxSkew
}

func (v *Verifier) maxValidity() time.Duration {
	if v.MaxValidity > 0 {
		return v.MaxValidity
	}
	return DefaultMaxValidity
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) verifyNoNonce(sj *agentv1.SignedJob) (*agentv1.Job, error) {
	if sj == nil {
		return nil, ErrMalformed
	}
	if len(sj.GetJob()) == 0 || len(sj.GetSig()) != ed25519.SignatureSize || len(sj.GetKeyId()) != KeyIDLen {
		return nil, ErrMalformed
	}
	if len(sj.GetJob()) > MaxJobBytes {
		return nil, ErrOversize
	}
	pub, ok := v.Keys[sj.GetKeyId()]
	if !ok {
		return nil, ErrUnknownKey
	}
	if !VerifyBytes(pub, DomainJob, sj.GetJob(), sj.GetSig()) {
		return nil, ErrBadSignature
	}

	var job agentv1.Job
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(sj.GetJob(), &job); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if err := validateJobFields(&job); err != nil {
		return nil, err
	}
	if v.HostID == "" || job.GetHostId() != v.HostID {
		return nil, ErrWrongHost
	}

	now := v.now()
	skew := v.skew()
	nb := time.Unix(job.GetNotBefore(), 0)
	exp := time.Unix(job.GetExpiresAt(), 0)
	if !exp.After(nb) || exp.Sub(nb) > v.maxValidity() {
		return nil, ErrWindowInvalid
	}
	if now.Add(skew).Before(nb) {
		return nil, ErrNotYetValid
	}
	if !now.Add(-skew).Before(exp) {
		return nil, ErrExpired
	}
	return &job, nil
}

func validateJobFields(job *agentv1.Job) error {
	if job == nil {
		return ErrMalformed
	}
	if !ids.Valid(job.GetJobId()) {
		return fmt.Errorf("%w: invalid job_id", ErrMalformed)
	}
	if !ids.Valid(job.GetHostId()) {
		return fmt.Errorf("%w: invalid host_id", ErrMalformed)
	}
	if len(job.GetNonce()) != NonceSize {
		return fmt.Errorf("%w: invalid nonce", ErrMalformed)
	}
	if job.GetNotBefore() <= 0 || job.GetExpiresAt() <= 0 {
		return ErrWindowInvalid
	}
	if job.GetAction() == nil {
		return ErrNoAction
	}
	return nil
}

// ActionName returns a stable name for the job's action (for logs, policy
// and rate limiting), e.g. "pkg_upgrade".
func ActionName(job *agentv1.Job) string {
	switch job.GetAction().(type) {
	case *agentv1.Job_PkgRefresh:
		return "pkg_refresh"
	case *agentv1.Job_PkgUpgrade:
		return "pkg_upgrade"
	case *agentv1.Job_PkgInstall:
		return "pkg_install"
	case *agentv1.Job_PkgRemove:
		return "pkg_remove"
	case *agentv1.Job_Service:
		return "service"
	case *agentv1.Job_Reboot:
		return "reboot"
	case *agentv1.Job_Shell:
		return "shell"
	case *agentv1.Job_RunCheck:
		return "run_check"
	case *agentv1.Job_Script:
		return "script"
	case *agentv1.Job_AgentUpdate:
		return "agent_update"
	case *agentv1.Job_FileRead:
		return "file_read"
	case *agentv1.Job_ProbeConfig:
		return "probe_config"
	case *agentv1.Job_CollectInventory:
		return "collect_inventory"
	default:
		return "unknown"
	}
}
