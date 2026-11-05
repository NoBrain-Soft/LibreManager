package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

type fixture struct {
	signer   *Signer
	otherKey *Signer
	hostID   string
	verifier *Verifier
	nonces   *MemoryNonceStore
}

func newSigner(t testing.TB) *Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	f := &fixture{signer: newSigner(t), otherKey: newSigner(t), hostID: ids.New()}
	ring := KeyRing{}
	if _, err := ring.Add(f.signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	f.nonces = NewMemoryNonceStore(func() time.Time { return t0 })
	f.verifier = &Verifier{Keys: ring, HostID: f.hostID, Nonces: f.nonces, Now: func() time.Time { return t0 }}
	return f
}

func (f *fixture) job() *agentv1.Job {
	nonce := make([]byte, NonceSize)
	_, _ = rand.Read(nonce)
	return &agentv1.Job{
		JobId:       ids.New(),
		HostId:      f.hostID,
		NotBefore:   t0.Add(-time.Minute).Unix(),
		ExpiresAt:   t0.Add(9 * time.Minute).Unix(),
		Nonce:       nonce,
		RequestedBy: "alice",
		Action:      &agentv1.Job_PkgRefresh{PkgRefresh: &agentv1.PkgRefresh{}},
	}
}

func (f *fixture) sign(t testing.TB, j *agentv1.Job) *agentv1.SignedJob {
	t.Helper()
	sj, err := f.signer.SignJob(j)
	if err != nil {
		t.Fatal(err)
	}
	return sj
}

// signRaw signs arbitrary job bytes, bypassing SignJob's structural checks,
// to prove the verifier enforces them independently.
func signRaw(t testing.TB, s *Signer, j *agentv1.Job) *agentv1.SignedJob {
	t.Helper()
	b, err := proto.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignBytes(s.priv, DomainJob, b)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.SignedJob{Job: b, KeyId: s.KeyID(), Sig: sig}
}

func TestVerifyValid(t *testing.T) {
	f := newFixture(t)
	j := f.job()
	got, err := f.verifier.Verify(f.sign(t, j))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.GetJobId() != j.GetJobId() || ActionName(got) != "pkg_refresh" {
		t.Fatalf("unexpected job %v", got)
	}
}

func TestVerifyNegative(t *testing.T) {
	cases := []struct {
		name string
		make func(t *testing.T, f *fixture) *agentv1.SignedJob
		want error
	}{
		{"nil envelope", func(*testing.T, *fixture) *agentv1.SignedJob { return nil }, ErrMalformed},
		{"empty job bytes", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			sj := f.sign(t, f.job())
			sj.Job = nil
			return sj
		}, ErrMalformed},
		{"truncated signature", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			sj := f.sign(t, f.job())
			sj.Sig = sj.Sig[:63]
			return sj
		}, ErrMalformed},
		{"bad key id length", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			sj := f.sign(t, f.job())
			sj.KeyId = "abc"
			return sj
		}, ErrMalformed},
		{"oversize", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			sj := f.sign(t, f.job())
			sj.Job = make([]byte, MaxJobBytes+1)
			return sj
		}, ErrOversize},
		{"unknown key", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			sj, err := f.otherKey.SignJob(f.job())
			if err != nil {
				t.Fatal(err)
			}
			return sj
		}, ErrUnknownKey},
		{"wrong key under pinned key id", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			sj, err := f.otherKey.SignJob(f.job())
			if err != nil {
				t.Fatal(err)
			}
			sj.KeyId = f.signer.KeyID()
			return sj
		}, ErrBadSignature},
		{"tampered payload", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			sj := f.sign(t, f.job())
			sj.Job = bytes.Clone(sj.Job)
			sj.Job[len(sj.Job)-1] ^= 0x01
			return sj
		}, ErrBadSignature},
		{"tampered signature", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			sj := f.sign(t, f.job())
			sj.Sig = bytes.Clone(sj.Sig)
			sj.Sig[0] ^= 0x80
			return sj
		}, ErrBadSignature},
		{"wrong domain", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			b, _ := proto.Marshal(f.job())
			sig, err := SignBytes(f.signer.priv, DomainKeyRotation, b)
			if err != nil {
				t.Fatal(err)
			}
			return &agentv1.SignedJob{Job: b, KeyId: f.signer.KeyID(), Sig: sig}
		}, ErrBadSignature},
		{"signed garbage", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			b := []byte{0xff, 0xff, 0xff, 0xff}
			sig, _ := SignBytes(f.signer.priv, DomainJob, b)
			return &agentv1.SignedJob{Job: b, KeyId: f.signer.KeyID(), Sig: sig}
		}, ErrMalformed},
		{"wrong host", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			j := f.job()
			j.HostId = ids.New()
			return f.sign(t, j)
		}, ErrWrongHost},
		{"invalid host id", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			j := f.job()
			j.HostId = "*"
			return signRaw(t, f.signer, j)
		}, ErrMalformed},
		{"invalid job id", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			j := f.job()
			j.JobId = "not-a-uuid"
			return signRaw(t, f.signer, j)
		}, ErrMalformed},
		{"missing nonce", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			j := f.job()
			j.Nonce = nil
			return signRaw(t, f.signer, j)
		}, ErrMalformed},
		{"short nonce", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			j := f.job()
			j.Nonce = j.Nonce[:8]
			return signRaw(t, f.signer, j)
		}, ErrMalformed},
		{"no action", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			j := f.job()
			j.Action = nil
			return signRaw(t, f.signer, j)
		}, ErrNoAction},
		{"expired", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			j := f.job()
			j.NotBefore = t0.Add(-20 * time.Minute).Unix()
			j.ExpiresAt = t0.Add(-3 * time.Minute).Unix()
			return f.sign(t, j)
		}, ErrExpired},
		{"expired within skew boundary", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			j := f.job()
			j.NotBefore = t0.Add(-20 * time.Minute).Unix()
			j.ExpiresAt = t0.Add(-DefaultMaxSkew).Unix()
			return f.sign(t, j)
		}, ErrExpired},
		{"not yet valid", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			j := f.job()
			j.NotBefore = t0.Add(5 * time.Minute).Unix()
			j.ExpiresAt = t0.Add(15 * time.Minute).Unix()
			return f.sign(t, j)
		}, ErrNotYetValid},
		{"inverted window", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			j := f.job()
			j.NotBefore, j.ExpiresAt = j.ExpiresAt, j.NotBefore
			return f.sign(t, j)
		}, ErrWindowInvalid},
		{"window too long", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			j := f.job()
			j.ExpiresAt = t0.Add(48 * time.Hour).Unix()
			return f.sign(t, j)
		}, ErrWindowInvalid},
		{"zero window", func(t *testing.T, f *fixture) *agentv1.SignedJob {
			j := f.job()
			j.NotBefore = 0
			j.ExpiresAt = 0
			return signRaw(t, f.signer, j)
		}, ErrWindowInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			sj := tc.make(t, f)
			_, err := f.verifier.Verify(sj)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify err = %v, want %v", err, tc.want)
			}
			if f.nonces.Len() != 0 {
				t.Fatalf("rejected envelope consumed a nonce")
			}
		})
	}
}

func TestVerifyReplay(t *testing.T) {
	f := newFixture(t)
	sj := f.sign(t, f.job())
	if _, err := f.verifier.Verify(sj); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if _, err := f.verifier.Verify(sj); !errors.Is(err, ErrReplay) {
		t.Fatalf("second Verify err = %v, want ErrReplay", err)
	}
}

func TestVerifyReplayAcrossRestartWithFileStore(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "nonces")
	now := func() time.Time { return t0 }
	store, err := OpenFileNonceStore(path, now)
	if err != nil {
		t.Fatal(err)
	}
	f.verifier.Nonces = store
	sj := f.sign(t, f.job())
	if _, err := f.verifier.Verify(sj); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileNonceStore(path, now)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	f.verifier.Nonces = reopened
	if _, err := f.verifier.Verify(sj); !errors.Is(err, ErrReplay) {
		t.Fatalf("Verify after restart err = %v, want ErrReplay", err)
	}
}

func TestFileStoreCompactsExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonces")
	cur := t0
	now := func() time.Time { return cur }
	s, err := OpenFileNonceStore(path, now)
	if err != nil {
		t.Fatal(err)
	}
	n := bytes.Repeat([]byte{1}, NonceSize)
	if err := s.CheckAndStore(n, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	cur = t0.Add(2 * time.Minute)
	s2, err := OpenFileNonceStore(path, now)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.mem.Len() != 0 {
		t.Fatalf("expired entry not compacted")
	}
	// Expired nonce may be stored again (the envelope itself is expired anyway).
	if err := s2.CheckAndStore(n, cur.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestNonceStoreCapacityFailsClosed(t *testing.T) {
	s := NewMemoryNonceStore(func() time.Time { return t0 })
	s.SetCapacity(2)
	for i := range 2 {
		n := bytes.Repeat([]byte{byte(i)}, NonceSize)
		if err := s.CheckAndStore(n, t0.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CheckAndStore(bytes.Repeat([]byte{9}, NonceSize), t0.Add(time.Hour)); !errors.Is(err, ErrNonceStoreFull) {
		t.Fatalf("err = %v, want ErrNonceStoreFull", err)
	}
}

func TestVerifyWithinSkewAccepted(t *testing.T) {
	f := newFixture(t)
	j := f.job()
	// Not yet valid by 90 s, but within 2 min skew.
	j.NotBefore = t0.Add(90 * time.Second).Unix()
	j.ExpiresAt = t0.Add(10 * time.Minute).Unix()
	if _, err := f.verifier.Verify(f.sign(t, j)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyEmptyVerifierHostRejects(t *testing.T) {
	f := newFixture(t)
	f.verifier.HostID = ""
	if _, err := f.verifier.Verify(f.sign(t, f.job())); !errors.Is(err, ErrWrongHost) {
		t.Fatalf("err = %v, want ErrWrongHost", err)
	}
}

func TestSignBytesDomainSeparation(t *testing.T) {
	s := newSigner(t)
	payload := []byte("hello")
	sig, err := SignBytes(s.priv, "a", payload)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyBytes(s.PublicKey(), "a", payload, sig) {
		t.Fatal("valid signature rejected")
	}
	// "a" || 0 || "hello" must not equal "a\x00h" || 0 || "ello": domains
	// with NUL are rejected outright.
	if VerifyBytes(s.PublicKey(), "a\x00h", []byte("ello"), sig) {
		t.Fatal("NUL in domain accepted")
	}
	if _, err := SignBytes(s.priv, "", payload); err == nil {
		t.Fatal("empty domain accepted")
	}
	if VerifyBytes(s.PublicKey(), "b", payload, sig) {
		t.Fatal("signature verified under another domain")
	}
}

func TestSignJobRejectsInvalid(t *testing.T) {
	f := newFixture(t)
	j := f.job()
	j.Action = nil
	if _, err := f.signer.SignJob(j); !errors.Is(err, ErrNoAction) {
		t.Fatalf("err = %v", err)
	}
}

func TestKeyRingAddRejectsBadKey(t *testing.T) {
	if _, err := (KeyRing{}).Add(ed25519.PublicKey{1, 2, 3}); err == nil {
		t.Fatal("short key accepted")
	}
}

// FuzzVerify ensures arbitrary envelope bytes never panic the verifier and
// are never accepted unless they carry a valid signature.
func FuzzVerify(f *testing.F) {
	fx := newFixture(f)
	valid := fx.sign(f, fx.job())
	b, _ := proto.Marshal(valid)
	f.Add(b)
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		var sj agentv1.SignedJob
		if err := proto.Unmarshal(data, &sj); err != nil {
			return
		}
		fx.verifier.Nonces = NewMemoryNonceStore(func() time.Time { return t0 })
		job, err := fx.verifier.Verify(&sj)
		if err != nil {
			return
		}
		// Accepted: it must carry a genuine signature over its bytes.
		if !VerifyBytes(fx.signer.PublicKey(), DomainJob, sj.GetJob(), sj.GetSig()) {
			t.Fatalf("accepted envelope without valid signature: %v", job)
		}
	})
}

// FuzzVerifyBytes checks the low-level primitive never panics.
func FuzzVerifyBytes(f *testing.F) {
	s := newSigner(f)
	f.Add("stellwerk-job-v1", []byte("x"), make([]byte, 64))
	f.Fuzz(func(t *testing.T, domain string, payload, sig []byte) {
		_ = VerifyBytes(s.PublicKey(), domain, payload, sig)
	})
}
