package jobs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	"github.com/nobrain-soft/libremanager/internal/common/envelope"
	"github.com/nobrain-soft/libremanager/internal/common/ids"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

type fakeHelper struct {
	mu    sync.Mutex
	calls int
}

func (f *fakeHelper) ExecuteJob(_ context.Context, _ *agentv1.SignedJob, onOutput func(*agentv1.JobOutput), _ func(*os.File, int32)) (*agentv1.JobFinished, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	onOutput(&agentv1.JobOutput{Stream: agentv1.OutputStream_OUTPUT_STREAM_STDOUT, Data: []byte("ok\n")})
	return &agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_SUCCEEDED}, nil
}

func (f *fakeHelper) n() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

type rec struct {
	mu  sync.Mutex
	evs []*agentv1.JobEvent
}

func (r *rec) emit(e *agentv1.JobEvent) { r.mu.Lock(); r.evs = append(r.evs, e); r.mu.Unlock() }

func (r *rec) finished(jobID string) *agentv1.JobFinished {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.evs {
		if e.GetJobId() == jobID && e.GetFinished() != nil {
			return e.GetFinished()
		}
	}
	return nil
}

type fixture struct {
	runner *Runner
	signer *envelope.Signer
	helper *fakeHelper
	rec    *rec
	hostID string
	synced bool
}

func newFixture(t *testing.T, yaml string) *fixture {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := envelope.NewSigner(priv)
	ring := envelope.KeyRing{}
	_, _ = ring.Add(s.PublicKey())
	p, err := policy.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{signer: s, helper: &fakeHelper{}, rec: &rec{}, hostID: ids.New(), synced: true}
	f.runner = &Runner{
		Verifier: &envelope.Verifier{Keys: ring, HostID: f.hostID, Nonces: envelope.NewMemoryNonceStore(nil)},
		Policy:   &policy.Evaluator{P: p}, Limiter: policy.NewRateLimiter(p.Limits.MaxJobsPerMinute, nil),
		Helper: f.helper, Emit: f.rec.emit,
		TimeSynced: func() (bool, error) { return f.synced, nil },
	}
	return f
}

const allowUpgrade = `
capabilities:
  packages: { list: true, upgrade: true }
limits: { max_jobs_per_minute: 2 }
`

func (f *fixture) job(t *testing.T) (*agentv1.SignedJob, string) {
	t.Helper()
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	id := ids.New()
	sj, err := f.signer.SignJob(&agentv1.Job{JobId: id, HostId: f.hostID, NotBefore: time.Now().Unix(), ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Nonce: nonce, RequestedBy: "alice", Action: &agentv1.Job_PkgUpgrade{PkgUpgrade: &agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY}}})
	if err != nil {
		t.Fatal(err)
	}
	return sj, id
}

func waitFinished(t *testing.T, r *rec, id string) *agentv1.JobFinished {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f := r.finished(id); f != nil {
			return f
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s did not finish", id)
	return nil
}

func TestRunsVerifiedJobThroughHelper(t *testing.T) {
	f := newFixture(t, allowUpgrade)
	sj, id := f.job(t)
	f.runner.Handle(context.Background(), sj)
	if fin := waitFinished(t, f.rec, id); fin.GetStatus() != agentv1.JobStatus_JOB_STATUS_SUCCEEDED || f.helper.n() != 1 {
		t.Fatalf("fin=%v calls=%d", fin, f.helper.n())
	}
}

func TestReplayIsIgnoredSilently(t *testing.T) {
	f := newFixture(t, allowUpgrade)
	sj, id := f.job(t)
	f.runner.Handle(context.Background(), sj)
	waitFinished(t, f.rec, id)
	f.runner.Handle(context.Background(), sj)
	time.Sleep(100 * time.Millisecond)
	f.rec.mu.Lock()
	n := 0
	for _, e := range f.rec.evs {
		if e.GetFinished() != nil {
			n++
		}
	}
	f.rec.mu.Unlock()
	if n != 1 || f.helper.n() != 1 {
		t.Fatalf("replay produced %d finished events, %d helper calls", n, f.helper.n())
	}
}

func TestRejections(t *testing.T) {
	cases := map[string]struct {
		yaml   string
		mutate func(f *fixture)
	}{
		"clock not synced": {allowUpgrade, func(f *fixture) { f.synced = false }},
		"policy denies":    {"capabilities: { packages: { upgrade: false } }\n", func(*fixture) {}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, tc.yaml)
			tc.mutate(f)
			sj, id := f.job(t)
			f.runner.Handle(context.Background(), sj)
			fin := waitFinished(t, f.rec, id)
			if fin.GetStatus() != agentv1.JobStatus_JOB_STATUS_REJECTED || f.helper.n() != 0 {
				t.Fatalf("fin=%v helper calls=%d", fin, f.helper.n())
			}
		})
	}
}

func TestRateLimit(t *testing.T) {
	f := newFixture(t, allowUpgrade)
	var last string
	for range 3 {
		sj, id := f.job(t)
		f.runner.Handle(context.Background(), sj)
		last = id
	}
	if fin := waitFinished(t, f.rec, last); fin.GetStatus() != agentv1.JobStatus_JOB_STATUS_REJECTED {
		t.Fatalf("third job within a minute: %v", fin)
	}
}

func TestWrongKeyNeverReachesHelper(t *testing.T) {
	f := newFixture(t, allowUpgrade)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := envelope.NewSigner(priv)
	f.signer = other
	sj, id := f.job(t)
	f.runner.Handle(context.Background(), sj)
	fin := waitFinished(t, f.rec, id)
	if fin.GetStatus() != agentv1.JobStatus_JOB_STATUS_REJECTED || f.helper.n() != 0 {
		t.Fatalf("fin=%v calls=%d", fin, f.helper.n())
	}
	if !errors.Is(func() error { _, err := f.runner.Verify(sj); return err }(), envelope.ErrUnknownKey) {
		t.Fatal("expected ErrUnknownKey")
	}
}
