// Package integration runs central and agent components together
// in-process with real TLS, a real PostgreSQL database and the real
// privileged helper on a unix socket (with a fake package manager).
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/nobrain-soft/libremanager/internal/agent/enroll"
	"github.com/nobrain-soft/libremanager/internal/agent/helperclient"
	"github.com/nobrain-soft/libremanager/internal/agent/jobs"
	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	"github.com/nobrain-soft/libremanager/internal/agent/runtime"
	"github.com/nobrain-soft/libremanager/internal/agent/state"
	"github.com/nobrain-soft/libremanager/internal/common/envelope"
	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/secretbox"
	"github.com/nobrain-soft/libremanager/internal/helper"
	"github.com/nobrain-soft/libremanager/internal/helper/pkgmgr"
	"github.com/nobrain-soft/libremanager/internal/pki"
	"github.com/nobrain-soft/libremanager/internal/pki/testpki"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	centralv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/central/v1"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/auth"
	"github.com/nobrain-soft/libremanager/internal/server/gateway"
	"github.com/nobrain-soft/libremanager/internal/server/signer"
	"github.com/nobrain-soft/libremanager/internal/server/store"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
	"github.com/nobrain-soft/libremanager/internal/server/store/storetest"
)

// fakePkg records operations instead of touching the system.
type fakePkg struct {
	mu       sync.Mutex
	upgrades int
}

func (f *fakePkg) Name() string { return "fake" }
func (f *fakePkg) Refresh(_ context.Context, o pkgmgr.Output) (pkgmgr.Result, error) {
	if o.Stdout != nil {
		_, _ = io.WriteString(o.Stdout, "Hit:1 fake repo\n")
	}
	return pkgmgr.Result{}, nil
}
func (f *fakePkg) ListUpgrades(context.Context) ([]pkgmgr.Upgrade, error) {
	return []pkgmgr.Upgrade{{Name: "openssl", Arch: "amd64", CurrentVersion: "3.0.11-1", CandidateVersion: "3.0.13-1", IsSecurity: true, Source: "Debian-Security"}}, nil
}
func (f *fakePkg) Upgrade(_ context.Context, spec pkgmgr.UpgradeSpec, o pkgmgr.Output) (pkgmgr.Result, error) {
	f.mu.Lock()
	f.upgrades++
	f.mu.Unlock()
	if o.Stdout != nil {
		fmt.Fprintf(o.Stdout, "Upgrading (%s)... openssl 3.0.13-1\n", spec.Scope)
	}
	return pkgmgr.Result{}, nil
}
func (f *fakePkg) Install(context.Context, []string, pkgmgr.Output) (pkgmgr.Result, error) {
	return pkgmgr.Result{ExitCode: 1}, nil
}
func (f *fakePkg) Remove(context.Context, []string, pkgmgr.Output) (pkgmgr.Result, error) {
	return pkgmgr.Result{ExitCode: 1}, nil
}
func (f *fakePkg) Hold(context.Context, []string, bool, pkgmgr.Output) (pkgmgr.Result, error) {
	return pkgmgr.Result{}, nil
}
func (f *fakePkg) RebootRequired(context.Context) (bool, []string, error) { return false, nil, nil }
func (f *fakePkg) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.upgrades
}

type memJournal struct {
	mu   sync.Mutex
	msgs []string
}

func (j *memJournal) Send(_ int, msg string, _ map[string]string) error {
	j.mu.Lock()
	j.msgs = append(j.msgs, msg)
	j.mu.Unlock()
	return nil
}

func (j *memJournal) has(sub string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, m := range j.msgs {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

type staticFacts struct{}

func (staticFacts) Facts(context.Context) *agentv1.HostFacts {
	return &agentv1.HostFacts{Hostname: "itest-host", OsFamily: "debian", OsId: "debian", OsVersion: "12", AgentVersion: "itest"}
}
func (staticFacts) CollectAll(context.Context) (*agentv1.InventoryReport, error) {
	return &agentv1.InventoryReport{CollectedAtMs: time.Now().UnixMilli(), Sections: []*agentv1.InventorySection{
		{Data: &agentv1.InventorySection_Os{Os: &agentv1.OsInfo{Id: "debian", PrettyName: "Debian GNU/Linux 12 (bookworm)"}}}}}, nil
}
func (staticFacts) Packages(context.Context) (*agentv1.InventorySection, error) {
	return &agentv1.InventorySection{Data: &agentv1.InventorySection_Packages{Packages: &agentv1.PackageList{Manager: "dpkg"}}}, nil
}
func (staticFacts) PackageDBFingerprint() string { return "x" }

type world struct {
	t       *testing.T
	ctx     context.Context
	st      *store.Store
	signer  *signer.Service
	hostID  uuid.UUID
	pkg     *fakePkg
	journal *memJournal
}

func setup(t *testing.T) *world {
	t.Helper()
	st := storetest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := testpki.New(t)
	dir := t.TempDir()

	// Signer with its key published in the DB (what `server init` does).
	mk, _ := secretbox.NewKey()
	if _, err := signer.GenerateKeyFile(mk, filepath.Join(dir, "jobkey")); err != nil {
		t.Fatal(err)
	}
	js, _ := signer.LoadKeyFile(mk, filepath.Join(dir, "jobkey"))
	svc, err := signer.NewService(js, filepath.Join(dir, "sig.log"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Q.UpsertJobSigningKey(ctx, db.UpsertJobSigningKeyParams{KeyID: js.KeyID(), PublicKey: js.PublicKey()}); err != nil {
		t.Fatal(err)
	}

	pepper := auth.Pepper(bytes.Repeat([]byte{7}, 32))
	gw, err := gateway.New(gateway.Config{Store: st, Audit: audit.New(st), CA: p.Intermediate, Roots: p.Roots,
		ServerNames: []string{"localhost"}, ServerIPs: []net.IP{net.ParseIP("127.0.0.1")}, Pepper: pepper})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gw.Serve(ctx, ln) }()
	go gw.RunBackground(ctx)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	central := "localhost:" + port

	tok, _ := auth.RandomToken(auth.PrefixEnrollment)
	if _, err := st.Q.CreateEnrollmentToken(ctx, db.CreateEnrollmentTokenParams{ID: ids.NewUUID(), TokenHash: pepper.HashToken(tok),
		Labels: json.RawMessage(`{}`), MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	// Host side: trust anchors + local policy.
	paths := state.Paths{StateDir: filepath.Join(dir, "state"), HostIDFile: filepath.Join(dir, "etc", "host-id"),
		JobKeysDir: filepath.Join(dir, "etc", "jobkeys.d"), CAFile: filepath.Join(dir, "etc", "ca.pem")}
	_ = os.MkdirAll(filepath.Dir(paths.CAFile), 0o755)
	if err := os.WriteFile(paths.CAFile, pki.EncodeCertPEM(p.Root.Cert), 0o644); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "etc", "agent.yaml")
	policyYAML := fmt.Sprintf(`central: %q
ca_fingerprint_sha256: %q
require_time_sync: false
capabilities:
  metrics: true
  inventory: true
  packages: { list: true, upgrade: true, install: false, remove: false }
  services: { control: true, allow: ["*.service"], deny: ["sshd.service"] }
`, central, pki.Fingerprint(p.Root.Cert))
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Parse([]byte(policyYAML))
	if err != nil {
		t.Fatal(err)
	}

	// Enroll exactly like `stellwerk-agent enroll`.
	res, err := enroll.Enroll(ctx, enroll.Options{Central: central, CAFingerprint: pol.CAFingerprint, Token: tok, Paths: paths,
		Facts: staticFacts{}.Facts(ctx)})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// Root helper on a unix socket with a fake package manager.
	sock := filepath.Join(dir, "helper.sock")
	hl, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	pkg := &fakePkg{}
	jr := &memJournal{}
	helperState := filepath.Join(dir, "helper-state")
	_ = os.MkdirAll(helperState, 0o700)
	hs, err := helper.NewServer(helper.Config{PolicyPath: policyPath, HostIDPath: paths.HostIDFile, JobKeysDir: paths.JobKeysDir,
		StateDir: helperState, AllowedUID: os.Getuid(), TimeSynced: func() (bool, error) { return true, nil },
		PkgManager: pkg, Journal: jr, SkipOwnerChecks: true, Version: "itest"})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = hs.Serve(ctx, hl) }()

	// Agent core.
	cert, err := state.LoadIdentity(paths)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := state.LoadJobKeys(paths)
	if err != nil {
		t.Fatal(err)
	}
	_, roots, err := state.LoadPinnedRoot(paths, pol.CAFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	nonces, err := envelope.OpenFileNonceStore(paths.NonceFile(), nil)
	if err != nil {
		t.Fatal(err)
	}
	hc := &helperclient.Client{SocketPath: sock}
	runner := &jobs.Runner{
		Verifier: &envelope.Verifier{Keys: keys, HostID: res.HostID, Nonces: nonces},
		Policy:   &policy.Evaluator{P: pol}, Limiter: policy.NewRateLimiter(pol.Limits.MaxJobsPerMinute, nil),
		Helper: hc, Journal: jr,
	}
	agent, err := runtime.New(runtime.Config{Policy: pol, Paths: paths, Identity: state.NewIdentity(cert), Roots: roots, Version: "itest",
		Inventory: staticFacts{}, Updates: hc, Runner: runner, MinBackoff: 100 * time.Millisecond, MaxBackoff: time.Second,
		HelperAvailable: func(ctx context.Context) bool { _, err := hc.Ping(ctx); return err == nil }})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = agent.Run(ctx) }()

	w := &world{t: t, ctx: ctx, st: st, signer: svc, hostID: uuid.MustParse(res.HostID), pkg: pkg, journal: jr}
	w.waitFor("agent connected", func() bool {
		h, err := st.Q.GetHost(ctx, w.hostID)
		return err == nil && h.Connected
	})
	return w
}

func (w *world) waitFor(what string, cond func() bool) {
	w.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	w.t.Fatalf("timed out waiting for %s", what)
}

// queue signs a job via the signer and queues it like the API does.
func (w *world) queue(action *agentv1.Job) (uuid.UUID, *agentv1.SignedJob) {
	w.t.Helper()
	jobID := ids.NewUUID()
	action.JobId = jobID.String()
	action.RequestedBy = "alice"
	resp, err := w.signer.SignJobs(w.ctx, &centralv1.SignJobsRequest{Template: action, HostIds: []string{w.hostID.String()}})
	if err != nil {
		w.t.Fatal(err)
	}
	sj := resp.GetEnvelopes()[0].GetSigned()
	w.insert(jobID, sj)
	return jobID, sj
}

func (w *world) insert(jobID uuid.UUID, sj *agentv1.SignedJob) {
	w.t.Helper()
	raw, _ := proto.Marshal(sj)
	if _, err := w.st.Q.CreateJob(w.ctx, db.CreateJobParams{ID: jobID, Type: "test", Params: json.RawMessage(`{}`), RequestedByName: "alice"}); err != nil {
		w.t.Fatal(err)
	}
	if err := w.st.Q.InsertJobTarget(w.ctx, db.InsertJobTargetParams{JobID: jobID, HostID: w.hostID, SignedEnvelope: raw, ExpiresAt: time.Now().Add(10 * time.Minute)}); err != nil {
		w.t.Fatal(err)
	}
	if err := w.st.Notify(w.ctx, store.ChanDispatch, w.hostID.String()); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) target(jobID uuid.UUID) db.JobTarget {
	t, err := w.st.Q.GetJobTarget(w.ctx, db.GetJobTargetParams{JobID: jobID, HostID: w.hostID})
	if err != nil {
		w.t.Fatal(err)
	}
	return t
}

func (w *world) output(jobID uuid.UUID) string {
	rows, _ := w.st.Q.ListJobOutput(w.ctx, db.ListJobOutputParams{JobID: jobID, HostID: w.hostID})
	var b strings.Builder
	for _, r := range rows {
		b.Write(r.Data)
	}
	return b.String()
}

func TestSignedJobPipeline(t *testing.T) {
	w := setup(t)

	// Pending updates were reported through the helper on connect.
	w.waitFor("updates report", func() bool {
		s, err := w.st.Q.GetUpdateStatus(w.ctx, w.hostID)
		return err == nil && s.Security == 1
	})

	// 1. Security upgrade succeeds with live output, journald entries on host.
	jobID, sj := w.queue(&agentv1.Job{Action: &agentv1.Job_PkgUpgrade{PkgUpgrade: &agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY}}})
	w.waitFor("upgrade succeeded", func() bool { return w.target(jobID).Status == "succeeded" })
	if out := w.output(jobID); !strings.Contains(out, "openssl 3.0.13-1") {
		t.Fatalf("job output = %q", out)
	}
	if j, _ := w.st.Q.GetJob(w.ctx, jobID); j.Status != "succeeded" {
		t.Fatalf("job status %s", j.Status)
	}
	if !w.journal.has("accepted") {
		t.Fatal("no journald entry for accepted job")
	}
	if w.pkg.count() != 1 {
		t.Fatalf("upgrades = %d", w.pkg.count())
	}

	// 2. Replay: the same envelope delivered again under a new job row is
	// never executed a second time.
	replayID := ids.NewUUID()
	w.insert(replayID, sj)
	w.waitFor("replay dispatched", func() bool { return w.target(replayID).Status != "queued" })
	time.Sleep(time.Second)
	if w.pkg.count() != 1 {
		t.Fatalf("replayed envelope executed: upgrades = %d", w.pkg.count())
	}

	// 3. Tampered envelope (job bytes modified after signing) is rejected by
	// the agent and never reaches the package manager.
	tamperID, sj2 := w.queue(&agentv1.Job{Action: &agentv1.Job_PkgRefresh{PkgRefresh: &agentv1.PkgRefresh{}}})
	_ = sj2
	w.waitFor("refresh done", func() bool { return w.target(tamperID).Status == "succeeded" })
	var j agentv1.Job
	_ = proto.Unmarshal(sj.GetJob(), &j)
	j.Action = &agentv1.Job_PkgUpgrade{PkgUpgrade: &agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_ALL}}
	newID := ids.NewUUID()
	j.JobId = newID.String()
	j.Nonce = bytes.Repeat([]byte{9}, 16)
	forged, _ := proto.Marshal(&j)
	w.insert(newID, &agentv1.SignedJob{Job: forged, KeyId: sj.GetKeyId(), Sig: sj.GetSig()})
	w.waitFor("forged job rejected", func() bool { return w.target(newID).Status == "rejected" })
	if w.pkg.count() != 1 {
		t.Fatalf("forged envelope executed: upgrades = %d", w.pkg.count())
	}

	// 4. Policy-denied action (install disabled locally) is rejected even
	// though it is validly signed.
	denyID, _ := w.queue(&agentv1.Job{Action: &agentv1.Job_PkgInstall{PkgInstall: &agentv1.PkgInstall{Packages: []string{"nmap"}}}})
	w.waitFor("install rejected", func() bool { return w.target(denyID).Status == "rejected" })
	if msg := w.target(denyID).Message; !strings.Contains(msg, "install disabled") {
		t.Fatalf("rejection message %q", msg)
	}

	// 5. Service on the deny list is rejected.
	svcID, _ := w.queue(&agentv1.Job{Action: &agentv1.Job_Service{Service: &agentv1.ServiceAction{Unit: "sshd.service", Op: agentv1.ServiceOp_SERVICE_OP_STOP}}})
	w.waitFor("sshd stop rejected", func() bool { return w.target(svcID).Status == "rejected" })

	// 6. An envelope signed for another host is rejected.
	other := &agentv1.Job{JobId: ids.New(), RequestedBy: "alice", Action: &agentv1.Job_PkgRefresh{PkgRefresh: &agentv1.PkgRefresh{}}}
	resp, err := w.signer.SignJobs(w.ctx, &centralv1.SignJobsRequest{Template: other, HostIds: []string{ids.New()}})
	if err != nil {
		t.Fatal(err)
	}
	wrongID := uuid.MustParse(other.GetJobId())
	w.insert(wrongID, resp.GetEnvelopes()[0].GetSigned())
	w.waitFor("wrong host rejected", func() bool { return w.target(wrongID).Status == "rejected" })
}
