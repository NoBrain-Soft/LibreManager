package helper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/nobrain-soft/libremanager/internal/agent/helperclient"
	"github.com/nobrain-soft/libremanager/internal/common/envelope"
	"github.com/nobrain-soft/libremanager/internal/common/framing"
	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/helper/pkgmgr"
	"github.com/nobrain-soft/libremanager/internal/helper/runner"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	helperv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/helper/v1"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

// --- fakes ----------------------------------------------------------------

type entry struct {
	pri    int
	msg    string
	fields map[string]string
}

type fakeJournal struct {
	mu      sync.Mutex
	entries []entry
	fail    atomic.Bool
}

func (j *fakeJournal) Send(pri int, msg string, fields map[string]string) error {
	if j.fail.Load() {
		return errors.New("journal down")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.entries = append(j.entries, entry{pri, msg, fields})
	return nil
}

func (j *fakeJournal) all() []entry {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]entry(nil), j.entries...)
}

func (j *fakeJournal) count(decision string) int {
	n := 0
	for _, e := range j.all() {
		if e.fields["STELLWERK_DECISION"] == decision {
			n++
		}
	}
	return n
}

func (j *fakeJournal) waitFor(t *testing.T, substr string) entry {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range j.all() {
			if strings.Contains(e.msg, substr) {
				return e
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("journal entry %q not found in %v", substr, j.all())
	return entry{}
}

type fakePM struct {
	mu        sync.Mutex
	calls     []string
	journalAt []int
	j         *fakeJournal
	out       []byte
	block     bool
	canceled  atomic.Bool
}

func (p *fakePM) record(ctx context.Context, call string, o pkgmgr.Output) (pkgmgr.Result, error) {
	p.mu.Lock()
	p.calls = append(p.calls, call)
	p.journalAt = append(p.journalAt, p.j.count("accepted"))
	out, block := p.out, p.block
	p.mu.Unlock()
	if len(out) > 0 {
		_, _ = o.Stdout.Write(out)
	}
	_, _ = io.WriteString(o.Stderr, "W: some warning\n")
	if block {
		<-ctx.Done()
		p.canceled.Store(true)
		return pkgmgr.Result{ExitCode: 130}, ctx.Err()
	}
	return pkgmgr.Result{}, nil
}

func (p *fakePM) getCalls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}

func (p *fakePM) Name() string { return "fake" }
func (p *fakePM) Refresh(ctx context.Context, o pkgmgr.Output) (pkgmgr.Result, error) {
	return p.record(ctx, "refresh", o)
}

func (p *fakePM) ListUpgrades(context.Context) ([]pkgmgr.Upgrade, error) {
	return []pkgmgr.Upgrade{
		{Name: "openssl", CurrentVersion: "3.0.11-1", CandidateVersion: "3.0.13-1", Arch: "amd64", IsSecurity: true, Source: "Debian-Security:12/stable-security"},
		{Name: "tzdata", CurrentVersion: "2024a", CandidateVersion: "2025b", Arch: "all"},
	}, nil
}

func (p *fakePM) Upgrade(ctx context.Context, s pkgmgr.UpgradeSpec, o pkgmgr.Output) (pkgmgr.Result, error) {
	return p.record(ctx, "upgrade "+s.Scope.String()+" "+strings.Join(s.Packages, ","), o)
}

func (p *fakePM) Install(ctx context.Context, n []string, o pkgmgr.Output) (pkgmgr.Result, error) {
	return p.record(ctx, "install "+strings.Join(n, ","), o)
}

func (p *fakePM) Remove(ctx context.Context, n []string, o pkgmgr.Output) (pkgmgr.Result, error) {
	return p.record(ctx, "remove "+strings.Join(n, ","), o)
}

func (p *fakePM) Hold(ctx context.Context, n []string, _ bool, o pkgmgr.Output) (pkgmgr.Result, error) {
	return p.record(ctx, "hold "+strings.Join(n, ","), o)
}

func (p *fakePM) RebootRequired(context.Context) (bool, []string, error) {
	return true, []string{"linux-image-6.8.0-50-generic"}, nil
}

type fakeRunner struct {
	mu    sync.Mutex
	calls []string
}

func (r *fakeRunner) Available(string) bool { return true }

func (r *fakeRunner) Run(_ context.Context, c runner.Cmd) (int, error) {
	r.mu.Lock()
	r.calls = append(r.calls, strings.Join(append([]string{c.Name}, c.Args...), " "))
	r.mu.Unlock()
	if c.Name == "sshd" && c.Stdout != nil {
		_, _ = io.WriteString(c.Stdout, "port 22\npermitrootlogin without-password\npasswordauthentication no\nmaxauthtries 6\nciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\nhostkey /etc/ssh/ssh_host_ed25519_key\nauthorizedkeysfile .ssh/authorized_keys\n")
	}
	return 0, nil
}

func (r *fakeRunner) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		return ""
	}
	return r.calls[len(r.calls)-1]
}

type testUsers struct{ ops *user.User }

func (u testUsers) Lookup(name string) (*user.User, error) {
	switch name {
	case "ops":
		return u.ops, nil
	case "root":
		return &user.User{Uid: "0", Gid: "0", Username: "root", HomeDir: "/root"}, nil
	}
	return nil, user.UnknownUserError(name)
}
func (testUsers) GroupIDs(u *user.User) ([]string, error) { return []string{u.Gid}, nil }
func (testUsers) LookupGroup(name string) (*user.Group, error) {
	return nil, user.UnknownGroupError(name)
}
func (testUsers) HasLoginShell(*user.User) bool { return true }

// --- fixture --------------------------------------------------------------

type fixture struct {
	t       *testing.T
	dir     string
	sock    string
	hostID  string
	signer  *envelope.Signer
	other   *envelope.Signer
	pm      *fakePM
	run     *fakeRunner
	journal *fakeJournal
	synced  atomic.Bool
	srv     *Server
	stop    func()
	client  *helperclient.Client
	cfgMod  func(*Config)
}

func newSigner(t *testing.T) *envelope.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := envelope.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const policyTmpl = `
require_time_sync: true
capabilities:
  metrics: true
  inventory: true
  security_checks: true
  packages: { list: true, upgrade: true, install: false, remove: false }
  services: { control: true, allow: ["*.service"], deny: ["sshd.service"] }
  reboot: true
  shell: { enabled: true, allow_root: false, allowed_users: ["ops"] }
  file_read: { allow: ["{{DIR}}/allowed/**"], deny: ["{{DIR}}/allowed/secret*", "{{DIR}}/denied/**"] }
limits:
  max_jobs_per_minute: {{RATE}}
  max_concurrent_shells: 1
  max_file_read_bytes: 1048576
`

func newFixture(t *testing.T, mod func(*Config)) *fixture {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		t: t, dir: dir, sock: filepath.Join(dir, "helper.sock"), hostID: ids.New(),
		signer: newSigner(t), other: newSigner(t), journal: &fakeJournal{}, run: &fakeRunner{}, cfgMod: mod,
	}
	f.pm = &fakePM{j: f.journal}
	f.synced.Store(true)
	for _, d := range []string{"state", "jobkeys.d", "allowed", "denied"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.writePolicy(100)
	f.write("host-id", f.hostID+"\n")
	f.write("jobkeys.d/central.pub", base64.StdEncoding.EncodeToString(f.signer.PublicKey())+"\n")
	f.write("jobkeys.d/garbage.pub", "not a key\n")
	f.write("allowed/motd", "hello from the host\n")
	f.write("allowed/secret.key", "s3cr3t")
	f.write("denied/secret", "top secret")
	f.start()
	f.client = &helperclient.Client{SocketPath: f.sock, Timeout: 10 * time.Second}
	t.Cleanup(func() { f.stop() })
	return f
}

func (f *fixture) write(name, content string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) writePolicy(rate int) {
	p := strings.ReplaceAll(policyTmpl, "{{DIR}}", f.dir)
	f.write("agent.yaml", strings.ReplaceAll(p, "{{RATE}}", strconv.Itoa(rate)))
}

func (f *fixture) config() Config {
	ops := &user.User{Uid: strconv.Itoa(os.Getuid()), Gid: strconv.Itoa(os.Getgid()), Username: "ops", HomeDir: f.dir}
	if os.Geteuid() == 0 {
		ops = &user.User{Uid: "65534", Gid: "65534", Username: "ops", HomeDir: "/"}
	}
	cfg := Config{
		PolicyPath: filepath.Join(f.dir, "agent.yaml"),
		HostIDPath: filepath.Join(f.dir, "host-id"),
		JobKeysDir: filepath.Join(f.dir, "jobkeys.d"),
		StateDir:   filepath.Join(f.dir, "state"),
		AllowedUID: os.Getuid(),
		TimeSynced: func() (bool, error) { return f.synced.Load(), nil },
		Now:        func() time.Time { return t0 },
		Runner:     f.run,
		PkgManager: f.pm,
		Journal:    f.journal,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Users:      testUsers{ops: ops},
		LoginShell: func(*user.User) (string, error) { return "/bin/sh", nil },
		Version:    "test",
		Paths: Paths{
			Shadow:  filepath.Join(f.dir, "shadow"),
			Sudoers: filepath.Join(f.dir, "sudoers"),
			Proc:    filepath.Join(f.dir, "proc"),
		},
		RequestTimeout:  time.Second,
		SkipOwnerChecks: true,
	}
	if f.cfgMod != nil {
		f.cfgMod(&cfg)
	}
	return cfg
}

func (f *fixture) start() {
	f.t.Helper()
	srv, err := NewServer(f.config())
	if err != nil {
		f.t.Fatal(err)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: f.sock, Net: "unix"})
	if err != nil {
		f.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	f.srv = srv
	var once sync.Once
	f.stop = func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				f.t.Errorf("Serve: %v", err)
			}
			_ = srv.Close()
		})
	}
}

func (f *fixture) restart() {
	f.stop()
	f.start()
}

func (f *fixture) job(action func(*agentv1.Job)) *agentv1.Job {
	nonce := make([]byte, envelope.NonceSize)
	_, _ = rand.Read(nonce)
	j := &agentv1.Job{
		JobId: ids.New(), HostId: f.hostID, Nonce: nonce, RequestedBy: "alice",
		NotBefore: t0.Add(-time.Minute).Unix(), ExpiresAt: t0.Add(9 * time.Minute).Unix(),
	}
	action(j)
	return j
}

func sign(t *testing.T, s *envelope.Signer, j *agentv1.Job) *agentv1.SignedJob {
	t.Helper()
	sj, err := s.SignJob(j)
	if err != nil {
		t.Fatal(err)
	}
	return sj
}

func (f *fixture) signed(action func(*agentv1.Job)) *agentv1.SignedJob {
	return sign(f.t, f.signer, f.job(action))
}

func (f *fixture) exec(sj *agentv1.SignedJob) (*agentv1.JobFinished, []*agentv1.JobOutput) {
	f.t.Helper()
	var outs []*agentv1.JobOutput
	fin, err := f.client.ExecuteJob(context.Background(), sj, func(o *agentv1.JobOutput) { outs = append(outs, o) }, nil)
	if err != nil {
		f.t.Fatalf("ExecuteJob: %v", err)
	}
	return fin, outs
}

// Action builders.
func upgradeAll(j *agentv1.Job) {
	j.Action = &agentv1.Job_PkgUpgrade{PkgUpgrade: &agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_ALL}}
}

func service(unit string, op agentv1.ServiceOp) func(*agentv1.Job) {
	return func(j *agentv1.Job) {
		j.Action = &agentv1.Job_Service{Service: &agentv1.ServiceAction{Unit: unit, Op: op}}
	}
}

func shellAs(name string, maxS uint32) func(*agentv1.Job) {
	return func(j *agentv1.Job) {
		j.Action = &agentv1.Job_Shell{Shell: &agentv1.ShellGrant{SessionId: ids.New(), UnixUser: name, Cols: 120, Rows: 40, MaxDurationS: maxS}}
	}
}

func fileRead(p string, max uint64) func(*agentv1.Job) {
	return func(j *agentv1.Job) {
		j.Action = &agentv1.Job_FileRead{FileRead: &agentv1.FileRead{Path: p, MaxBytes: max}}
	}
}

func joinOut(outs []*agentv1.JobOutput, stream agentv1.OutputStream) string {
	var b strings.Builder
	for _, o := range outs {
		if o.GetStream() == stream {
			b.Write(o.GetData())
		}
	}
	return b.String()
}

func wantStatus(t *testing.T, fin *agentv1.JobFinished, st agentv1.JobStatus, msg string) {
	t.Helper()
	if fin.GetStatus() != st || !strings.Contains(fin.GetMessage(), msg) {
		t.Fatalf("finished = %v %q, want %v containing %q", fin.GetStatus(), fin.GetMessage(), st, msg)
	}
}

// --- tests ----------------------------------------------------------------

func TestPing(t *testing.T) {
	f := newFixture(t, nil)
	p, err := f.client.Ping(context.Background())
	if err != nil || p.GetVersion() != "test" || p.GetHostId() != f.hostID {
		t.Fatalf("ping = %v, %v", p, err)
	}
}

func TestUpgradeStreamsOutputAndAuditsFirst(t *testing.T) {
	f := newFixture(t, nil)
	f.pm.out = bytes.Repeat([]byte("Unpacking libfoo (1.2-3) over (1.2-2) ...\n"), 2000) // ~84 KiB
	fin, outs := f.exec(f.signed(upgradeAll))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_SUCCEEDED, "")
	if got := joinOut(outs, agentv1.OutputStream_OUTPUT_STREAM_STDOUT); got != string(f.pm.out) {
		t.Fatalf("stdout mismatch: %d vs %d bytes", len(got), len(f.pm.out))
	}
	if got := joinOut(outs, agentv1.OutputStream_OUTPUT_STREAM_STDERR); got != "W: some warning\n" {
		t.Fatalf("stderr %q", got)
	}
	for _, o := range outs {
		if len(o.GetData()) > maxChunk {
			t.Fatalf("chunk of %d bytes", len(o.GetData()))
		}
	}
	if calls := f.pm.getCalls(); len(calls) != 1 || calls[0] != "upgrade UPGRADE_SCOPE_ALL " {
		t.Fatalf("calls %v", calls)
	}
	if f.pm.journalAt[0] != 1 {
		t.Fatal("job executed before the journald entry was written")
	}
	e := f.journal.all()[0]
	if e.fields["STELLWERK_ACTION"] != "pkg_upgrade" || e.fields["STELLWERK_REQUESTED_BY"] != "alice" || e.fields["STELLWERK_JOB_ID"] == "" {
		t.Fatalf("journal fields %v", e.fields)
	}
	if f.journal.count("finished") != 1 {
		t.Fatal("missing finished entry")
	}
}

func TestOutputIsCapped(t *testing.T) {
	f := newFixture(t, nil)
	f.pm.out = bytes.Repeat([]byte("x"), maxJobOutput+maxJobOutput/4)
	fin, outs := f.exec(f.signed(upgradeAll))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_SUCCEEDED, "")
	if n := len(joinOut(outs, agentv1.OutputStream_OUTPUT_STREAM_STDOUT)); n != maxJobOutput {
		t.Fatalf("stdout %d bytes, want %d", n, maxJobOutput)
	}
	if !strings.Contains(joinOut(outs, agentv1.OutputStream_OUTPUT_STREAM_INFO), "output truncated") {
		t.Fatal("missing truncation notice")
	}
}

func TestRejections(t *testing.T) {
	f := newFixture(t, nil)
	if err := os.Symlink(filepath.Join(f.dir, "denied", "secret"), filepath.Join(f.dir, "allowed", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.dir, "host-id"), filepath.Join(f.dir, "allowed", "etc-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(f.dir, "denied", "secret"), filepath.Join(f.dir, "allowed", "hardlink")); err != nil {
		t.Fatal(err)
	}
	valid := f.job(upgradeAll)
	validBytes, _ := proto.Marshal(valid)
	tests := []struct {
		name string
		sj   func() *agentv1.SignedJob
		msg  string
	}{
		{"garbage", func() *agentv1.SignedJob {
			return &agentv1.SignedJob{Job: []byte("garbage"), KeyId: "0123456789abcdef", Sig: make([]byte, 64)}
		}, "unknown signing key"},
		{"unsigned", func() *agentv1.SignedJob { return &agentv1.SignedJob{Job: validBytes} }, "malformed"},
		{"nil envelope", func() *agentv1.SignedJob { return nil }, "malformed"},
		{"bad signature", func() *agentv1.SignedJob {
			sj := f.signed(upgradeAll)
			sj.Sig[0] ^= 0xff
			return sj
		}, "invalid signature"},
		{"tampered job", func() *agentv1.SignedJob {
			sj := f.signed(upgradeAll)
			sj.Job[len(sj.Job)-1] ^= 0x01
			return sj
		}, "invalid signature"},
		{"wrong key", func() *agentv1.SignedJob { return sign(t, f.other, f.job(upgradeAll)) }, "unknown signing key"},
		{"wrong key claiming pinned id", func() *agentv1.SignedJob {
			sj := sign(t, f.other, f.job(upgradeAll))
			sj.KeyId = f.signer.KeyID()
			return sj
		}, "invalid signature"},
		{"wrong host", func() *agentv1.SignedJob {
			j := f.job(upgradeAll)
			j.HostId = ids.New()
			return sign(t, f.signer, j)
		}, "different host"},
		{"expired", func() *agentv1.SignedJob {
			j := f.job(upgradeAll)
			j.NotBefore, j.ExpiresAt = t0.Add(-20*time.Minute).Unix(), t0.Add(-10*time.Minute).Unix()
			return sign(t, f.signer, j)
		}, "expired"},
		{"not yet valid", func() *agentv1.SignedJob {
			j := f.job(upgradeAll)
			j.NotBefore, j.ExpiresAt = t0.Add(10*time.Minute).Unix(), t0.Add(15*time.Minute).Unix()
			return sign(t, f.signer, j)
		}, "not yet valid"},
		{"install disabled", func() *agentv1.SignedJob {
			return f.signed(func(j *agentv1.Job) {
				j.Action = &agentv1.Job_PkgInstall{PkgInstall: &agentv1.PkgInstall{Packages: []string{"netcat"}}}
			})
		}, "package install disabled"},
		{"remove disabled", func() *agentv1.SignedJob {
			return f.signed(func(j *agentv1.Job) {
				j.Action = &agentv1.Job_PkgRemove{PkgRemove: &agentv1.PkgRemove{Packages: []string{"auditd"}}}
			})
		}, "package remove disabled"},
		{"sshd denied", func() *agentv1.SignedJob { return f.signed(service("sshd.service", agentv1.ServiceOp_SERVICE_OP_STOP)) }, "denied by policy"},
		{"own unit protected", func() *agentv1.SignedJob {
			return f.signed(service("stellwerk-agent-helper.service", agentv1.ServiceOp_SERVICE_OP_STOP))
		}, "protected"},
		{"option injection unit", func() *agentv1.SignedJob {
			return f.signed(service("--root=/tmp.service", agentv1.ServiceOp_SERVICE_OP_START))
		}, "invalid unit name"},
		{"root shell denied", func() *agentv1.SignedJob { return f.signed(shellAs("root", 60)) }, "root shell not allowed"},
		{"unknown shell user", func() *agentv1.SignedJob { return f.signed(shellAs("mallory", 60)) }, "unknown unix user"},
		{"run_check not helper", func() *agentv1.SignedJob {
			return f.signed(func(j *agentv1.Job) { j.Action = &agentv1.Job_RunCheck{RunCheck: &agentv1.RunCheck{}} })
		}, "not a helper action"},
		{"collect_inventory not helper", func() *agentv1.SignedJob {
			return f.signed(func(j *agentv1.Job) {
				j.Action = &agentv1.Job_CollectInventory{CollectInventory: &agentv1.CollectInventory{}}
			})
		}, "not a helper action"},
		{"probe_config not helper", func() *agentv1.SignedJob {
			return f.signed(func(j *agentv1.Job) { j.Action = &agentv1.Job_ProbeConfig{ProbeConfig: &agentv1.ProbeConfig{}} })
		}, "not a helper action"},
		{"script not implemented", func() *agentv1.SignedJob {
			return f.signed(func(j *agentv1.Job) { j.Action = &agentv1.Job_Script{Script: &agentv1.RunScript{ScriptId: "x"}} })
		}, "not implemented"},
		{"agent_update not implemented", func() *agentv1.SignedJob {
			return f.signed(func(j *agentv1.Job) {
				j.Action = &agentv1.Job_AgentUpdate{AgentUpdate: &agentv1.AgentUpdate{Version: "v9"}}
			})
		}, "not implemented"},
		{"file_read denied path", func() *agentv1.SignedJob { return f.signed(fileRead(filepath.Join(f.dir, "denied", "secret"), 0)) }, `denied/secret" denied by policy`},
		{"file_read deny pattern", func() *agentv1.SignedJob { return f.signed(fileRead(filepath.Join(f.dir, "allowed", "secret.key"), 0)) }, "denied by policy"},
		{"file_read unclean path", func() *agentv1.SignedJob {
			return f.signed(fileRead(f.dir+"/allowed/../denied/secret", 0))
		}, "invalid path"},
		{"file_read symlink into denied", func() *agentv1.SignedJob { return f.signed(fileRead(filepath.Join(f.dir, "allowed", "link"), 0)) }, `denied/secret" denied by policy`},
		{"file_read symlink outside allow list", func() *agentv1.SignedJob { return f.signed(fileRead(filepath.Join(f.dir, "allowed", "etc-link"), 0)) }, "not in allow list"},
		{"file_read hardlink alias", func() *agentv1.SignedJob { return f.signed(fileRead(filepath.Join(f.dir, "allowed", "hardlink"), 0)) }, "hard links"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := len(f.journal.all())
			fin, outs := f.exec(tc.sj())
			wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_REJECTED, tc.msg)
			if s := joinOut(outs, agentv1.OutputStream_OUTPUT_STREAM_STDOUT); strings.Contains(s, "secret") {
				t.Fatalf("leaked content %q", s)
			}
			if len(f.journal.all()) == before {
				t.Fatal("rejection not journaled")
			}
		})
	}
	if calls := f.pm.getCalls(); len(calls) != 0 {
		t.Fatalf("package manager called: %v", calls)
	}
	if last := f.run.last(); last != "" {
		t.Fatalf("runner called: %s", last)
	}
}

func TestReplayRejectedAlsoAfterRestart(t *testing.T) {
	f := newFixture(t, nil)
	sj := f.signed(upgradeAll)
	fin, _ := f.exec(sj)
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_SUCCEEDED, "")
	fin, _ = f.exec(sj)
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_REJECTED, "replayed")
	f.restart()
	fin, _ = f.exec(sj)
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_REJECTED, "replayed")
	if n := len(f.pm.getCalls()); n != 1 {
		t.Fatalf("executed %d times", n)
	}
}

func TestRateLimit(t *testing.T) {
	f := newFixture(t, nil)
	f.writePolicy(2)
	for range 2 {
		fin, _ := f.exec(f.signed(upgradeAll))
		wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_SUCCEEDED, "")
	}
	fin, _ := f.exec(f.signed(upgradeAll))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_REJECTED, "rate limit")
}

func TestTimeNotSynced(t *testing.T) {
	f := newFixture(t, nil)
	f.synced.Store(false)
	sj := f.signed(upgradeAll)
	fin, _ := f.exec(sj)
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_REJECTED, "clock not synchronized")
	// The nonce was not consumed: once the clock is synced the job runs.
	f.synced.Store(true)
	fin, _ = f.exec(sj)
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_SUCCEEDED, "")

	f2 := newFixture(t, func(c *Config) { c.TimeSynced = nil })
	fin, _ = f2.exec(f2.signed(upgradeAll))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_REJECTED, "clock not synchronized")
}

func TestJournalFailureRefusesJob(t *testing.T) {
	f := newFixture(t, nil)
	f.journal.fail.Store(true)
	fin, _ := f.exec(f.signed(upgradeAll))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_REJECTED, "audit log unavailable")
	if len(f.pm.getCalls()) != 0 {
		t.Fatal("job executed without audit entry")
	}
}

func TestMissingTrustAnchorsRejectJobs(t *testing.T) {
	tests := []struct {
		name    string
		breakIt func(f *fixture)
		msg     string
	}{
		{"no policy", func(f *fixture) { _ = os.Remove(filepath.Join(f.dir, "agent.yaml")) }, "local policy unavailable"},
		{"bad policy", func(f *fixture) { f.write("agent.yaml", "capabilities: {packagez: {}}\n") }, "local policy unavailable"},
		{"no host id", func(f *fixture) { _ = os.Remove(filepath.Join(f.dir, "host-id")) }, "host identity unavailable"},
		{"bad host id", func(f *fixture) { f.write("host-id", "not-a-uuid\n") }, "host identity invalid"},
		{"no keys", func(f *fixture) { _ = os.Remove(filepath.Join(f.dir, "jobkeys.d", "central.pub")) }, "no valid key"},
		{"symlinked key", func(f *fixture) {
			p := filepath.Join(f.dir, "jobkeys.d", "central.pub")
			_ = os.Rename(p, filepath.Join(f.dir, "central.pub"))
			_ = os.Symlink(filepath.Join(f.dir, "central.pub"), p)
		}, "no valid key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			tc.breakIt(f)
			fin, _ := f.exec(f.signed(upgradeAll))
			wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_REJECTED, tc.msg)
		})
	}
}

func TestOwnerChecksEnabledByDefault(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create root-owned files")
	}
	f := newFixture(t, func(c *Config) { c.SkipOwnerChecks = false })
	if err := os.Chmod(filepath.Join(f.dir, "agent.yaml"), 0o664); err != nil {
		t.Fatal(err)
	}
	fin, _ := f.exec(f.signed(upgradeAll))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_REJECTED, "insecure permissions")
	if err := os.Chmod(filepath.Join(f.dir, "agent.yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	fin, _ = f.exec(f.signed(upgradeAll))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_SUCCEEDED, "")
	if err := os.Chmod(filepath.Join(f.dir, "jobkeys.d", "central.pub"), 0o666); err != nil {
		t.Fatal(err)
	}
	fin, _ = f.exec(f.signed(upgradeAll))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_REJECTED, "no valid key")

	// A state dir readable by others is refused at startup.
	if err := os.Chmod(filepath.Join(f.dir, "state"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(f.config()); err == nil {
		t.Fatal("insecure state dir accepted")
	}
}

func TestServiceAndRebootArgv(t *testing.T) {
	f := newFixture(t, nil)
	fin, _ := f.exec(f.signed(service("nginx.service", agentv1.ServiceOp_SERVICE_OP_RESTART)))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_SUCCEEDED, "")
	if got := f.run.last(); got != "systemctl --no-ask-password restart -- nginx.service" {
		t.Fatalf("argv %q", got)
	}
	fin, _ = f.exec(f.signed(func(j *agentv1.Job) {
		j.Action = &agentv1.Job_Reboot{Reboot: &agentv1.Reboot{DelayS: 90, Message: "-c\nkernel \x1b[2Jupdate"}}
	}))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_SUCCEEDED, "")
	if got := f.run.last(); got != "shutdown -r -- +2 Stellwerk: reboot requested by alice: -ckernel [2Jupdate" {
		t.Fatalf("argv %q", got)
	}
	fin, _ = f.exec(f.signed(func(j *agentv1.Job) { j.Action = &agentv1.Job_Reboot{Reboot: &agentv1.Reboot{}} }))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_SUCCEEDED, "")
	if got := f.run.last(); got != "shutdown -r -- now Stellwerk: reboot requested by alice" {
		t.Fatalf("argv %q", got)
	}
	fin, _ = f.exec(f.signed(func(j *agentv1.Job) { j.Action = &agentv1.Job_Reboot{Reboot: &agentv1.Reboot{DelayS: 3601}} }))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_REJECTED, "invalid reboot parameters")
}

func TestCancelStopsJob(t *testing.T) {
	f := newFixture(t, nil)
	f.pm.block = true
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := f.client.ExecuteJob(ctx, f.signed(upgradeAll), nil, nil)
		errc <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for len(f.pm.getCalls()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("client err = %v", err)
	}
	e := f.journal.waitFor(t, "finished: JOB_STATUS_CANCELED")
	if e.fields["STELLWERK_STATUS"] != "JOB_STATUS_CANCELED" || !f.pm.canceled.Load() {
		t.Fatalf("job not canceled: %v", e)
	}
}

func TestFileRead(t *testing.T) {
	f := newFixture(t, nil)
	fin, outs := f.exec(f.signed(fileRead(filepath.Join(f.dir, "allowed", "motd"), 0)))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_SUCCEEDED, "")
	if got := joinOut(outs, agentv1.OutputStream_OUTPUT_STREAM_STDOUT); got != "hello from the host\n" {
		t.Fatalf("content %q", got)
	}
	fin, outs = f.exec(f.signed(fileRead(filepath.Join(f.dir, "allowed", "motd"), 5)))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_SUCCEEDED, "")
	if got := joinOut(outs, agentv1.OutputStream_OUTPUT_STREAM_STDOUT); got != "hello" ||
		!strings.Contains(joinOut(outs, agentv1.OutputStream_OUTPUT_STREAM_INFO), "truncated") {
		t.Fatalf("truncated read %q", got)
	}
	// Symlink staying inside the allow list is fine (resolved path checked).
	if err := os.Symlink("motd", filepath.Join(f.dir, "allowed", "motd-link")); err != nil {
		t.Fatal(err)
	}
	fin, outs = f.exec(f.signed(fileRead(filepath.Join(f.dir, "allowed", "motd-link"), 0)))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_SUCCEEDED, "")
	if got := joinOut(outs, agentv1.OutputStream_OUTPUT_STREAM_STDOUT); got != "hello from the host\n" {
		t.Fatalf("content %q", got)
	}
	// Directories and FIFOs are refused (and the FIFO must not block).
	fin, _ = f.exec(f.signed(fileRead(filepath.Join(f.dir, "allowed"), 0)))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_FAILED, "not a regular file")
	if err := unix.Mkfifo(filepath.Join(f.dir, "allowed", "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	fin, _ = f.exec(f.signed(fileRead(filepath.Join(f.dir, "allowed", "fifo"), 0)))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_FAILED, "not a regular file")
	fin, _ = f.exec(f.signed(fileRead(filepath.Join(f.dir, "allowed", "missing"), 0)))
	wantStatus(t, fin, agentv1.JobStatus_JOB_STATUS_FAILED, "cannot resolve")
}

func TestOpenNoFollowRefusesSymlinkComponents(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "real", "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	// A directory component swapped for a symlink after EvalSymlinks.
	if f, err := openNoFollow(filepath.Join(dir, "link", "f")); err == nil {
		f.Close()
		t.Fatal("symlinked directory component was followed")
	}
	f, err := openNoFollow(filepath.Join(dir, "real", "f"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestListUpgrades(t *testing.T) {
	f := newFixture(t, nil)
	rep, err := f.client.ListUpgrades(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.GetManager() != "fake" || len(rep.GetUpdates()) != 2 || !rep.GetUpdates()[0].GetIsSecurity() ||
		!rep.GetRebootRequired() || rep.GetRebootReasons()[0] != "linux-image-6.8.0-50-generic" || rep.GetCheckedAtMs() != t0.UnixMilli() {
		t.Fatalf("report %v", rep)
	}
	f.write("agent.yaml", "capabilities: { packages: { list: false } }\n")
	if _, err := f.client.ListUpgrades(context.Background()); !errors.Is(err, helperclient.ErrHelper) || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("err = %v", err)
	}
}

func TestReadPrivileged(t *testing.T) {
	f := newFixture(t, nil)
	f.write("shadow", strings.Join([]string{
		"root:$y$j9T$abcdefgh$HASHROOTHASHROOTHASHROOT:19700:0:99999:7:::",
		"daemon:*:19700:0:99999:7:::",
		"ops:$6$saltsalt$HASHOPSHASHOPSHASHOPS:19700:0:99999:7:::",
		"locked:!$6$salt$HASHLOCKEDHASHLOCKED:19700::::::",
		"nopw::19700:0:99999:7:::",
		"rhel:!!:19700::::::",
		"bad name:x:1::::::",
		"",
	}, "\n"))
	if err := os.MkdirAll(filepath.Join(f.dir, "sudoers.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.write("sudoers", "#\n# This file MUST be edited with the 'visudo' command as root.\nDefaults\tenv_reset\nDefaults:%sudo !lecture\n"+
		"root\tALL=(ALL:ALL) ALL\n%admin ALL=(ALL) ALL   # trailing comment\nCmnd_Alias PKG = /usr/bin/apt-get, \\\n                 /usr/bin/dpkg\n"+
		"#1001 ALL=(ALL) NOPASSWD: PKG\n@includedir sudoers.d\n#include extra\n")
	f.write("sudoers.d/ops", "ops ALL=(ALL) NOPASSWD: ALL\n")
	f.write("sudoers.d/README", "# comments only\n")
	f.write("sudoers.d/old~", "evil ALL=(ALL) ALL\n")
	f.write("sudoers.d/x.disabled", "evil ALL=(ALL) ALL\n")
	f.write("extra", "deploy ALL=(root) /usr/bin/systemctl restart app.service\n#include extra\n")

	ctx := context.Background()
	d, err := f.client.ReadPrivileged(ctx, helperv1.PrivilegedKind_PRIVILEGED_KIND_SHADOW_FLAGS)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.GetEmptyPasswordUsers(), ",") != "nopw" || strings.Join(d.GetLockedUsers(), ",") != "daemon,locked,rhel" {
		t.Fatalf("shadow flags %v", d)
	}
	raw, _ := proto.Marshal(d)
	for _, leak := range []string{"HASH", "$6$", "$y$", "salt"} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Fatalf("shadow response leaks %q", leak)
		}
	}

	d, err = f.client.ReadPrivileged(ctx, helperv1.PrivilegedKind_PRIVILEGED_KIND_SUDOERS)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"root ALL=(ALL:ALL) ALL", "%admin ALL=(ALL) ALL", "Cmnd_Alias PKG = /usr/bin/apt-get, /usr/bin/dpkg",
		"#1001 ALL=(ALL) NOPASSWD: PKG", "ops ALL=(ALL) NOPASSWD: ALL", "deploy ALL=(root) /usr/bin/systemctl restart app.service",
	}
	if got := d.GetSudoRules(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("sudo rules\n got %q\nwant %q", got, want)
	}

	d, err = f.client.ReadPrivileged(ctx, helperv1.PrivilegedKind_PRIVILEGED_KIND_SSHD_EFFECTIVE_CONFIG)
	if err != nil {
		t.Fatal(err)
	}
	if v := d.GetValues(); len(v) != 4 || v["permitrootlogin"] != "without-password" || v["ciphers"] == "" || v["hostkey"] != "" {
		t.Fatalf("sshd values %v", v)
	}
	if got := f.run.last(); got != "sshd -T" {
		t.Fatalf("argv %q", got)
	}

	f.write("agent.yaml", "capabilities: { security_checks: false, inventory: false }\n")
	if _, err := f.client.ReadPrivileged(ctx, helperv1.PrivilegedKind_PRIVILEGED_KIND_SHADOW_FLAGS); !errors.Is(err, helperclient.ErrHelper) {
		t.Fatalf("err = %v", err)
	}
}

func TestSocketOwners(t *testing.T) {
	dir := t.TempDir()
	mk := func(p, content string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := func(p, target string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, p)); err != nil {
			t.Fatal(err)
		}
	}
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	mk("net/tcp", hdr+
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"+
		"   1: 0100007F:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0\n"+
		"   2: 0100007F:9C40 0100007F:0016 01 00000000:00000000 00:00000000 00000000  1000        0 999 1 0000000000000000 20 4 30 10 -1\n")
	mk("net/tcp6", hdr+
		"   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0\n")
	mk("net/udp", hdr+
		"  100: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 12348 2 0000000000000000 0\n")
	mk("812/comm", "sshd\n")
	link("812/fd/3", "socket:[12345]")
	link("812/fd/4", "socket:[12347]")
	link("812/fd/5", "/dev/null")
	mk("900/comm", "master\n")
	link("900/fd/7", "socket:[12346]")
	mk("901/comm", "systemd-resolve\n")
	link("901/fd/9", "socket:[12348]")
	link("902/fd/1", "socket:[999]")
	mk("self/comm", "x\n")

	got, err := socketOwners(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"12345": "812/sshd",
		"12346": "900/master",
		"12347": "812/sshd",
		"12348": "901/systemd-resolve",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestOversizeAndTruncatedFrames(t *testing.T) {
	f := newFixture(t, nil)
	for _, payload := range [][]byte{
		{0xff, 0xff, 0xff, 0xff},                   // header far above MaxFrame
		{0x00, 0x10, 0x00, 0x01},                   // MaxFrame + 1
		{0x00, 0x00, 0x00, 0x64, 0x01, 0x02, 0x03}, // truncated: waits for RequestTimeout
		{0x00, 0x00, 0x00, 0x03, 0xff, 0xff, 0xff}, // not protobuf
	} {
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: f.sock, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(payload); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		var resp helperv1.HelperResponse
		if err := framing.Read(c, &resp); err != nil || !strings.Contains(resp.GetError().GetMessage(), "invalid request") {
			t.Fatalf("payload %x: resp %v err %v", payload, &resp, err)
		}
		c.Close()
	}
	// The server keeps serving.
	if _, err := f.client.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestUnauthorizedPeerIsDropped(t *testing.T) {
	if os.Geteuid() != 0 {
		// Not root: only our own uid could connect; pretend it is not the agent's.
		f := newFixture(t, func(c *Config) { c.AllowedUID = os.Getuid() + 1 })
		if _, err := f.client.Ping(context.Background()); err == nil {
			t.Fatal("unauthorized uid was served")
		}
		return
	}
	// Root: connect from a thread whose effective uid is 65534. SO_PEERCRED
	// records the connecting thread's credentials.
	base, err := os.MkdirTemp("", "helper-peercred-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, func(c *Config) { c.AllowedUID = 4242 })
	sock := filepath.Join(base, "h.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sock, 0o666); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.srv.Serve(ctx, ln) }()
	defer func() { cancel(); <-done }()

	dial := func(euid int) (*net.UnixConn, error) {
		res := make(chan any, 1)
		go func() {
			runtime.LockOSThread() // never unlocked if restoring fails: the thread then dies with the goroutine
			if _, _, e := syscall.RawSyscall(syscall.SYS_SETRESUID, ^uintptr(0), uintptr(euid), ^uintptr(0)); e != 0 {
				res <- error(e)
				return
			}
			c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
			if _, _, e := syscall.RawSyscall(syscall.SYS_SETRESUID, ^uintptr(0), 0, ^uintptr(0)); e != 0 {
				res <- error(e)
				return
			}
			runtime.UnlockOSThread()
			if err != nil {
				res <- err
				return
			}
			res <- c
		}()
		switch v := (<-res).(type) {
		case *net.UnixConn:
			return v, nil
		case error:
			return nil, v
		}
		return nil, errors.New("unreachable")
	}
	ping := func(c *net.UnixConn) error {
		defer c.Close()
		if err := framing.Write(c, &helperv1.HelperRequest{Call: &helperv1.HelperRequest_Ping{Ping: &helperv1.PingRequest{}}}); err != nil {
			return err
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		var resp helperv1.HelperResponse
		return framing.Read(c, &resp)
	}
	c, err := dial(65534)
	if err != nil {
		t.Skip("cannot switch thread euid:", err)
	}
	if err := ping(c); err == nil {
		t.Fatal("uid 65534 was served")
	}
	c, err = dial(4242)
	if err != nil {
		t.Fatal(err)
	}
	if err := ping(c); err != nil {
		t.Fatalf("allowed uid refused: %v", err)
	}
}

// --- shell ------------------------------------------------------------------

func requirePTY(t *testing.T) {
	t.Helper()
	m, s, err := openPTY()
	if err != nil {
		t.Skip("PTYs unavailable:", err)
	}
	m.Close()
	s.Close()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
}

type shellRun struct {
	master *os.File
	pid    int32
	fin    chan *agentv1.JobFinished
	err    chan error
	out    *syncBuf
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func (f *fixture) startShell(ctx context.Context, sj *agentv1.SignedJob) (*shellRun, *agentv1.JobFinished) {
	f.t.Helper()
	r := &shellRun{fin: make(chan *agentv1.JobFinished, 1), err: make(chan error, 1), out: &syncBuf{}}
	started := make(chan struct{})
	go func() {
		fin, err := f.client.ExecuteJob(ctx, sj, nil, func(m *os.File, pid int32) {
			r.master, r.pid = m, pid
			go func() { _, _ = io.Copy(r.out, m) }()
			close(started)
		})
		r.fin <- fin
		r.err <- err
	}()
	select {
	case <-started:
		f.t.Cleanup(func() { r.master.Close() })
		return r, nil
	case fin := <-r.fin:
		if err := <-r.err; err != nil {
			f.t.Fatalf("ExecuteJob: %v", err)
		}
		return nil, fin
	case <-time.After(15 * time.Second):
		f.t.Fatal("shell did not start")
	}
	return nil, nil
}

func (r *shellRun) waitOutput(t *testing.T, substr string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(r.out.String(), substr) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("output %q does not contain %q", r.out.String(), substr)
}

func TestShellSpawnsOnPTY(t *testing.T) {
	requirePTY(t)
	f := newFixture(t, nil)
	r, fin := f.startShell(context.Background(), f.signed(shellAs("ops", 60)))
	if r == nil {
		t.Fatalf("shell not started: %v", fin)
	}
	if r.pid <= 0 {
		t.Fatalf("pid %d", r.pid)
	}
	wantUID := strconv.Itoa(os.Getuid())
	if os.Geteuid() == 0 {
		wantUID = "65534"
	}
	if _, err := io.WriteString(r.master, "echo hi-$((40+2)) uid=$(id -u) term=$TERM; exit 3\n"); err != nil {
		t.Fatal(err)
	}
	r.waitOutput(t, "hi-42 uid="+wantUID+" term=xterm-256color")
	select {
	case fin := <-r.fin:
		if err := <-r.err; err != nil {
			t.Fatal(err)
		}
		if fin.GetStatus() != agentv1.JobStatus_JOB_STATUS_FAILED || fin.GetExitCode() != 3 {
			t.Fatalf("finished %v", fin)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("shell did not finish")
	}
	f.journal.waitFor(t, "shell opened for \"alice\" as ops")
	f.journal.waitFor(t, "shell closed for \"alice\" as ops")
}

func TestShellLimits(t *testing.T) {
	requirePTY(t)
	f := newFixture(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, fin := f.startShell(ctx, f.signed(shellAs("ops", 600)))
	if r == nil {
		t.Fatalf("shell not started: %v", fin)
	}
	// max_concurrent_shells: 1
	if r2, fin := f.startShell(context.Background(), f.signed(shellAs("ops", 600))); r2 != nil || !strings.Contains(fin.GetMessage(), "too many concurrent shells") {
		t.Fatalf("second shell: %v", fin)
	}
	// Closing the connection (kill switch) hangs up the shell.
	cancel()
	if err := <-r.err; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	// The "finished" entry is written after the shell slot was released.
	e := f.journal.waitFor(t, "finished: JOB_STATUS_CANCELED")
	if e.fields["STELLWERK_ACTION"] != "shell" {
		t.Fatalf("entry %v", e)
	}
	if err := unix.Kill(int(r.pid), 0); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("shell %d still alive: %v", r.pid, err)
	}
	// The slot was released; max_duration_s is enforced.
	r3, fin := f.startShell(context.Background(), f.signed(shellAs("ops", 1)))
	if r3 == nil {
		t.Fatalf("third shell: %v", fin)
	}
	select {
	case fin := <-r3.fin:
		if fin.GetStatus() != agentv1.JobStatus_JOB_STATUS_TIMED_OUT {
			t.Fatalf("finished %v", fin)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("max duration not enforced")
	}
}
