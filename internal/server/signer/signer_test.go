package signer

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nobrain-soft/libremanager/internal/common/envelope"
	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/secretbox"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	centralv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/central/v1"
)

func newService(t *testing.T) (*Service, string, envelope.KeyRing) {
	t.Helper()
	dir := t.TempDir()
	mk, _ := secretbox.NewKey()
	keyPath := filepath.Join(dir, "jobkey.sealed")
	pub, err := GenerateKeyFile(mk, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	s, err := LoadKeyFile(mk, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := secretbox.NewKey()
	if _, err := LoadKeyFile(other, keyPath); err == nil {
		t.Fatal("key opened with wrong master key")
	}
	logPath := filepath.Join(dir, "sig.log")
	svc, err := NewService(s, logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	ring := envelope.KeyRing{}
	if _, err := ring.Add(pub); err != nil {
		t.Fatal(err)
	}
	return svc, logPath, ring
}

func tmpl(action any) *agentv1.Job {
	j := &agentv1.Job{JobId: ids.New(), RequestedBy: "alice"}
	switch a := action.(type) {
	case *agentv1.PkgUpgrade:
		j.Action = &agentv1.Job_PkgUpgrade{PkgUpgrade: a}
	case *agentv1.ServiceAction:
		j.Action = &agentv1.Job_Service{Service: a}
	case *agentv1.ShellGrant:
		j.Action = &agentv1.Job_Shell{Shell: a}
	case *agentv1.RunScript:
		j.Action = &agentv1.Job_Script{Script: a}
	case *agentv1.RunCheck:
		j.Action = &agentv1.Job_RunCheck{RunCheck: a}
	}
	return j
}

func TestSignJobsProducesVerifiableEnvelopes(t *testing.T) {
	svc, logPath, ring := newService(t)
	h1, h2 := ids.New(), ids.New()
	resp, err := svc.SignJobs(context.Background(), &centralv1.SignJobsRequest{
		Template: tmpl(&agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY}),
		HostIds:  []string{h1, h2},
		TtlS:     99999, // capped
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetEnvelopes()) != 2 {
		t.Fatalf("got %d envelopes", len(resp.GetEnvelopes()))
	}
	nonces := map[string]bool{}
	for _, e := range resp.GetEnvelopes() {
		v := &envelope.Verifier{Keys: ring, HostID: e.GetHostId(), Nonces: envelope.NewMemoryNonceStore(nil)}
		job, err := v.Verify(e.GetSigned())
		if err != nil {
			t.Fatalf("verify %s: %v", e.GetHostId(), err)
		}
		if time.Duration(job.GetExpiresAt()-job.GetNotBefore())*time.Second > MaxTTL {
			t.Fatal("ttl not capped")
		}
		nonces[string(job.GetNonce())] = true
		// Envelope for h1 must not verify on h2.
		other := h1
		if e.GetHostId() == h1 {
			other = h2
		}
		v2 := &envelope.Verifier{Keys: ring, HostID: other, Nonces: envelope.NewMemoryNonceStore(nil)}
		if _, err := v2.Verify(e.GetSigned()); err == nil {
			t.Fatal("envelope verified for another host")
		}
	}
	if len(nonces) != 2 {
		t.Fatal("nonces not unique per envelope")
	}
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if !strings.Contains(sc.Text(), `"action":"pkg_upgrade"`) {
			t.Fatalf("bad log line %s", sc.Text())
		}
		n++
	}
	if n != 2 {
		t.Fatalf("signature log has %d lines", n)
	}
}

func TestSignJobsRejects(t *testing.T) {
	svc, _, _ := newService(t)
	host := ids.New()
	cases := map[string]*centralv1.SignJobsRequest{
		"no template":     {HostIds: []string{host}},
		"no hosts":        {Template: tmpl(&agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_ALL})},
		"bad host":        {Template: tmpl(&agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_ALL}), HostIds: []string{"x"}},
		"duplicate host":  {Template: tmpl(&agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_ALL}), HostIds: []string{host, host}},
		"bad package":     {Template: tmpl(&agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_NAMED, Packages: []string{"-oX=1"}}), HostIds: []string{host}},
		"bad unit":        {Template: tmpl(&agentv1.ServiceAction{Unit: "x;reboot", Op: agentv1.ServiceOp_SERVICE_OP_RESTART}), HostIds: []string{host}},
		"script disabled": {Template: tmpl(&agentv1.RunScript{}), HostIds: []string{host}},
		"bad check id":    {Template: tmpl(&agentv1.RunCheck{CheckIds: []string{"../x"}}), HostIds: []string{host}},
		"shell multi host": {Template: tmpl(&agentv1.ShellGrant{SessionId: ids.New(), UnixUser: "ops", MaxDurationS: 60}),
			HostIds: []string{host, ids.New()}},
		"far future": {Template: tmpl(&agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_ALL}), HostIds: []string{host},
			NotBefore: time.Now().Add(48 * time.Hour).Unix()},
	}
	for name, req := range cases {
		if _, err := svc.SignJobs(context.Background(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err = %v, want InvalidArgument", name, err)
		}
	}
}

func TestRateLimit(t *testing.T) {
	svc, _, _ := newService(t)
	svc.UserPerMin = 3
	req := func() error {
		_, err := svc.SignJobs(context.Background(), &centralv1.SignJobsRequest{
			Template: tmpl(&agentv1.PkgUpgrade{Scope: agentv1.UpgradeScope_UPGRADE_SCOPE_ALL}),
			HostIds:  []string{ids.New(), ids.New()},
		})
		return err
	}
	if err := req(); err != nil {
		t.Fatal(err)
	}
	if err := req(); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("err = %v, want ResourceExhausted", err)
	}
}

func TestShellTTLCapped(t *testing.T) {
	svc, _, ring := newService(t)
	host := ids.New()
	resp, err := svc.SignJobs(context.Background(), &centralv1.SignJobsRequest{
		Template: tmpl(&agentv1.ShellGrant{SessionId: ids.New(), UnixUser: "ops", MaxDurationS: 3600}),
		HostIds:  []string{host}, TtlS: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	v := &envelope.Verifier{Keys: ring, HostID: host, Nonces: envelope.NewMemoryNonceStore(nil)}
	job, err := v.Verify(resp.GetEnvelopes()[0].GetSigned())
	if err != nil {
		t.Fatal(err)
	}
	if job.GetExpiresAt()-job.GetNotBefore() > int64(ShellMaxTTL.Seconds()) {
		t.Fatal("shell grant ttl not capped")
	}
}

func TestServeOverUnixSocket(t *testing.T) {
	svc, _, _ := newService(t)
	sock := filepath.Join(t.TempDir(), "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, svc, sock) }()
	var client centralv1.SignerServiceClient
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket not created")
		}
		time.Sleep(20 * time.Millisecond)
	}
	client, cc, err := Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	keys, err := client.ListKeys(ctx, &centralv1.ListKeysRequest{})
	if err != nil || len(keys.GetKeys()) != 1 {
		t.Fatalf("ListKeys: %v %v", keys, err)
	}
	st, _ := os.Stat(sock)
	if st.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v", st.Mode().Perm())
	}
}
