package gateway_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/snappy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nobrain-soft/libremanager/internal/common/envelope"
	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/pki"
	"github.com/nobrain-soft/libremanager/internal/pki/testpki"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/auth"
	"github.com/nobrain-soft/libremanager/internal/server/gateway"
	"github.com/nobrain-soft/libremanager/internal/server/gateway/remotewrite"
	"github.com/nobrain-soft/libremanager/internal/server/store"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
	"github.com/nobrain-soft/libremanager/internal/server/store/storetest"
)

type env struct {
	t      *testing.T
	st     *store.Store
	pki    *testpki.PKI
	gw     *gateway.Gateway
	addr   string
	pepper auth.Pepper
	signer *envelope.Signer
	rw     chan []byte
	ctx    context.Context
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := storetest.New(t)
	p := testpki.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rw := make(chan []byte, 100)
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		raw, _ := snappy.Decode(nil, b)
		rw <- raw
		w.WriteHeader(204)
	}))
	t.Cleanup(vm.Close)
	writer := remotewrite.New(vm.URL)
	writer.FlushInterval = 50 * time.Millisecond
	pepper := auth.Pepper(make([]byte, 32))
	gw, err := gateway.New(gateway.Config{
		Store: st, Audit: audit.New(st), CA: p.Intermediate, Roots: p.Roots,
		ServerNames: []string{"localhost"}, ServerIPs: []net.IP{net.ParseIP("127.0.0.1")},
		Pepper: pepper, RemoteWrite: writer,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gw.Serve(ctx, ln) }()
	go gw.RunBackground(ctx)

	_, priv, _ := newKey(t)
	signer, _ := envelope.NewSigner(priv)
	if err := st.Q.UpsertJobSigningKey(ctx, db.UpsertJobSigningKeyParams{KeyID: signer.KeyID(), PublicKey: signer.PublicKey()}); err != nil {
		t.Fatal(err)
	}
	return &env{t: t, st: st, pki: p, gw: gw, addr: ln.Addr().String(), pepper: pepper, signer: signer, rw: rw, ctx: ctx}
}

func (e *env) token(maxUses int32) string {
	e.t.Helper()
	tok, err := auth.RandomToken(auth.PrefixEnrollment)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.st.Q.CreateEnrollmentToken(e.ctx, db.CreateEnrollmentTokenParams{
		ID: ids.NewUUID(), TokenHash: e.pepper.HashToken(tok), Labels: json.RawMessage(`{"env":"test"}`),
		MaxUses: maxUses, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (e *env) client(cert *tls.Certificate) agentv1.GatewayServiceClient {
	e.t.Helper()
	cc, err := grpc.NewClient(e.addr, grpc.WithTransportCredentials(credentials.NewTLS(e.pki.ClientTLS(cert))))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = cc.Close() })
	return agentv1.NewGatewayServiceClient(cc)
}

// enroll performs a real enrollment and returns the host id and TLS cert.
func (e *env) enroll(tok string) (string, tls.Certificate) {
	e.t.Helper()
	key, _ := pki.GenerateKey()
	csr, _ := pki.NewCSR(key, "agent")
	resp, err := e.client(nil).Enroll(e.ctx, &agentv1.EnrollRequest{Token: tok, CsrDer: csr,
		Facts: &agentv1.HostFacts{Hostname: "web1", OsId: "debian", OsVersion: "12", AgentVersion: "test"}})
	if err != nil {
		e.t.Fatalf("enroll: %v", err)
	}
	tc, err := pki.TLSCertificate(resp.GetCertChainDer(), key)
	if err != nil {
		e.t.Fatal(err)
	}
	if len(resp.GetJobKeys()) != 1 || resp.GetJobKeys()[0].GetKeyId() != e.signer.KeyID() {
		e.t.Fatalf("job keys not delivered: %v", resp.GetJobKeys())
	}
	return resp.GetHostId(), tc
}

func TestEnrollConnectIngest(t *testing.T) {
	e := newEnv(t)
	tok := e.token(1)
	hostID, cert := e.enroll(tok)

	// Token was single-use.
	key, _ := pki.GenerateKey()
	csr, _ := pki.NewCSR(key, "x")
	if _, err := e.client(nil).Enroll(e.ctx, &agentv1.EnrollRequest{Token: tok, CsrDer: csr}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("reused token: %v", err)
	}

	c := e.client(&cert)
	stream, err := c.Connect(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Hello{Hello: &agentv1.Hello{
		AgentVersion: "test", Facts: &agentv1.HostFacts{Hostname: "web1", OsFamily: "debian"}}}}); err != nil {
		t.Fatal(err)
	}
	welcome, err := stream.Recv()
	if err != nil || welcome.GetWelcome().GetHostId() != hostID {
		t.Fatalf("welcome: %v %v", welcome, err)
	}

	// Metrics with a forged host_id label: gateway must replace it.
	if err := stream.Send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Metrics{Metrics: &agentv1.MetricsBatch{
		TimestampMs: time.Now().UnixMilli(),
		Defs: []*agentv1.SeriesDef{
			{Id: 1, Name: "stellwerk_load1", Labels: []*agentv1.Label{{Name: "host_id", Value: "forged"}}},
			{Id: 2, Name: "evil_metric"},
		},
		Points: []*agentv1.Point{{SeriesId: 1, Value: 0.5}, {SeriesId: 2, Value: 1}},
	}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case raw := <-e.rw:
		s := string(raw)
		if !strings.Contains(s, "stellwerk_load1") || !strings.Contains(s, hostID) || strings.Contains(s, "forged") || strings.Contains(s, "evil_metric") {
			t.Fatalf("remote write content unexpected: %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no remote write")
	}

	// Inventory with packages.
	if err := stream.Send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Inventory{Inventory: &agentv1.InventoryReport{
		CollectedAtMs: time.Now().UnixMilli(),
		Sections: []*agentv1.InventorySection{
			{Data: &agentv1.InventorySection_Os{Os: &agentv1.OsInfo{Id: "debian", PrettyName: "Debian GNU/Linux 12 (bookworm)"}}},
			{Data: &agentv1.InventorySection_Packages{Packages: &agentv1.PackageList{Manager: "dpkg", Packages: []*agentv1.Package{
				{Name: "openssl", Version: "3.0.11-1", Arch: "amd64"}, {Name: "bash", Version: "5.2", Arch: "amd64"}}}}},
		},
	}}}); err != nil {
		t.Fatal(err)
	}
	hid := uuid.MustParse(hostID)
	waitFor(t, func() bool {
		pk, err := e.st.Q.ListHostPackages(e.ctx, db.ListHostPackagesParams{HostID: hid})
		return err == nil && len(pk) == 2
	})
	h, err := e.st.Q.GetHost(e.ctx, hid)
	if err != nil || !h.Connected || h.OsPrettyName != "Debian GNU/Linux 12 (bookworm)" || string(h.Labels) != `{"env": "test"}` {
		t.Fatalf("host row: %+v %v", h, err)
	}

	// Dispatch a signed job via the DB queue and complete it.
	jobID := ids.NewUUID()
	if _, err := e.st.Q.CreateJob(e.ctx, db.CreateJobParams{ID: jobID, Type: "pkg_refresh", Params: json.RawMessage(`{}`), RequestedByName: "alice"}); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 16)
	sj, err := e.signer.SignJob(&agentv1.Job{JobId: jobID.String(), HostId: hostID, NotBefore: time.Now().Unix(), ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Nonce: nonce, RequestedBy: "alice", Action: &agentv1.Job_PkgRefresh{PkgRefresh: &agentv1.PkgRefresh{}}})
	if err != nil {
		t.Fatal(err)
	}
	env, _ := proto.Marshal(sj)
	if err := e.st.Q.InsertJobTarget(e.ctx, db.InsertJobTargetParams{JobID: jobID, HostID: hid, SignedEnvelope: env, ExpiresAt: time.Now().Add(5 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Notify(e.ctx, store.ChanDispatch, hostID); err != nil {
		t.Fatal(err)
	}
	var got *agentv1.SignedJob
	deadline := time.After(10 * time.Second)
	for got == nil {
		msgCh := make(chan *agentv1.ConnectResponse, 1)
		go func() {
			m, err := stream.Recv()
			if err == nil {
				msgCh <- m
			}
		}()
		select {
		case m := <-msgCh:
			got = m.GetJob()
		case <-deadline:
			t.Fatal("job not dispatched")
		}
	}
	if !proto.Equal(got, sj) {
		t.Fatal("dispatched envelope differs")
	}
	for _, ev := range []*agentv1.JobEvent{
		{JobId: jobID.String(), Event: &agentv1.JobEvent_Started{Started: &agentv1.JobStarted{}}},
		{JobId: jobID.String(), Event: &agentv1.JobEvent_Output{Output: &agentv1.JobOutput{Stream: agentv1.OutputStream_OUTPUT_STREAM_STDOUT, Data: []byte("Hit:1 http://deb.debian.org\n")}}},
		{JobId: jobID.String(), Event: &agentv1.JobEvent_Finished{Finished: &agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_SUCCEEDED}}},
	} {
		if err := stream.Send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_JobEvent{JobEvent: ev}}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool {
		j, err := e.st.Q.GetJob(e.ctx, jobID)
		return err == nil && j.Status == "succeeded"
	})
	out, err := e.st.Q.ListJobOutput(e.ctx, db.ListJobOutputParams{JobID: jobID, HostID: hid})
	if err != nil || len(out) != 1 || !strings.Contains(string(out[0].Data), "deb.debian.org") {
		t.Fatalf("output: %v %v", out, err)
	}

	// Renewal yields a cert for the same host.
	key2, _ := pki.GenerateKey()
	csr2, _ := pki.NewCSR(key2, "x")
	rr, err := c.Renew(e.ctx, &agentv1.RenewRequest{CsrDer: csr2})
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(rr.GetCertChainDer()[0])
	if id, _ := pki.HostIDFromCert(leaf); id != hostID {
		t.Fatalf("renewed cert for %q", id)
	}
	_ = stream.CloseSend()
}

func TestConnectRequiresValidIdentity(t *testing.T) {
	e := newEnv(t)
	hostID, cert := e.enroll(e.token(5))
	_ = hostID

	// No client certificate.
	stream, err := e.client(nil).Connect(e.ctx)
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no cert: %v", err)
	}

	// Certificate for a host that does not exist in the DB.
	ghost := e.pki.IssueAgent(t, ids.New())
	if _, err := e.client(&ghost).Renew(e.ctx, &agentv1.RenewRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unknown host: %v", err)
	}

	// Certificate from a foreign CA fails at TLS.
	foreign := testpki.New(t).IssueAgent(t, hostID)
	if _, err := e.client(&foreign).Renew(e.ctx, &agentv1.RenewRequest{}); err == nil || status.Code(err) == codes.OK {
		t.Fatal("foreign CA accepted")
	}

	// Revoked certificate.
	hid := uuid.MustParse(hostID)
	if _, err := e.st.Q.RevokeHostCerts(e.ctx, db.RevokeHostCertsParams{HostID: hid, RevokeReason: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Notify(e.ctx, store.ChanRevocations, hostID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		_, err := e.client(&cert).Renew(e.ctx, &agentv1.RenewRequest{})
		return status.Code(err) == codes.PermissionDenied
	})

	// First message must be Hello.
	_, cert2 := e.enroll(e.token(1))
	s2, err := e.client(&cert2).Connect(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = s2.Send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Heartbeat{Heartbeat: &agentv1.Heartbeat{}}})
	if _, err := s2.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("no hello: %v", err)
	}
}

func TestHostCannotTouchOtherHostsJobs(t *testing.T) {
	e := newEnv(t)
	hostA, _ := e.enroll(e.token(1))
	_, certB := e.enroll(e.token(1))
	jobID := ids.NewUUID()
	if _, err := e.st.Q.CreateJob(e.ctx, db.CreateJobParams{ID: jobID, Type: "reboot", Params: json.RawMessage(`{}`), RequestedByName: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Q.InsertJobTarget(e.ctx, db.InsertJobTargetParams{JobID: jobID, HostID: uuid.MustParse(hostA), SignedEnvelope: []byte{1}, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	s, err := e.client(&certB).Connect(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Hello{Hello: &agentv1.Hello{Facts: &agentv1.HostFacts{Hostname: "b"}}}})
	if _, err := s.Recv(); err != nil {
		t.Fatal(err)
	}
	_ = s.Send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_JobEvent{JobEvent: &agentv1.JobEvent{
		JobId: jobID.String(), Event: &agentv1.JobEvent_Finished{Finished: &agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_SUCCEEDED}}}}})
	time.Sleep(300 * time.Millisecond)
	tg, err := e.st.Q.GetJobTarget(e.ctx, db.GetJobTargetParams{JobID: jobID, HostID: uuid.MustParse(hostA)})
	if err != nil || tg.Status != "queued" {
		t.Fatalf("host B modified host A's target: %+v %v", tg, err)
	}
}

func TestShellSessionBoundToHost(t *testing.T) {
	e := newEnv(t)
	_, certB := e.enroll(e.token(1))
	s, err := e.client(&certB).ShellSession(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Send(&agentv1.ShellSessionRequest{Payload: &agentv1.ShellSessionRequest_Attach{Attach: &agentv1.ShellAttach{SessionId: ids.New()}}})
	if _, err := s.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unknown session attach: %v", err)
	}
}

func TestEnrollRejectsBadInput(t *testing.T) {
	e := newEnv(t)
	key, _ := pki.GenerateKey()
	csr, _ := pki.NewCSR(key, "x")
	c := e.client(nil)
	for name, req := range map[string]*agentv1.EnrollRequest{
		"empty token":   {CsrDer: csr},
		"unknown token": {Token: auth.PrefixEnrollment + strings.Repeat("A", 43), CsrDer: csr},
		"bad csr":       {Token: e.token(1), CsrDer: []byte("x")},
	} {
		if _, err := c.Enroll(e.ctx, req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEnrollRateLimited(t *testing.T) {
	e := newEnv(t)
	c := e.client(nil)
	var mu sync.Mutex
	limited := false
	for range 20 {
		_, err := c.Enroll(e.ctx, &agentv1.EnrollRequest{Token: "x"})
		mu.Lock()
		if status.Code(err) == codes.ResourceExhausted {
			limited = true
		}
		mu.Unlock()
	}
	if !limited {
		t.Fatal("enrollment not rate limited")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}
