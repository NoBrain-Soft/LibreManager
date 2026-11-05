package collect

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

func probe(name string, kind agentv1.ProbeKind, target string) *agentv1.Probe {
	return &agentv1.Probe{Name: name, Kind: kind, Target: target, IntervalS: 30, TimeoutMs: 2000}
}

func TestValidateProbe(t *testing.T) {
	tests := []struct {
		name string
		p    *agentv1.Probe
		ok   bool
	}{
		{"tcp ok", probe("db", agentv1.ProbeKind_PROBE_KIND_TCP, "db.internal:5432"), true},
		{"tcp ipv6", probe("db6", agentv1.ProbeKind_PROBE_KIND_TCP, "[::1]:5432"), true},
		{"tcp no port", probe("x", agentv1.ProbeKind_PROBE_KIND_TCP, "db.internal"), false},
		{"tcp port zero", probe("x", agentv1.ProbeKind_PROBE_KIND_TCP, "db:0"), false},
		{"tcp port too big", probe("x", agentv1.ProbeKind_PROBE_KIND_TCP, "db:70000"), false},
		{"http ok", probe("web", agentv1.ProbeKind_PROBE_KIND_HTTP, "https://example.internal/health"), true},
		{"http credentials rejected", probe("x", agentv1.ProbeKind_PROBE_KIND_HTTP, "https://user:pw@example.internal/"), false},
		{"http bad scheme", probe("x", agentv1.ProbeKind_PROBE_KIND_HTTP, "file:///etc/shadow"), false},
		{"http no host", probe("x", agentv1.ProbeKind_PROBE_KIND_HTTP, "http:///x"), false},
		{"process ok", probe("nginx", agentv1.ProbeKind_PROBE_KIND_PROCESS, "nginx"), true},
		{"process path", probe("x", agentv1.ProbeKind_PROBE_KIND_PROCESS, "/usr/sbin/nginx"), false},
		{"unit ok", probe("u", agentv1.ProbeKind_PROBE_KIND_UNIT, "nginx.service"), true},
		{"unit template instance", probe("u", agentv1.ProbeKind_PROBE_KIND_UNIT, "getty@tty1.service"), true},
		{"unit option injection", probe("x", agentv1.ProbeKind_PROBE_KIND_UNIT, "--root=/tmp"), false},
		{"unit spaces", probe("x", agentv1.ProbeKind_PROBE_KIND_UNIT, "a b"), false},
		{"unspecified kind", probe("x", agentv1.ProbeKind_PROBE_KIND_UNSPECIFIED, "x"), false},
		{"empty name", probe("", agentv1.ProbeKind_PROBE_KIND_PROCESS, "x"), false},
		{"name too long", probe(strings.Repeat("n", 65), agentv1.ProbeKind_PROBE_KIND_PROCESS, "x"), false},
		{"name control chars", probe("a\nb", agentv1.ProbeKind_PROBE_KIND_PROCESS, "x"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateProbe(tt.p)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
		})
	}
	t.Run("clamping", func(t *testing.T) {
		s, err := validateProbe(&agentv1.Probe{Name: "a", Kind: agentv1.ProbeKind_PROBE_KIND_PROCESS, Target: "x", IntervalS: 1, TimeoutMs: 999999})
		if err != nil {
			t.Fatal(err)
		}
		if s.interval != minProbeInterval || s.timeout != minProbeInterval {
			t.Fatalf("interval %s timeout %s", s.interval, s.timeout)
		}
		s, _ = validateProbe(&agentv1.Probe{Name: "a", Kind: agentv1.ProbeKind_PROBE_KIND_PROCESS, Target: "x"})
		if s.interval != defaultProbeInterval || s.timeout != defaultProbeTimeout {
			t.Fatalf("defaults: interval %s timeout %s", s.interval, s.timeout)
		}
	})
}

func newTestProbes(t *testing.T, probes []*agentv1.Probe, mod func(*Options)) *ProbeCollector {
	t.Helper()
	o := fixtureOptions()
	o.Probes = probes
	if mod != nil {
		mod(&o)
	}
	c := NewProbeCollector(o)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestProbeKinds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	_ = closed.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/fail", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ok", http.StatusFound) })
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", http.StatusFound) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	plain := httptest.NewServer(mux)
	defer plain.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	runner := &fakeRunner{outputs: map[string]fakeResult{
		"systemctl is-active -- nginx.service": {out: "active\n"},
		"systemctl is-active -- cron.service":  {out: "inactive\n", err: &exec.ExitError{}},
	}}
	probes := []*agentv1.Probe{
		probe("tcp-up", agentv1.ProbeKind_PROBE_KIND_TCP, ln.Addr().String()),
		probe("tcp-down", agentv1.ProbeKind_PROBE_KIND_TCP, closedAddr),
		probe("https-ok", agentv1.ProbeKind_PROBE_KIND_HTTP, srv.URL+"/ok"),
		probe("https-500", agentv1.ProbeKind_PROBE_KIND_HTTP, srv.URL+"/fail"),
		probe("https-redirect", agentv1.ProbeKind_PROBE_KIND_HTTP, srv.URL+"/redirect"),
		probe("https-loop", agentv1.ProbeKind_PROBE_KIND_HTTP, srv.URL+"/loop"),
		probe("http-plain", agentv1.ProbeKind_PROBE_KIND_HTTP, plain.URL+"/ok"),
		probe("proc-java", agentv1.ProbeKind_PROBE_KIND_PROCESS, "java"),
		probe("proc-argv0", agentv1.ProbeKind_PROBE_KIND_PROCESS, "init"),
		probe("proc-missing", agentv1.ProbeKind_PROBE_KIND_PROCESS, "nginx"),
		probe("unit-active", agentv1.ProbeKind_PROBE_KIND_UNIT, "nginx.service"),
		probe("unit-inactive", agentv1.ProbeKind_PROBE_KIND_UNIT, "cron.service"),
	}
	c := newTestProbes(t, probes, func(o *Options) { o.Exec = runner; o.ProbeRootCAs = roots })
	got := collectMap(t, c)
	expect(t, got, map[string]float64{
		"stellwerk_probe_success{kind=tcp,probe=tcp-up}":            1,
		"stellwerk_probe_success{kind=tcp,probe=tcp-down}":          0,
		"stellwerk_probe_success{kind=http,probe=https-ok}":         1,
		"stellwerk_probe_success{kind=http,probe=https-500}":        0,
		"stellwerk_probe_success{kind=http,probe=https-redirect}":   1,
		"stellwerk_probe_success{kind=http,probe=https-loop}":       0,
		"stellwerk_probe_success{kind=http,probe=http-plain}":       1,
		"stellwerk_probe_success{kind=process,probe=proc-java}":     1,
		"stellwerk_probe_success{kind=process,probe=proc-argv0}":    1,
		"stellwerk_probe_success{kind=process,probe=proc-missing}":  0,
		"stellwerk_probe_success{kind=unit,probe=unit-active}":      1,
		"stellwerk_probe_success{kind=unit,probe=unit-inactive}":    0,
		"stellwerk_probe_cert_expiry_seconds{probe=https-ok}":       float64(srv.Certificate().NotAfter.Unix()),
		"stellwerk_probe_cert_expiry_seconds{probe=https-redirect}": float64(srv.Certificate().NotAfter.Unix()),
	})
	if _, ok := got["stellwerk_probe_cert_expiry_seconds{probe=http-plain}"]; ok {
		t.Error("cert expiry for plain HTTP")
	}
	if d := got["stellwerk_probe_duration_seconds{kind=tcp,probe=tcp-up}"]; d <= 0 || d > 2 {
		t.Errorf("duration = %v", d)
	}
}

func TestProbeTLSVerificationIsOn(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected handshake failure
	srv.StartTLS()
	defer srv.Close()
	// No test roots: the self-signed test certificate must be rejected.
	c := newTestProbes(t, []*agentv1.Probe{probe("self-signed", agentv1.ProbeKind_PROBE_KIND_HTTP, srv.URL)}, nil)
	got := collectMap(t, c)
	expect(t, got, map[string]float64{"stellwerk_probe_success{kind=http,probe=self-signed}": 0})
	if _, ok := got["stellwerk_probe_cert_expiry_seconds{probe=self-signed}"]; ok {
		t.Fatal("unverified certificate reported")
	}
}

func TestProbeSchedulingAndAsync(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/slow" {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
	}))
	defer srv.Close()
	defer close(release)

	now := time.Unix(1_800_000_000, 0)
	c := newTestProbes(t, []*agentv1.Probe{
		{Name: "fast", Kind: agentv1.ProbeKind_PROBE_KIND_HTTP, Target: srv.URL + "/fast", IntervalS: 60, TimeoutMs: 5000},
		{Name: "slow", Kind: agentv1.ProbeKind_PROBE_KIND_HTTP, Target: srv.URL + "/slow", IntervalS: 60, TimeoutMs: 10000},
	}, func(o *Options) { o.Now = func() time.Time { return now } })

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	got := map[string]float64{}
	if err := c.Collect(ctx, func(s Sample) { got[key(s)] = s.Value }); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("Collect blocked on slow probe for %s", time.Since(start))
	}
	expect(t, got, map[string]float64{"stellwerk_probe_success{kind=http,probe=fast}": 1})
	if _, ok := got["stellwerk_probe_success{kind=http,probe=slow}"]; ok {
		t.Fatal("slow probe reported before completion")
	}

	// Not due yet: no new requests, cached results are emitted.
	now = now.Add(30 * time.Second)
	before := hits.Load()
	got = collectMap(t, c)
	if hits.Load() != before {
		t.Fatalf("probe re-run before its interval")
	}
	expect(t, got, map[string]float64{"stellwerk_probe_success{kind=http,probe=fast}": 1})

	// SetProbes with an unchanged spec keeps state; a removed probe goes away.
	c.SetProbes([]*agentv1.Probe{{Name: "fast", Kind: agentv1.ProbeKind_PROBE_KIND_HTTP, Target: srv.URL + "/fast", IntervalS: 60, TimeoutMs: 5000}})
	got = collectMap(t, c)
	expect(t, got, map[string]float64{"stellwerk_probe_success{kind=http,probe=fast}": 1})
	if len(got) != 2 {
		t.Fatalf("got %v", sortedKeys(got))
	}
}

func TestProbeLimits(t *testing.T) {
	var probes []*agentv1.Probe
	for i := range MaxProbes + 10 {
		probes = append(probes, probe("p"+strings.Repeat("x", i%3)+string(rune('a'+i%26))+string(rune('a'+i/26)), agentv1.ProbeKind_PROBE_KIND_PROCESS, "nonexistent"))
	}
	probes = append(probes, probe("pxa"+"a", agentv1.ProbeKind_PROBE_KIND_PROCESS, "dup"))
	c := newTestProbes(t, probes, nil)
	c.mu.Lock()
	n := len(c.states)
	c.mu.Unlock()
	if n != MaxProbes {
		t.Fatalf("accepted %d probes, want %d", n, MaxProbes)
	}
}

func TestProbeClose(t *testing.T) {
	c := newTestProbes(t, []*agentv1.Probe{probe("p", agentv1.ProbeKind_PROBE_KIND_PROCESS, "java")}, nil)
	_ = c.Close()
	// After Close no results are recorded, and Collect does not hang.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Collect(ctx, func(Sample) {}); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
