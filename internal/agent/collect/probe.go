package collect

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Probe limits.
const (
	MaxProbes            = 64
	maxProbeName         = 64
	defaultProbeInterval = 60 * time.Second
	minProbeInterval     = 10 * time.Second
	maxProbeInterval     = time.Hour
	defaultProbeTimeout  = 5 * time.Second
	minProbeTimeout      = 100 * time.Millisecond
	maxProbeTimeout      = 30 * time.Second
	maxProbeWait         = 5 * time.Second
	maxRedirects         = 5
	maxProbeBody         = 64 << 10
	processCacheTTL      = 5 * time.Second
)

var probeUnitName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@\\-]{0,250}$`)

// probeSpec is a validated probe.
type probeSpec struct {
	name     string
	kind     string // tcp, http, process, unit
	target   string
	interval time.Duration
	timeout  time.Duration
}

type probeState struct {
	spec    probeSpec
	lastRun time.Time
	running bool
	done    chan struct{}

	have     bool
	success  bool
	duration time.Duration
	expiry   time.Time // zero: no TLS / unknown
}

// ProbeCollector runs local probes configured centrally (ARCHITECTURE.md
// §5.1) on their own intervals with bounded concurrency.
//
//	stellwerk_probe_success{probe,kind}           gauge (0/1)
//	stellwerk_probe_duration_seconds{probe,kind}  gauge
//	stellwerk_probe_cert_expiry_seconds{probe}    gauge, unix time of the
//	    earliest NotAfter in the presented chain (HTTPS only)
//
// Collect starts the probes that are due, waits briefly (≤ 5 s or the
// context deadline) for them, and emits the latest result of every probe.
// Slow probes keep running in the background and are reported next round;
// a probe is never started twice concurrently.
type ProbeCollector struct {
	exec     CommandRunner
	procRoot string
	roots    *x509.CertPool
	now      func() time.Time
	log      *slog.Logger
	sem      chan struct{}

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	states []*probeState

	procMu    sync.Mutex
	procNames map[string]bool
	procAt    time.Time
}

// NewProbeCollector returns a probe collector configured with opts.Probes.
func NewProbeCollector(opts Options) *ProbeCollector {
	o := opts.withDefaults()
	ctx, cancel := context.WithCancel(context.Background())
	c := &ProbeCollector{
		exec:     o.Exec,
		procRoot: o.ProcRoot,
		roots:    o.ProbeRootCAs,
		now:      o.Now,
		log:      o.Logger,
		sem:      make(chan struct{}, o.ProbeConcurrency),
		ctx:      ctx,
		cancel:   cancel,
	}
	c.SetProbes(o.Probes)
	return c
}

func (c *ProbeCollector) Name() string { return "probes" }

// Close stops running probes.
func (c *ProbeCollector) Close() error {
	c.cancel()
	return nil
}

// SetProbes replaces the probe set. Invalid probes are skipped (and logged);
// state of unchanged probes is kept. At most MaxProbes are accepted.
func (c *ProbeCollector) SetProbes(probes []*agentv1.Probe) {
	specs := make([]probeSpec, 0, len(probes))
	seen := make(map[string]bool)
	for _, p := range probes {
		if len(specs) >= MaxProbes {
			c.log.Warn("too many probes; ignoring the rest", "max", MaxProbes)
			break
		}
		spec, err := validateProbe(p)
		if err != nil {
			c.log.Warn("ignoring invalid probe", "error", err)
			continue
		}
		if seen[spec.name] {
			c.log.Warn("ignoring duplicate probe name", "probe", spec.name)
			continue
		}
		seen[spec.name] = true
		specs = append(specs, spec)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	old := make(map[string]*probeState, len(c.states))
	for _, st := range c.states {
		old[st.spec.name] = st
	}
	states := make([]*probeState, 0, len(specs))
	for _, spec := range specs {
		if st, ok := old[spec.name]; ok && st.spec == spec {
			states = append(states, st)
			continue
		}
		states = append(states, &probeState{spec: spec})
	}
	c.states = states
}

func validateProbe(p *agentv1.Probe) (probeSpec, error) {
	if p == nil {
		return probeSpec{}, errors.New("nil probe")
	}
	name := p.GetName()
	if name == "" || len(name) > maxProbeName || osutil.Clean(name, maxProbeName) != name {
		return probeSpec{}, fmt.Errorf("invalid probe name %q", osutil.Clean(name, maxProbeName))
	}
	spec := probeSpec{name: name, target: p.GetTarget()}
	spec.interval = clampDuration(time.Duration(p.GetIntervalS())*time.Second, defaultProbeInterval, minProbeInterval, maxProbeInterval)
	spec.timeout = clampDuration(time.Duration(p.GetTimeoutMs())*time.Millisecond, defaultProbeTimeout, minProbeTimeout, maxProbeTimeout)
	spec.timeout = min(spec.timeout, spec.interval)
	switch p.GetKind() {
	case agentv1.ProbeKind_PROBE_KIND_TCP:
		spec.kind = "tcp"
		host, port, err := net.SplitHostPort(spec.target)
		if err != nil || host == "" {
			return probeSpec{}, fmt.Errorf("probe %s: tcp target must be host:port", name)
		}
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return probeSpec{}, fmt.Errorf("probe %s: invalid port %q", name, port)
		}
	case agentv1.ProbeKind_PROBE_KIND_HTTP:
		spec.kind = "http"
		u, err := url.Parse(spec.target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return probeSpec{}, fmt.Errorf("probe %s: http target must be an http(s) URL", name)
		}
		if u.User != nil {
			return probeSpec{}, fmt.Errorf("probe %s: credentials in URLs are not allowed", name)
		}
	case agentv1.ProbeKind_PROBE_KIND_PROCESS:
		spec.kind = "process"
		if spec.target == "" || len(spec.target) > 255 || strings.ContainsAny(spec.target, "/\x00\n") {
			return probeSpec{}, fmt.Errorf("probe %s: invalid process name", name)
		}
	case agentv1.ProbeKind_PROBE_KIND_UNIT:
		spec.kind = "unit"
		if !probeUnitName.MatchString(spec.target) {
			return probeSpec{}, fmt.Errorf("probe %s: invalid unit name", name)
		}
	default:
		return probeSpec{}, fmt.Errorf("probe %s: unsupported kind %v", name, p.GetKind())
	}
	return spec, nil
}

func clampDuration(d, def, lo, hi time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return max(lo, min(d, hi))
}

// Collect implements Collector.
func (c *ProbeCollector) Collect(ctx context.Context, emit func(Sample)) error {
	now := c.now()
	var waits []chan struct{}
	c.mu.Lock()
	for _, st := range c.states {
		if st.running || (!st.lastRun.IsZero() && now.Sub(st.lastRun) < st.spec.interval) {
			continue
		}
		st.running = true
		st.lastRun = now
		st.done = make(chan struct{})
		waits = append(waits, st.done)
		go c.run(st)
	}
	c.mu.Unlock()

	if len(waits) > 0 {
		wait := maxProbeWait
		if dl, ok := ctx.Deadline(); ok {
			wait = min(wait, time.Until(dl))
		}
		timer := time.NewTimer(max(wait, 0))
	waitLoop:
		for _, ch := range waits {
			select {
			case <-ch:
			case <-timer.C:
				break waitLoop
			case <-ctx.Done():
				break waitLoop
			}
		}
		timer.Stop()
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, st := range c.states {
		if !st.have {
			continue
		}
		ok := 0.0
		if st.success {
			ok = 1
		}
		emit(sample("stellwerk_probe_success", ok, "kind", st.spec.kind, "probe", st.spec.name))
		emit(sample("stellwerk_probe_duration_seconds", st.duration.Seconds(), "kind", st.spec.kind, "probe", st.spec.name))
		if !st.expiry.IsZero() {
			emit(sample("stellwerk_probe_cert_expiry_seconds", float64(st.expiry.Unix()), "probe", st.spec.name))
		}
	}
	return nil
}

func (c *ProbeCollector) run(st *probeState) {
	spec := st.spec
	var (
		ok     bool
		expiry time.Time
		dur    time.Duration
	)
	select {
	case c.sem <- struct{}{}:
		ctx, cancel := context.WithTimeout(c.ctx, spec.timeout)
		start := time.Now()
		ok, expiry = c.probe(ctx, spec)
		dur = time.Since(start)
		cancel()
		<-c.sem
	case <-c.ctx.Done():
	}
	c.mu.Lock()
	st.running = false
	if c.ctx.Err() == nil {
		st.have, st.success, st.duration, st.expiry = true, ok, dur, expiry
	}
	close(st.done)
	c.mu.Unlock()
}

func (c *ProbeCollector) probe(ctx context.Context, spec probeSpec) (bool, time.Time) {
	switch spec.kind {
	case "tcp":
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", spec.target)
		if err != nil {
			return false, time.Time{}
		}
		_ = conn.Close()
		return true, time.Time{}
	case "http":
		return c.probeHTTP(ctx, spec)
	case "process":
		return c.processRunning(spec.target), time.Time{}
	case "unit":
		out, _ := c.exec.Run(ctx, "systemctl", "is-active", "--", spec.target)
		return string(bytes.TrimSpace(out)) == "active", time.Time{}
	}
	return false, time.Time{}
}

// probeHTTP performs a GET with TLS verification against the system roots
// (or ProbeRootCAs in tests), no proxy, no keep-alive, at most 5 redirects.
// 2xx/3xx final status is success.
func (c *ProbeCollector) probeHTTP(ctx context.Context, spec probeSpec) (bool, time.Time) {
	dialer := &net.Dialer{Timeout: spec.timeout}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.roots},
		TLSHandshakeTimeout:    spec.timeout,
		ResponseHeaderTimeout:  spec.timeout,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   spec.timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, spec.target, nil)
	if err != nil {
		return false, time.Time{}
	}
	req.Header.Set("User-Agent", "stellwerk-agent-probe/1")
	resp, err := client.Do(req)
	if err != nil {
		return false, time.Time{}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBody))
	_ = resp.Body.Close()
	var expiry time.Time
	if resp.TLS != nil {
		for _, cert := range resp.TLS.PeerCertificates {
			if expiry.IsZero() || cert.NotAfter.Before(expiry) {
				expiry = cert.NotAfter
			}
		}
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 400, expiry
}

// processRunning matches the target against process comm names (truncated
// to 15 bytes by the kernel) and the basename of argv[0].
func (c *ProbeCollector) processRunning(target string) bool {
	names := c.processNames()
	if names[target] {
		return true
	}
	if len(target) > 15 && names[target[:15]] {
		return true
	}
	return false
}

func (c *ProbeCollector) processNames() map[string]bool {
	c.procMu.Lock()
	defer c.procMu.Unlock()
	now := time.Now()
	if c.procNames != nil && now.Sub(c.procAt) < processCacheTTL {
		return c.procNames
	}
	names := make(map[string]bool)
	_ = eachPID(c.procRoot, func(pid int32) bool {
		dir := filepath.Join(c.procRoot, strconv.Itoa(int(pid)))
		if comm, err := osutil.ReadString(filepath.Join(dir, "comm"), 64); err == nil && comm != "" {
			names[comm] = true
		}
		if data, err := osutil.ReadFileLimit(filepath.Join(dir, "cmdline"), 64<<10); err == nil {
			argv0, _, _ := bytes.Cut(data, []byte{0})
			if len(argv0) > 0 {
				names[filepath.Base(string(argv0))] = true
			}
		}
		return len(names) < maxProcessScan
	})
	c.procNames, c.procAt = names, now
	return names
}
