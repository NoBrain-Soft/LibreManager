package collect

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// timesyncCollector reports the kernel's clock discipline state:
//
//	stellwerk_time_sync_status     gauge (1 synchronized, 0 not)
//	stellwerk_time_offset_seconds  gauge
type timesyncCollector struct {
	query func() (bool, time.Duration, error)
}

func newTimesyncCollector(o Options) *timesyncCollector { return &timesyncCollector{o.TimeSync} }

func (c *timesyncCollector) Name() string { return "timesync" }

func (c *timesyncCollector) Collect(_ context.Context, emit func(Sample)) error {
	synced, off, err := c.query()
	if err != nil {
		return fmt.Errorf("query time sync: %w", err)
	}
	v := 0.0
	if synced {
		v = 1
	}
	emit(sample("stellwerk_time_sync_status", v))
	emit(sample("stellwerk_time_offset_seconds", off.Seconds()))
	return nil
}

// systemdCollector counts failed units via
// `systemctl list-units --state=failed --plain --no-legend --no-pager`,
// at most once per interval (default 60 s); results are cached between runs.
//
//	stellwerk_systemd_units_failed  gauge
//
// Hosts not booted with systemd (no /run/systemd/system) are skipped.
type systemdCollector struct {
	exec     CommandRunner
	rootFS   string
	interval time.Duration
	now      func() time.Time

	mu      sync.Mutex
	lastRun time.Time
	value   float64
	have    bool
}

func newSystemdCollector(o Options) *systemdCollector {
	return &systemdCollector{exec: o.Exec, rootFS: o.RootFS, interval: o.SystemdInterval, now: o.Now}
}

func (c *systemdCollector) Name() string { return "systemd" }

func (c *systemdCollector) Collect(ctx context.Context, emit func(Sample)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.lastRun.IsZero() || now.Sub(c.lastRun) >= c.interval {
		c.lastRun = now
		if err := c.refresh(ctx); err != nil {
			// Never keep reporting a stale count after a failure.
			c.have = false
			return err
		}
	}
	if c.have {
		emit(sample("stellwerk_systemd_units_failed", c.value))
	}
	return nil
}

func (c *systemdCollector) refresh(ctx context.Context) error {
	if _, err := os.Stat(filepath.Join(c.rootFS, "run", "systemd", "system")); err != nil {
		c.have = false
		return nil //nolint:nilerr // no systemd on this host: nothing to collect
	}
	out, err := c.exec.Run(ctx, "systemctl", "list-units", "--state=failed", "--plain", "--no-legend", "--no-pager")
	if err != nil {
		return fmt.Errorf("systemctl list-units: %w", err)
	}
	n := 0
	eachLine(out, func(line []byte) {
		if len(bytes.TrimSpace(line)) > 0 {
			n++
		}
	})
	c.value = float64(n)
	c.have = true
	return nil
}

// selfCollector reports the agent's own footprint:
//
//	stellwerk_agent_rss_bytes          gauge
//	stellwerk_agent_cpu_seconds_total  counter (user + system)
//	stellwerk_agent_goroutines         gauge
type selfCollector struct {
	procRoot string
	pageSize float64
}

func newSelfCollector(o Options) *selfCollector {
	return &selfCollector{procRoot: o.ProcRoot, pageSize: float64(os.Getpagesize())}
}

func (c *selfCollector) Name() string { return "self" }

func (c *selfCollector) Collect(_ context.Context, emit func(Sample)) error {
	emit(sample("stellwerk_agent_goroutines", float64(runtime.NumGoroutine())))
	if data, err := readProc(c.procRoot, "self", "statm"); err == nil {
		if f := bytes.Fields(data); len(f) >= 2 {
			emitUint(emit, "stellwerk_agent_rss_bytes", f[1], c.pageSize)
		}
	}
	data, err := readProc(c.procRoot, "self", "stat")
	if err != nil {
		return fmt.Errorf("read /proc/self/stat: %w", err)
	}
	st, ok := parsePIDStat(data)
	if !ok {
		return fmt.Errorf("malformed /proc/self/stat")
	}
	emit(sample("stellwerk_agent_cpu_seconds_total", float64(st.utime+st.stime)/userHZ))
	return nil
}
