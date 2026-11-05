// Package collect implements the agent's metrics collectors
// (ARCHITECTURE.md §5.1 "Collectors (MVP)", §7.3) and the delta-friendly
// MetricsBatch encoder.
//
// Collectors read /proc and /sys directly (no gopsutil) and are designed for
// a 15 s interval at well under 1 % CPU: they read small files, cache static
// data, and run expensive or potentially blocking work (systemctl, statfs on
// network filesystems, probes) with timeouts and rate limits.
//
// Metric names are a contract with the server's chart queries and alert
// rules; they follow node_exporter semantics with a "stellwerk_" prefix.
// Every collector takes configurable roots so tests run against fixtures.
package collect

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	"github.com/nobrain-soft/libremanager/internal/common/timesync"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Label is a metric label.
type Label struct{ Name, Value string }

// Sample is one metric value. Labels are sorted by name.
type Sample struct {
	Name   string
	Labels []Label
	Value  float64
}

// Collector produces samples. Collect must be safe to call repeatedly and
// should return an error only for unexpected failures (a missing optional
// source such as /proc/pressure is not an error).
type Collector interface {
	Name() string
	Collect(ctx context.Context, emit func(Sample)) error
}

// CommandRunner runs programs with argument vectors (never a shell).
type CommandRunner = osutil.CommandRunner

// Options configures DefaultCollectors. Zero values select production
// defaults.
type Options struct {
	// ProcRoot, SysRoot and RootFS default to "/proc", "/sys" and "/".
	ProcRoot, SysRoot, RootFS string
	// PerCPU adds a cpu label to stellwerk_cpu_seconds_total.
	PerCPU bool
	// Probes are the initial local probes (see ProbeCollector.SetProbes).
	Probes []*agentv1.Probe
	// Exec runs systemctl (default osutil.ExecRunner).
	Exec CommandRunner

	// Statfs overrides statfs(2) (tests).
	Statfs osutil.StatfsFunc
	// StatfsTimeout bounds statfs per mount (default 5 s).
	StatfsTimeout time.Duration
	// TimeSync overrides timesync.Synchronized (tests).
	TimeSync func() (bool, time.Duration, error)
	// ProbeRootCAs replaces the system roots for HTTPS probes (tests only;
	// verification is never disabled).
	ProbeRootCAs *x509.CertPool
	// ProbeConcurrency bounds concurrently running probes (default 4).
	ProbeConcurrency int
	// SystemdInterval is the minimum time between systemctl invocations
	// (default 60 s).
	SystemdInterval time.Duration
	// Now overrides time.Now (tests).
	Now func() time.Time
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

func (o Options) withDefaults() Options {
	if o.ProcRoot == "" {
		o.ProcRoot = "/proc"
	}
	if o.SysRoot == "" {
		o.SysRoot = "/sys"
	}
	if o.RootFS == "" {
		o.RootFS = "/"
	}
	if o.Exec == nil {
		o.Exec = osutil.ExecRunner{Timeout: 20 * time.Second, MaxOutput: 4 << 20}
	}
	if o.StatfsTimeout <= 0 {
		o.StatfsTimeout = 5 * time.Second
	}
	if o.TimeSync == nil {
		o.TimeSync = timesync.Synchronized
	}
	if o.ProbeConcurrency <= 0 {
		o.ProbeConcurrency = 4
	}
	if o.SystemdInterval <= 0 {
		o.SystemdInterval = 60 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o
}

// DefaultCollectors returns the MVP collector set. The *ProbeCollector in
// the result can be found with FindProbeCollector to update probes when
// central sends new settings. Collectors implementing io.Closer should be
// closed on shutdown.
func DefaultCollectors(opts Options) []Collector {
	o := opts.withDefaults()
	return []Collector{
		newStatCollector(o),
		newLoadavgCollector(o),
		newPressureCollector(o),
		newMeminfoCollector(o),
		newVmstatCollector(o),
		newFilesystemCollector(o),
		newDiskstatsCollector(o),
		newNetdevCollector(o),
		newSocketCollector(o),
		newConntrackCollector(o),
		newUptimeCollector(o),
		newFilefdCollector(o),
		newProcessCountCollector(o),
		newTimesyncCollector(o),
		newSystemdCollector(o),
		NewProbeCollector(o),
		newSelfCollector(o),
	}
}

// FindProbeCollector returns the probe collector in cs, if any.
func FindProbeCollector(cs []Collector) *ProbeCollector {
	for _, c := range cs {
		if p, ok := c.(*ProbeCollector); ok {
			return p
		}
	}
	return nil
}

// CollectAll runs every collector sequentially and returns all samples. A
// failing collector does not stop the others; their errors are joined.
func CollectAll(ctx context.Context, cs []Collector) ([]Sample, error) {
	samples := make([]Sample, 0, 512)
	emit := func(s Sample) { samples = append(samples, s) }
	var errs []error
	for _, c := range cs {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		if err := c.Collect(ctx, emit); err != nil {
			errs = append(errs, fmt.Errorf("collector %s: %w", c.Name(), err))
		}
	}
	return samples, errors.Join(errs...)
}

// sample builds a Sample from name/value pairs (labels sorted by name).
func sample(name string, v float64, kv ...string) Sample {
	s := Sample{Name: name, Value: v}
	if len(kv) >= 2 {
		s.Labels = make([]Label, 0, len(kv)/2)
		for i := 0; i+1 < len(kv); i += 2 {
			s.Labels = append(s.Labels, Label{Name: kv[i], Value: kv[i+1]})
		}
		sortLabels(s.Labels)
	}
	return s
}

func sortLabels(ls []Label) {
	if len(ls) < 2 {
		return
	}
	slices.SortFunc(ls, func(a, b Label) int { return strings.Compare(a.Name, b.Name) })
}

// isNotExist reports errors meaning "this optional source is absent or not
// supported here".
func isNotExist(err error) bool {
	return errors.Is(err, errNotExist) || errors.Is(err, errNoSupport) || errors.Is(err, errNotDir)
}
