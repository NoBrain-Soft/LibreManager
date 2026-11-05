package collect

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strconv"
)

// cpuModes are the /proc/stat cpu columns we export, in file order.
var cpuModes = [...]string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"}

// statCollector reads /proc/stat.
//
//	stellwerk_cpu_seconds_total{mode[,cpu]}  counter
//	stellwerk_cpu_count                      gauge (online CPUs)
//	stellwerk_context_switches_total         counter
//	stellwerk_forks_total                    counter
//	stellwerk_procs_running, _procs_blocked  gauge
//	stellwerk_boot_time_seconds              gauge (unix time)
type statCollector struct {
	procRoot string
	perCPU   bool
}

func newStatCollector(o Options) *statCollector {
	return &statCollector{procRoot: o.ProcRoot, perCPU: o.PerCPU}
}

func (c *statCollector) Name() string { return "stat" }

func (c *statCollector) Collect(_ context.Context, emit func(Sample)) error {
	data, err := readProc(c.procRoot, "stat")
	if err != nil {
		return fmt.Errorf("read /proc/stat: %w", err)
	}
	cpus := 0
	var f [][]byte
	eachLine(data, func(line []byte) {
		f = fieldsN(f, line)
		if len(f) < 2 {
			return
		}
		key := f[0]
		switch {
		case bytes.Equal(key, []byte("cpu")):
			emitCPU(emit, f[1:], "")
		case bytes.HasPrefix(key, []byte("cpu")):
			cpus++
			if c.perCPU {
				emitCPU(emit, f[1:], string(key[3:]))
			}
		case bytes.Equal(key, []byte("ctxt")):
			emitUint(emit, "stellwerk_context_switches_total", f[1], 1)
		case bytes.Equal(key, []byte("processes")):
			emitUint(emit, "stellwerk_forks_total", f[1], 1)
		case bytes.Equal(key, []byte("procs_running")):
			emitUint(emit, "stellwerk_procs_running", f[1], 1)
		case bytes.Equal(key, []byte("procs_blocked")):
			emitUint(emit, "stellwerk_procs_blocked", f[1], 1)
		case bytes.Equal(key, []byte("btime")):
			emitUint(emit, "stellwerk_boot_time_seconds", f[1], 1)
		}
	})
	if cpus > 0 {
		emit(sample("stellwerk_cpu_count", float64(cpus)))
	}
	return nil
}

func emitCPU(emit func(Sample), vals [][]byte, cpu string) {
	for i, mode := range cpuModes {
		if i >= len(vals) {
			return
		}
		v, ok := parseUint(vals[i])
		if !ok {
			continue
		}
		if cpu == "" {
			emit(sample("stellwerk_cpu_seconds_total", float64(v)/userHZ, "mode", mode))
		} else {
			emit(sample("stellwerk_cpu_seconds_total", float64(v)/userHZ, "cpu", cpu, "mode", mode))
		}
	}
}

func emitUint(emit func(Sample), name string, b []byte, scale float64) {
	if v, ok := parseUint(b); ok {
		emit(sample(name, float64(v)*scale))
	}
}

// loadavgCollector reads /proc/loadavg: stellwerk_load1/5/15.
type loadavgCollector struct{ procRoot string }

func newLoadavgCollector(o Options) *loadavgCollector { return &loadavgCollector{o.ProcRoot} }

func (c *loadavgCollector) Name() string { return "loadavg" }

func (c *loadavgCollector) Collect(_ context.Context, emit func(Sample)) error {
	data, err := readProc(c.procRoot, "loadavg")
	if err != nil {
		return fmt.Errorf("read /proc/loadavg: %w", err)
	}
	f := bytes.Fields(data)
	if len(f) < 3 {
		return fmt.Errorf("malformed /proc/loadavg %q", data)
	}
	for i, name := range []string{"stellwerk_load1", "stellwerk_load5", "stellwerk_load15"} {
		if v, ok := parseFloat(f[i]); ok {
			emit(sample(name, v))
		}
	}
	return nil
}

// pressureCollector reads PSI (/proc/pressure/{cpu,memory,io}), present on
// kernels >= 4.20 with CONFIG_PSI and psi not disabled.
//
//	stellwerk_pressure_seconds_total{resource,kind}  counter
type pressureCollector struct{ procRoot string }

func newPressureCollector(o Options) *pressureCollector { return &pressureCollector{o.ProcRoot} }

func (c *pressureCollector) Name() string { return "pressure" }

func (c *pressureCollector) Collect(_ context.Context, emit func(Sample)) error {
	for _, res := range []string{"cpu", "memory", "io"} {
		data, err := readProc(c.procRoot, "pressure", res)
		if err != nil {
			if isNotExist(err) {
				continue
			}
			return fmt.Errorf("read /proc/pressure/%s: %w", res, err)
		}
		// some avg10=0.00 avg60=0.00 avg300=0.00 total=12345
		eachLine(data, func(line []byte) {
			f := bytes.Fields(line)
			if len(f) < 2 {
				return
			}
			kind := string(f[0])
			if kind != "some" && kind != "full" {
				return
			}
			for _, kv := range f[1:] {
				if v, ok := bytes.CutPrefix(kv, []byte("total=")); ok {
					if us, ok := parseUint(v); ok {
						emit(sample("stellwerk_pressure_seconds_total", float64(us)/1e6, "kind", kind, "resource", res))
					}
				}
			}
		})
	}
	return nil
}

// uptimeCollector reads /proc/uptime: stellwerk_uptime_seconds.
type uptimeCollector struct{ procRoot string }

func newUptimeCollector(o Options) *uptimeCollector { return &uptimeCollector{o.ProcRoot} }

func (c *uptimeCollector) Name() string { return "uptime" }

func (c *uptimeCollector) Collect(_ context.Context, emit func(Sample)) error {
	up, err := readUptime(c.procRoot)
	if err != nil {
		return err
	}
	emit(sample("stellwerk_uptime_seconds", up))
	return nil
}

func readUptime(procRoot string) (float64, error) {
	data, err := readProc(procRoot, "uptime")
	if err != nil {
		return 0, fmt.Errorf("read /proc/uptime: %w", err)
	}
	f := bytes.Fields(data)
	if len(f) < 1 {
		return 0, fmt.Errorf("malformed /proc/uptime %q", data)
	}
	v, err := strconv.ParseFloat(string(f[0]), 64)
	if err != nil {
		return 0, fmt.Errorf("parse /proc/uptime: %w", err)
	}
	return v, nil
}

// processCountCollector counts processes (numeric /proc entries):
//
//	stellwerk_processes_total  gauge (current number of processes; the fork
//	                           counter is stellwerk_forks_total)
type processCountCollector struct{ procRoot string }

func newProcessCountCollector(o Options) *processCountCollector {
	return &processCountCollector{o.ProcRoot}
}

func (c *processCountCollector) Name() string { return "processes" }

func (c *processCountCollector) Collect(_ context.Context, emit func(Sample)) error {
	n, err := countPIDs(c.procRoot)
	if err != nil {
		return err
	}
	emit(sample("stellwerk_processes_total", float64(n)))
	return nil
}

func countPIDs(procRoot string) (int, error) {
	n := 0
	err := eachPID(procRoot, func(int32) bool { n++; return true })
	return n, err
}

// eachPID calls fn for every numeric entry of procRoot until fn returns
// false.
func eachPID(procRoot string, fn func(pid int32) bool) error {
	d, err := openDir(filepath.Clean(procRoot))
	if err != nil {
		return fmt.Errorf("open %s: %w", procRoot, err)
	}
	defer func() { _ = d.Close() }()
	for {
		names, err := d.Readdirnames(256)
		for _, name := range names {
			if name == "" || name[0] < '0' || name[0] > '9' {
				continue
			}
			pid, perr := strconv.ParseInt(name, 10, 32)
			if perr != nil {
				continue
			}
			if !fn(int32(pid)) {
				return nil
			}
		}
		if err != nil {
			return nil //nolint:nilerr // io.EOF or a transient readdir error ends the scan
		}
	}
}
