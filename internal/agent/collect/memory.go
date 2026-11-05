package collect

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
)

// meminfoFields maps /proc/meminfo keys to metric names (values in kB).
var meminfoFields = map[string]string{
	"MemTotal":     "stellwerk_memory_total_bytes",
	"MemAvailable": "stellwerk_memory_available_bytes",
	"MemFree":      "stellwerk_memory_free_bytes",
	"Cached":       "stellwerk_memory_cached_bytes",
	"Buffers":      "stellwerk_memory_buffers_bytes",
	"Shmem":        "stellwerk_memory_shared_bytes",
	"Slab":         "stellwerk_memory_slab_bytes",
	"SwapTotal":    "stellwerk_swap_total_bytes",
	"SwapFree":     "stellwerk_swap_free_bytes",
}

// meminfoCollector reads /proc/meminfo (all gauges, bytes).
type meminfoCollector struct{ procRoot string }

func newMeminfoCollector(o Options) *meminfoCollector { return &meminfoCollector{o.ProcRoot} }

func (c *meminfoCollector) Name() string { return "meminfo" }

func (c *meminfoCollector) Collect(_ context.Context, emit func(Sample)) error {
	data, err := readProc(c.procRoot, "meminfo")
	if err != nil {
		return fmt.Errorf("read /proc/meminfo: %w", err)
	}
	eachMeminfo(data, func(key string, bytes uint64) {
		if name, ok := meminfoFields[key]; ok {
			emit(sample(name, float64(bytes)))
		}
	})
	return nil
}

// eachMeminfo calls fn with every "Key: value [kB]" pair, scaled to bytes.
func eachMeminfo(data []byte, fn func(key string, value uint64)) {
	eachLine(data, func(line []byte) {
		k, rest, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			return
		}
		f := bytes.Fields(rest)
		if len(f) == 0 {
			return
		}
		v, ok := parseUint(f[0])
		if !ok {
			return
		}
		if len(f) > 1 && bytes.Equal(f[1], []byte("kB")) {
			v *= 1024
		}
		fn(string(k), v)
	})
}

// vmstatCollector reads /proc/vmstat: stellwerk_oom_kills_total (kernel
// >= 4.13).
type vmstatCollector struct{ procRoot string }

func newVmstatCollector(o Options) *vmstatCollector { return &vmstatCollector{o.ProcRoot} }

func (c *vmstatCollector) Name() string { return "vmstat" }

func (c *vmstatCollector) Collect(_ context.Context, emit func(Sample)) error {
	data, err := readProc(c.procRoot, "vmstat")
	if err != nil {
		return fmt.Errorf("read /proc/vmstat: %w", err)
	}
	eachLine(data, func(line []byte) {
		if v, ok := bytes.CutPrefix(line, []byte("oom_kill ")); ok {
			emitUint(emit, "stellwerk_oom_kills_total", bytes.TrimSpace(v), 1)
		}
	})
	return nil
}

// filefdCollector reads /proc/sys/fs/file-nr ("allocated unused max"):
// stellwerk_filefd_allocated, stellwerk_filefd_maximum.
type filefdCollector struct{ procRoot string }

func newFilefdCollector(o Options) *filefdCollector { return &filefdCollector{o.ProcRoot} }

func (c *filefdCollector) Name() string { return "filefd" }

func (c *filefdCollector) Collect(_ context.Context, emit func(Sample)) error {
	data, err := readProc(c.procRoot, "sys", "fs", "file-nr")
	if err != nil {
		return fmt.Errorf("read file-nr: %w", err)
	}
	f := bytes.Fields(data)
	if len(f) < 3 {
		return fmt.Errorf("malformed file-nr %q", data)
	}
	emitUint(emit, "stellwerk_filefd_allocated", f[0], 1)
	emitUint(emit, "stellwerk_filefd_maximum", f[2], 1)
	return nil
}

// conntrackCollector reads the netfilter conntrack sysctls when the module
// is loaded: stellwerk_conntrack_entries, stellwerk_conntrack_entries_limit.
type conntrackCollector struct{ procRoot string }

func newConntrackCollector(o Options) *conntrackCollector { return &conntrackCollector{o.ProcRoot} }

func (c *conntrackCollector) Name() string { return "conntrack" }

func (c *conntrackCollector) Collect(_ context.Context, emit func(Sample)) error {
	dir := filepath.Join(c.procRoot, "sys", "net", "netfilter")
	for _, f := range []struct{ file, name string }{
		{"nf_conntrack_count", "stellwerk_conntrack_entries"},
		{"nf_conntrack_max", "stellwerk_conntrack_entries_limit"},
	} {
		file, name := f.file, f.name
		v, err := osutil.ReadUint(filepath.Join(dir, file))
		if err != nil {
			if isNotExist(err) {
				continue
			}
			return fmt.Errorf("read %s: %w", file, err)
		}
		emit(sample(name, float64(v)))
	}
	return nil
}
