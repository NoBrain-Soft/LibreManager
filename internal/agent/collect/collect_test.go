package collect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
)

const fixture = "testdata/host"

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

// fixtureOptions points every root at the fixture host.
func fixtureOptions() Options {
	return Options{
		ProcRoot: filepath.Join(fixture, "proc"),
		SysRoot:  filepath.Join(fixture, "sys"),
		RootFS:   fixture,
		Exec:     &fakeRunner{},
		Statfs:   fakeStatfs(nil),
		TimeSync: func() (bool, time.Duration, error) { return true, 2 * time.Millisecond, nil },
		Logger:   discard,
	}
}

// fakeRunner returns canned output per command line.
type fakeRunner struct {
	mu      sync.Mutex
	outputs map[string]fakeResult
	calls   []string
}

type fakeResult struct {
	out string
	err error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, key)
	r, ok := f.outputs[key]
	if !ok {
		return nil, fmt.Errorf("fake: unexpected command %q: %w", key, osutil.ErrNotFound)
	}
	return []byte(r.out), r.err
}

func (f *fakeRunner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// fakeStatfs returns fixed stats for every path except those in special.
func fakeStatfs(special map[string]func() (osutil.FSStats, error)) osutil.StatfsFunc {
	return func(path string) (osutil.FSStats, error) {
		for suffix, fn := range special {
			if strings.HasSuffix(path, suffix) {
				return fn()
			}
		}
		return osutil.FSStats{Type: 0xEF53, BlockSize: 4096, Blocks: 1000, Bfree: 400, Bavail: 300, Files: 500, Ffree: 200}, nil
	}
}

// key renders a sample as name{a=b,c=d}.
func key(s Sample) string {
	if len(s.Labels) == 0 {
		return s.Name
	}
	parts := make([]string, len(s.Labels))
	for i, l := range s.Labels {
		parts[i] = l.Name + "=" + l.Value
	}
	return s.Name + "{" + strings.Join(parts, ",") + "}"
}

func collectMap(t *testing.T, c Collector) map[string]float64 {
	t.Helper()
	m := make(map[string]float64)
	err := c.Collect(context.Background(), func(s Sample) {
		if !slices.IsSortedFunc(s.Labels, func(a, b Label) int { return strings.Compare(a.Name, b.Name) }) {
			t.Errorf("labels not sorted: %v", s.Labels)
		}
		k := key(s)
		if _, dup := m[k]; dup {
			t.Errorf("duplicate sample %s", k)
		}
		m[k] = s.Value
	})
	if err != nil {
		t.Fatalf("%s: %v", c.Name(), err)
	}
	return m
}

func expect(t *testing.T, got map[string]float64, want map[string]float64) {
	t.Helper()
	for k, v := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("missing %s (have %v)", k, sortedKeys(got))
			continue
		}
		if diff := g - v; diff > 1e-9 || diff < -1e-9 {
			t.Errorf("%s = %v, want %v", k, g, v)
		}
	}
}

func absent(t *testing.T, got map[string]float64, keys ...string) {
	t.Helper()
	for _, k := range keys {
		for g := range got {
			if g == k || strings.HasPrefix(g, k+"{") || strings.Contains(g, k) {
				t.Errorf("unexpected sample %s (matched %q)", g, k)
			}
		}
	}
}

func sortedKeys(m map[string]float64) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func TestStatCollector(t *testing.T) {
	tests := []struct {
		name   string
		perCPU bool
		want   map[string]float64
		absent []string
	}{
		{
			name: "aggregate",
			want: map[string]float64{
				"stellwerk_cpu_seconds_total{mode=user}":    101321.53,
				"stellwerk_cpu_seconds_total{mode=nice}":    2906.96,
				"stellwerk_cpu_seconds_total{mode=system}":  30847.19,
				"stellwerk_cpu_seconds_total{mode=idle}":    468284.83,
				"stellwerk_cpu_seconds_total{mode=iowait}":  166.83,
				"stellwerk_cpu_seconds_total{mode=irq}":     0,
				"stellwerk_cpu_seconds_total{mode=softirq}": 251.95,
				"stellwerk_cpu_seconds_total{mode=steal}":   12,
				"stellwerk_cpu_count":                       2,
				"stellwerk_context_switches_total":          115315133,
				"stellwerk_forks_total":                     80530,
				"stellwerk_procs_running":                   3,
				"stellwerk_procs_blocked":                   1,
				"stellwerk_boot_time_seconds":               1762300000,
			},
			absent: []string{"cpu=0"},
		},
		{
			name:   "per cpu",
			perCPU: true,
			want: map[string]float64{
				"stellwerk_cpu_seconds_total{mode=user}":       101321.53,
				"stellwerk_cpu_seconds_total{cpu=0,mode=user}": 50660.76,
				"stellwerk_cpu_seconds_total{cpu=1,mode=idle}": 234142.42,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := fixtureOptions()
			o.PerCPU = tt.perCPU
			got := collectMap(t, newStatCollector(o.withDefaults()))
			expect(t, got, tt.want)
			absent(t, got, tt.absent...)
		})
	}
}

func TestSimpleProcCollectors(t *testing.T) {
	o := fixtureOptions().withDefaults()
	tests := []struct {
		c    Collector
		want map[string]float64
	}{
		{newLoadavgCollector(o), map[string]float64{"stellwerk_load1": 0.75, "stellwerk_load5": 0.35, "stellwerk_load15": 0.25}},
		{newMeminfoCollector(o), map[string]float64{
			"stellwerk_memory_total_bytes":     16337388 * 1024,
			"stellwerk_memory_available_bytes": 9876544 * 1024,
			"stellwerk_memory_free_bytes":      1203920 * 1024,
			"stellwerk_memory_cached_bytes":    7654320 * 1024,
			"stellwerk_memory_buffers_bytes":   312340 * 1024,
			"stellwerk_memory_shared_bytes":    456789 * 1024,
			"stellwerk_memory_slab_bytes":      876543 * 1024,
			"stellwerk_swap_total_bytes":       2097148 * 1024,
			"stellwerk_swap_free_bytes":        2000000 * 1024,
		}},
		{newVmstatCollector(o), map[string]float64{"stellwerk_oom_kills_total": 3}},
		{newUptimeCollector(o), map[string]float64{"stellwerk_uptime_seconds": 100000}},
		{newFilefdCollector(o), map[string]float64{"stellwerk_filefd_allocated": 9184, "stellwerk_filefd_maximum": 9223372036854775807}},
		{newConntrackCollector(o), map[string]float64{"stellwerk_conntrack_entries": 1234, "stellwerk_conntrack_entries_limit": 262144}},
		{newProcessCountCollector(o), map[string]float64{"stellwerk_processes_total": 6}},
		{newPressureCollector(o), map[string]float64{
			"stellwerk_pressure_seconds_total{kind=some,resource=cpu}":    12.345678,
			"stellwerk_pressure_seconds_total{kind=full,resource=cpu}":    0,
			"stellwerk_pressure_seconds_total{kind=some,resource=memory}": 2.5,
			"stellwerk_pressure_seconds_total{kind=full,resource=memory}": 1,
			"stellwerk_pressure_seconds_total{kind=some,resource=io}":     7,
			"stellwerk_pressure_seconds_total{kind=full,resource=io}":     3,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.c.Name(), func(t *testing.T) {
			got := collectMap(t, tt.c)
			expect(t, got, tt.want)
			if len(got) != len(tt.want) {
				t.Errorf("got %d samples, want %d: %v", len(got), len(tt.want), sortedKeys(got))
			}
		})
	}
}

func TestOptionalSourcesMissing(t *testing.T) {
	empty := t.TempDir()
	o := Options{ProcRoot: empty, SysRoot: empty, RootFS: empty, Logger: discard}.withDefaults()
	for _, c := range []Collector{newPressureCollector(o), newConntrackCollector(o), newSocketCollector(o)} {
		t.Run(c.Name(), func(t *testing.T) {
			if got := collectMap(t, c); len(got) != 0 {
				t.Fatalf("expected no samples, got %v", got)
			}
		})
	}
	// Mandatory sources report an error.
	for _, c := range []Collector{newStatCollector(o), newMeminfoCollector(o), newLoadavgCollector(o)} {
		if err := c.Collect(context.Background(), func(Sample) {}); err == nil {
			t.Errorf("%s: expected error for missing source", c.Name())
		}
	}
}

func TestDiskstats(t *testing.T) {
	t.Run("sysfs whole disks", func(t *testing.T) {
		got := collectMap(t, newDiskstatsCollector(fixtureOptions().withDefaults()))
		expect(t, got, map[string]float64{
			"stellwerk_disk_reads_completed_total{device=sda}":     31427,
			"stellwerk_disk_read_bytes_total{device=sda}":          2178826 * 512,
			"stellwerk_disk_read_time_seconds_total{device=sda}":   13.542,
			"stellwerk_disk_writes_completed_total{device=sda}":    26843,
			"stellwerk_disk_written_bytes_total{device=sda}":       1672048 * 512,
			"stellwerk_disk_write_time_seconds_total{device=sda}":  30.316,
			"stellwerk_disk_io_time_seconds_total{device=sda}":     30.176,
			"stellwerk_disk_reads_completed_total{device=nvme0n1}": 100000,
			"stellwerk_disk_reads_completed_total{device=dm-0}":    30000,
		})
		absent(t, got, "sda1", "nvme0n1p1", "loop0", "ram0", "sr0", "nbd0")
		if len(got) != 3*7 {
			t.Fatalf("got %d samples: %v", len(got), sortedKeys(got))
		}
	})
	t.Run("regex fallback without sysfs", func(t *testing.T) {
		o := fixtureOptions()
		o.SysRoot = t.TempDir()
		got := collectMap(t, newDiskstatsCollector(o.withDefaults()))
		absent(t, got, "sda1", "nvme0n1p1", "loop0", "ram0")
		expect(t, got, map[string]float64{"stellwerk_disk_reads_completed_total{device=sr0}": 0})
	})
}

func TestNetdev(t *testing.T) {
	got := collectMap(t, newNetdevCollector(fixtureOptions().withDefaults()))
	expect(t, got, map[string]float64{
		"stellwerk_network_receive_bytes_total{device=eth0}":     1215645,
		"stellwerk_network_receive_packets_total{device=eth0}":   2751,
		"stellwerk_network_receive_errs_total{device=eth0}":      1,
		"stellwerk_network_receive_drop_total{device=eth0}":      2,
		"stellwerk_network_transmit_bytes_total{device=eth0}":    1782404,
		"stellwerk_network_transmit_packets_total{device=eth0}":  4324,
		"stellwerk_network_transmit_errs_total{device=eth0}":     3,
		"stellwerk_network_transmit_drop_total{device=eth0}":     4,
		"stellwerk_network_receive_bytes_total{device=docker0}":  50000,
		"stellwerk_network_transmit_bytes_total{device=docker0}": 60000,
	})
	absent(t, got, "device=lo", "veth")
	if len(got) != 16 {
		t.Fatalf("got %d samples", len(got))
	}
}

func TestSockets(t *testing.T) {
	got := collectMap(t, newSocketCollector(fixtureOptions().withDefaults()))
	expect(t, got, map[string]float64{
		"stellwerk_tcp_connections{state=listen}":       3,
		"stellwerk_tcp_connections{state=established}":  2,
		"stellwerk_tcp_connections{state=time_wait}":    1,
		"stellwerk_tcp_connections{state=close_wait}":   1,
		"stellwerk_tcp_connections{state=syn_sent}":     0,
		"stellwerk_tcp_connections{state=new_syn_recv}": 0,
		// 3 TCP listeners + unconnected UDP :53 and udp6 :546.
		"stellwerk_listening_sockets": 5,
	})
	if len(got) != 13 {
		t.Fatalf("got %d samples: %v", len(got), sortedKeys(got))
	}
}

func TestScanSocketTableRobust(t *testing.T) {
	in := "header\n   0: 00000000:0016 00000000:0000 ZZ\n short\n   1: 0 0 0A\n   2: 0 0 1"
	var states []int
	if err := scanSocketTable(strings.NewReader(in), func(st int, _ []byte) { states = append(states, st) }); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(states, []int{10, 1}) {
		t.Fatalf("states = %v", states)
	}
}

func TestFilesystem(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	o := fixtureOptions()
	o.StatfsTimeout = 50 * time.Millisecond
	o.Statfs = fakeStatfs(map[string]func() (osutil.FSStats, error){
		// ProtectHome=yes: /home is an inaccessible tmpfs in our namespace.
		"/home": func() (osutil.FSStats, error) {
			return osutil.FSStats{Type: osutil.TmpfsMagic, BlockSize: 4096, Blocks: 1}, nil
		},
		"/mnt/hung": func() (osutil.FSStats, error) { <-release; return osutil.FSStats{}, nil },
		"/dev/shm": func() (osutil.FSStats, error) {
			return osutil.FSStats{Type: osutil.TmpfsMagic, BlockSize: 4096, Blocks: 50, Bfree: 50, Bavail: 50}, nil
		},
		"/broken/fs": func() (osutil.FSStats, error) { return osutil.FSStats{}, errors.New("EIO") },
	})
	c := newFilesystemCollector(o.withDefaults())
	got := collectMap(t, c)
	root := "{device=/dev/mapper/vg0-root,fstype=ext4,mountpoint=/}"
	boot := "{device=/dev/sda1,fstype=ext4,mountpoint=/boot}"
	expect(t, got, map[string]float64{
		"stellwerk_filesystem_size_bytes" + root:                                                 1000 * 4096,
		"stellwerk_filesystem_free_bytes" + root:                                                 400 * 4096,
		"stellwerk_filesystem_avail_bytes" + root:                                                300 * 4096,
		"stellwerk_filesystem_files" + root:                                                      500,
		"stellwerk_filesystem_files_free" + root:                                                 200,
		"stellwerk_filesystem_readonly" + root:                                                   0,
		"stellwerk_filesystem_readonly" + boot:                                                   1,
		"stellwerk_filesystem_size_bytes{device=tmpfs,fstype=tmpfs,mountpoint=/dev/shm}":         50 * 4096,
		"stellwerk_filesystem_size_bytes{device=tmpfs,fstype=tmpfs,mountpoint=/run}":             1000 * 4096,
		"stellwerk_filesystem_size_bytes{device=server:/export,fstype=nfs4,mountpoint=/mnt/nfs}": 1000 * 4096,
	})
	// /data is a bind mount of / (same device), /home is shadowed, /mnt/hung
	// timed out, pseudo filesystems are skipped.
	absent(t, got, "mountpoint=/data", "mountpoint=/home", "mountpoint=/mnt/hung", "/run/user", "/snap", "/var/lib/docker", "fstype=proc", "devtmpfs")
	// 5 filesystems × 6 metrics.
	if len(got) != 5*6 {
		t.Fatalf("got %d samples: %v", len(got), sortedKeys(got))
	}
	// The hung mount is skipped immediately on the next round.
	start := time.Now()
	collectMap(t, c)
	if time.Since(start) > 40*time.Millisecond {
		t.Fatalf("second round waited for the stuck statfs (%s)", time.Since(start))
	}
}

func TestTimesync(t *testing.T) {
	tests := []struct {
		name    string
		fn      func() (bool, time.Duration, error)
		want    map[string]float64
		wantErr bool
	}{
		{"synced", func() (bool, time.Duration, error) { return true, -1500 * time.Microsecond, nil }, map[string]float64{"stellwerk_time_sync_status": 1, "stellwerk_time_offset_seconds": -0.0015}, false},
		{"unsynced", func() (bool, time.Duration, error) { return false, 0, nil }, map[string]float64{"stellwerk_time_sync_status": 0, "stellwerk_time_offset_seconds": 0}, false},
		{"error", func() (bool, time.Duration, error) { return false, 0, errors.New("EPERM") }, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &timesyncCollector{query: tt.fn}
			got := map[string]float64{}
			err := c.Collect(context.Background(), func(s Sample) { got[key(s)] = s.Value })
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v", err)
			}
			if !tt.wantErr {
				expect(t, got, tt.want)
			}
		})
	}
}

func TestSystemd(t *testing.T) {
	const cmd = "systemctl list-units --state=failed --plain --no-legend --no-pager"
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }

	t.Run("counts and caches", func(t *testing.T) {
		r := &fakeRunner{outputs: map[string]fakeResult{cmd: {out: "foo.service loaded failed failed Foo\n● bar.service loaded failed failed Bar\n\n"}}}
		o := fixtureOptions()
		o.Exec, o.Now = r, clock
		c := newSystemdCollector(o.withDefaults())
		expect(t, collectMap(t, c), map[string]float64{"stellwerk_systemd_units_failed": 2})
		now = now.Add(30 * time.Second)
		expect(t, collectMap(t, c), map[string]float64{"stellwerk_systemd_units_failed": 2})
		if r.callCount() != 1 {
			t.Fatalf("systemctl ran %d times within 60 s", r.callCount())
		}
		now = now.Add(31 * time.Second)
		collectMap(t, c)
		if r.callCount() != 2 {
			t.Fatalf("systemctl not re-run after 60 s")
		}
	})
	t.Run("none failed", func(t *testing.T) {
		r := &fakeRunner{outputs: map[string]fakeResult{cmd: {out: ""}}}
		o := fixtureOptions()
		o.Exec = r
		expect(t, collectMap(t, newSystemdCollector(o.withDefaults())), map[string]float64{"stellwerk_systemd_units_failed": 0})
	})
	t.Run("error drops stale value", func(t *testing.T) {
		r := &fakeRunner{outputs: map[string]fakeResult{cmd: {out: "a.service x\n"}}}
		o := fixtureOptions()
		o.Exec, o.Now = r, clock
		c := newSystemdCollector(o.withDefaults())
		collectMap(t, c)
		r.outputs[cmd] = fakeResult{err: errors.New("dbus down")}
		now = now.Add(2 * time.Minute)
		var n int
		if err := c.Collect(context.Background(), func(Sample) { n++ }); err == nil || n != 0 {
			t.Fatalf("err = %v, samples = %d", err, n)
		}
	})
	t.Run("not systemd", func(t *testing.T) {
		r := &fakeRunner{}
		o := fixtureOptions()
		o.Exec, o.RootFS = r, t.TempDir()
		if got := collectMap(t, newSystemdCollector(o.withDefaults())); len(got) != 0 || r.callCount() != 0 {
			t.Fatalf("got %v, calls %d", got, r.callCount())
		}
	})
}

func TestSelfCollector(t *testing.T) {
	got := collectMap(t, newSelfCollector(fixtureOptions().withDefaults()))
	expect(t, got, map[string]float64{
		"stellwerk_agent_cpu_seconds_total": 20,
		"stellwerk_agent_rss_bytes":         float64(3000 * os.Getpagesize()),
	})
	if got["stellwerk_agent_goroutines"] < 1 {
		t.Fatalf("goroutines = %v", got["stellwerk_agent_goroutines"])
	}
}

func TestParsePIDStat(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool
		comm string
	}{
		{"normal", "1 (systemd) S 0 1 1 0 -1 4194560 1 2 3 4 340 412 0 0 20 0 1 0 4 172457984 3221 1", true, "systemd"},
		{"parens and spaces", "7 (a) (b c)) R 0 1 1 0 -1 0 1 2 3 4 5 6 0 0 20 0 1 0 4 1 2 1", true, "a) (b c)"},
		{"truncated", "1 (x) S 0 1", false, ""},
		{"no parens", "1 x S 0 1 1 0 -1 4194560 1 2 3 4 340 412 0 0 20 0 1 0 4 172457984 3221", false, ""},
		{"non numeric", "1 (x) S 0 1 1 0 -1 zz 1 2 3 4 340 412 0 0 20 0 1 0 4 172457984 3221 1", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, ok := parsePIDStat([]byte(tt.in))
			if ok != tt.ok || (ok && st.comm != tt.comm) {
				t.Fatalf("got %+v, %v", st, ok)
			}
		})
	}
}

func TestDefaultCollectorsOnFixture(t *testing.T) {
	o := fixtureOptions()
	o.Exec = &fakeRunner{outputs: map[string]fakeResult{
		"systemctl list-units --state=failed --plain --no-legend --no-pager": {out: "x.service loaded failed failed X\n"},
	}}
	cs := DefaultCollectors(o)
	if FindProbeCollector(cs) == nil {
		t.Fatal("no probe collector")
	}
	samples, err := CollectAll(context.Background(), cs)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, s := range samples {
		names[s.Name] = true
		if _, ok := normalize(s); !ok {
			t.Errorf("collector emitted invalid sample %s", key(s))
		}
	}
	for n := range names {
		if !slices.Contains(MetricNames, n) {
			t.Errorf("metric %s is not in the documented contract (MetricNames)", n)
		}
	}
	for _, n := range MetricNames {
		if strings.HasPrefix(n, "stellwerk_probe_") || n == droppedSeriesMetric {
			continue // need probes / drops
		}
		if !names[n] {
			t.Errorf("fixture produced no %s", n)
		}
	}
	for _, c := range cs {
		if cl, ok := c.(io.Closer); ok {
			_ = cl.Close()
		}
	}
}
