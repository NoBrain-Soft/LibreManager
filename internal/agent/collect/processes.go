package collect

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Process snapshot limits.
const (
	maxProcessScan = 32768
	maxTopN        = 100
	maxCmdline     = 256
	pfKthread      = 0x00200000 // PF_KTHREAD in /proc/<pid>/stat flags
)

// pidStat is the subset of /proc/<pid>/stat we use.
type pidStat struct {
	comm      string
	state     string
	flags     uint64
	utime     uint64
	stime     uint64
	starttime uint64 // ticks after boot
	rssPages  uint64
}

// parsePIDStat parses /proc/<pid>/stat. comm may contain spaces and
// parentheses, so fields are located from the last ')'.
func parsePIDStat(data []byte) (pidStat, bool) {
	open := bytes.IndexByte(data, '(')
	closeIdx := bytes.LastIndexByte(data, ')')
	if open < 0 || closeIdx < open {
		return pidStat{}, false
	}
	st := pidStat{comm: string(data[open+1 : closeIdx])}
	f := bytes.Fields(data[closeIdx+1:])
	// f[0] is field 3 (state); field N is f[N-3].
	if len(f) < 22 {
		return pidStat{}, false
	}
	st.state = string(f[0])
	var ok [5]bool
	st.flags, ok[0] = parseUint(f[6])
	st.utime, ok[1] = parseUint(f[11])
	st.stime, ok[2] = parseUint(f[12])
	st.starttime, ok[3] = parseUint(f[19])
	st.rssPages, ok[4] = parseUint(f[21])
	for _, o := range ok {
		if !o {
			return pidStat{}, false
		}
	}
	return st, true
}

type procKey struct {
	pid   int32
	start uint64 // distinguishes PID reuse
}

// ProcSampler produces top-N process snapshots. CPU percentages are computed
// from the CPU time used between two Sample calls (like top); on the first
// call they are lifetime averages (like ps). Percentages are per core, so a
// busy multi-threaded process can exceed 100.
type ProcSampler struct {
	// ProcRoot defaults to "/proc".
	ProcRoot string
	// PasswdFile maps uids to names (default "/etc/passwd").
	PasswdFile string
	// Now overrides time.Now (tests).
	Now func() time.Time

	mu       sync.Mutex
	prev     map[procKey]uint64 // cpu ticks
	prevAt   time.Time
	users    map[uint32]string
	usersMod time.Time
	pageSize uint64
}

// NewProcSampler returns a sampler reading procRoot.
func NewProcSampler(procRoot string) *ProcSampler {
	return &ProcSampler{ProcRoot: procRoot}
}

type procEntry struct {
	key   procKey
	st    pidStat
	ticks uint64
	cpu   float64
	rss   uint64
}

// Sample returns the processes among the top n by CPU and the top n by RSS
// (at most 2n entries, ordered by CPU then RSS), plus the total process
// count. n is clamped to [1, 100].
func (s *ProcSampler) Sample(ctx context.Context, n int) (*agentv1.ProcessSnapshot, error) {
	return s.sample(ctx, "/proc", n)
}

func (s *ProcSampler) sample(ctx context.Context, defaultRoot string, n int) (*agentv1.ProcessSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ProcRoot == "" {
		s.ProcRoot = defaultRoot
	}
	if s.PasswdFile == "" {
		s.PasswdFile = "/etc/passwd"
	}
	if s.pageSize == 0 {
		s.pageSize = uint64(os.Getpagesize()) //nolint:gosec // page size is positive
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	n = max(1, min(n, maxTopN))

	uptime, err := readUptime(s.ProcRoot)
	if err != nil {
		return nil, err
	}
	var procs []procEntry
	err = eachPID(s.ProcRoot, func(pid int32) bool {
		if len(procs) >= maxProcessScan || ctx.Err() != nil {
			return false
		}
		data, err := osutil.ReadFileLimit(filepath.Join(s.ProcRoot, strconv.Itoa(int(pid)), "stat"), 4096)
		if err != nil {
			return true // process exited or hidden
		}
		st, ok := parsePIDStat(data)
		if !ok {
			return true
		}
		procs = append(procs, procEntry{key: procKey{pid, st.starttime}, st: st, ticks: st.utime + st.stime, rss: st.rssPages * s.pageSize})
		return true
	})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("process scan: %w", err)
	}

	elapsed := now.Sub(s.prevAt).Seconds()
	havePrev := s.prev != nil && elapsed > 0
	next := make(map[procKey]uint64, len(procs))
	for i := range procs {
		p := &procs[i]
		next[p.key] = p.ticks
		cpuSec := float64(p.ticks) / userHZ
		switch prevTicks, ok := s.prev[p.key]; {
		case havePrev && ok && prevTicks <= p.ticks:
			p.cpu = float64(p.ticks-prevTicks) / userHZ / elapsed * 100
		case havePrev:
			// Started since the last sample: all of its CPU time was used
			// within the interval.
			p.cpu = cpuSec / elapsed * 100
		default:
			age := uptime - float64(p.st.starttime)/userHZ
			if age > 0 {
				p.cpu = cpuSec / age * 100
			}
		}
	}
	s.prev, s.prevAt = next, now

	selected := topProcesses(procs, n)
	s.refreshUsers()
	snap := &agentv1.ProcessSnapshot{TimestampMs: now.UnixMilli(), Total: uint32(len(procs))} //nolint:gosec // bounded by maxProcessScan
	for _, p := range selected {
		snap.Top = append(snap.Top, s.processInfo(p))
	}
	return snap, nil
}

// topProcesses returns the union of the top n by CPU and the top n by RSS.
func topProcesses(procs []procEntry, n int) []procEntry {
	byCPU := func(a, b procEntry) int {
		return cmp.Or(cmp.Compare(b.cpu, a.cpu), cmp.Compare(b.rss, a.rss), cmp.Compare(a.key.pid, b.key.pid))
	}
	byRSS := func(a, b procEntry) int {
		return cmp.Or(cmp.Compare(b.rss, a.rss), cmp.Compare(b.cpu, a.cpu), cmp.Compare(a.key.pid, b.key.pid))
	}
	seen := make(map[int32]bool, 2*n)
	var out []procEntry
	slices.SortFunc(procs, byRSS)
	for _, p := range procs[:min(n, len(procs))] {
		seen[p.key.pid] = true
		out = append(out, p)
	}
	slices.SortFunc(procs, byCPU)
	for _, p := range procs[:min(n, len(procs))] {
		if !seen[p.key.pid] {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, byCPU)
	return out
}

func (s *ProcSampler) processInfo(p procEntry) *agentv1.ProcessInfo {
	dir := filepath.Join(s.ProcRoot, strconv.Itoa(int(p.key.pid)))
	info := &agentv1.ProcessInfo{
		Pid:        p.key.pid,
		Name:       osutil.Clean(p.st.comm, 64),
		CpuPercent: float64(int64(p.cpu*100+0.5)) / 100,
		RssBytes:   p.rss,
		State:      osutil.Clean(p.st.state, 4),
	}
	if uid, ok := readUID(dir); ok {
		if name, ok := s.users[uid]; ok {
			info.User = name
		} else {
			info.User = strconv.FormatUint(uint64(uid), 10)
		}
	}
	if p.st.flags&pfKthread != 0 {
		info.Cmdline = "[" + info.Name + "]"
		return info
	}
	if data, err := osutil.ReadFileLimit(filepath.Join(dir, "cmdline"), 64<<10); err == nil {
		data = bytes.TrimRight(data, "\x00")
		data = bytes.ReplaceAll(data, []byte{0}, []byte{' '})
		info.Cmdline = osutil.Clean(string(data), maxCmdline)
	}
	if info.Cmdline == "" {
		info.Cmdline = "[" + info.Name + "]"
	}
	return info
}

// readUID returns the real uid from /proc/<pid>/status.
func readUID(dir string) (uint32, bool) {
	data, err := osutil.ReadFileLimit(filepath.Join(dir, "status"), 16<<10)
	if err != nil {
		return 0, false
	}
	var uid uint32
	found := false
	eachLine(data, func(line []byte) {
		if found {
			return
		}
		if rest, ok := bytes.CutPrefix(line, []byte("Uid:")); ok {
			if f := bytes.Fields(rest); len(f) > 0 {
				if v, err := strconv.ParseUint(string(f[0]), 10, 32); err == nil {
					uid, found = uint32(v), true
				}
			}
		}
	})
	return uid, found
}

// refreshUsers reloads the uid -> name map when the passwd file changes.
func (s *ProcSampler) refreshUsers() {
	fi, err := os.Stat(s.PasswdFile)
	if err != nil {
		return
	}
	if s.users != nil && fi.ModTime().Equal(s.usersMod) {
		return
	}
	data, err := osutil.ReadFileLimit(s.PasswdFile, 8<<20)
	if err != nil {
		return
	}
	users := make(map[uint32]string)
	for _, e := range osutil.ParsePasswd(data, 65536) {
		if _, dup := users[e.UID]; !dup {
			users[e.UID] = osutil.Clean(e.Name, 64)
		}
	}
	s.users, s.usersMod = users, fi.ModTime()
}

// TopProcesses returns a process snapshot. With prev == nil it performs a
// one-shot sample whose CPU percentages are lifetime averages; with a
// sampler it delegates to prev.Sample (procRoot is used when prev has none).
func TopProcesses(ctx context.Context, procRoot string, n int, prev *ProcSampler) (*agentv1.ProcessSnapshot, error) {
	if prev == nil {
		prev = NewProcSampler(procRoot)
	}
	if procRoot == "" {
		procRoot = "/proc"
	}
	return prev.sample(ctx, procRoot, n)
}
