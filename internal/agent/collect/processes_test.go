package collect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTopProcessesOneShot(t *testing.T) {
	procRoot := filepath.Join(fixture, "proc")
	s := NewProcSampler(procRoot)
	s.PasswdFile = filepath.Join(fixture, "etc", "passwd")
	snap, err := s.Sample(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if snap.GetTotal() != 6 {
		t.Fatalf("total = %d", snap.GetTotal())
	}
	// Top 2 by RSS: java (500000 pages), postgres (80000). Top 2 by CPU
	// (lifetime): "my (weird) proc" (100 s over ~10000 s), java.
	var pids []int32
	for _, p := range snap.GetTop() {
		pids = append(pids, p.GetPid())
	}
	if fmt.Sprint(pids) != "[4321 1234 5555]" {
		t.Fatalf("top pids = %v", pids)
	}
	weird, java, pg := snap.GetTop()[0], snap.GetTop()[1], snap.GetTop()[2]
	if weird.GetName() != "my (weird) proc" || weird.GetUser() != "bob" || weird.GetState() != "R" || weird.GetCmdline() != "./weird" {
		t.Errorf("weird = %v", weird)
	}
	// 10000 ticks = 100 s over (100000 - 90000) s of lifetime = 1 %.
	if weird.GetCpuPercent() != 1 {
		t.Errorf("weird cpu = %v", weird.GetCpuPercent())
	}
	if java.GetUser() != "alice" || java.GetCmdline() != "/usr/bin/java -Xmx2g -jar app.jar" || java.GetRssBytes() != 500000*uint64(os.Getpagesize()) {
		t.Errorf("java = %v", java)
	}
	if pg.GetUser() != "4242" {
		t.Errorf("unknown uid not rendered numerically: %q", pg.GetUser())
	}
}

func TestTopProcessesKernelThread(t *testing.T) {
	snap, err := TopProcesses(context.Background(), filepath.Join(fixture, "proc"), 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range snap.GetTop() {
		if p.GetPid() == 2 && p.GetCmdline() != "[kthreadd]" {
			t.Fatalf("kthread cmdline = %q", p.GetCmdline())
		}
	}
	if len(snap.GetTop()) != 6 {
		t.Fatalf("expected all 6 processes, got %d", len(snap.GetTop()))
	}
}

func writeProc(t *testing.T, root string, pid int, comm string, utime, start uint64, cmdline string) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (%s) S 1 1 1 0 -1 4194560 0 0 0 0 %d 0 0 0 20 0 1 0 %d 1000 10 0\n", pid, comm, utime, start)
	for name, content := range map[string]string{"stat": stat, "cmdline": cmdline, "status": "Uid:\t0\t0\t0\t0\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProcSamplerDelta(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "uptime"), []byte("1000.00 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeProc(t, root, 10, "busy", 0, 100, "busy\x00")
	writeProc(t, root, 11, "idle", 50000, 100, "idle\x00")
	now := time.Unix(1_800_000_000, 0)
	s := &ProcSampler{ProcRoot: root, PasswdFile: filepath.Join(root, "passwd"), Now: func() time.Time { return now }}
	if _, err := s.Sample(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
	// 10 s later: busy used 5 s of CPU (500 ticks) = 50 %, idle none.
	now = now.Add(10 * time.Second)
	writeProc(t, root, 10, "busy", 500, 100, "busy\x00")
	// PID 12 started during the interval with 2 s of CPU = 20 %.
	writeProc(t, root, 12, "new", 200, 99000, "new\x00")
	// PID 11 was replaced by a different process (PID reuse).
	writeProc(t, root, 11, "reused", 100, 99500, "reused\x00")
	snap, err := s.Sample(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, p := range snap.GetTop() {
		got[p.GetName()] = p.GetCpuPercent()
	}
	want := map[string]float64{"busy": 50, "new": 20, "reused": 10}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s cpu = %v, want %v (all: %v)", k, got[k], v, got)
		}
	}
	if snap.GetTop()[0].GetName() != "busy" {
		t.Errorf("not ordered by cpu: %v", snap.GetTop())
	}
}

func TestProcSamplerContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := TopProcesses(ctx, filepath.Join(fixture, "proc"), 5, nil); err == nil {
		t.Fatal("expected context error")
	}
}
