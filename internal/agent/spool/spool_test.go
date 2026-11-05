package spool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

var t0 = time.UnixMilli(1_800_000_000_000)

func batch(ts time.Time, n int) *agentv1.MetricsBatch {
	b := &agentv1.MetricsBatch{TimestampMs: ts.UnixMilli(), Replay: true}
	for i := range n {
		id := uint32(i + 1) //nolint:gosec // test
		b.Defs = append(b.Defs, &agentv1.SeriesDef{Id: id, Name: "stellwerk_test", Labels: []*agentv1.Label{{Name: "i", Value: fmt.Sprint(i)}}})
		b.Points = append(b.Points, &agentv1.Point{SeriesId: id, Value: float64(i)})
	}
	return b
}

func openAt(t *testing.T, dir string, maxBytes int64, maxAge time.Duration, now *time.Time) *Spool {
	t.Helper()
	s, err := Open(dir, maxBytes, maxAge)
	if err != nil {
		t.Fatal(err)
	}
	if now != nil {
		s.now = func() time.Time { return *now }
	}
	return s
}

// drainAll returns the timestamps of all drained batches.
func drainAll(t *testing.T, s *Spool) []int64 {
	t.Helper()
	var got []int64
	if err := s.Drain(context.Background(), func(b *agentv1.MetricsBatch) error {
		if !b.GetReplay() {
			t.Error("drained batch is not marked replay")
		}
		got = append(got, b.GetTimestampMs())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func appendN(t *testing.T, s *Spool, from, n int) {
	t.Helper()
	for i := from; i < from+n; i++ {
		if err := s.Append(batch(t0.Add(time.Duration(i)*time.Second), 10)); err != nil {
			t.Fatal(err)
		}
	}
}

func want(from, n int) []int64 {
	out := make([]int64, 0, n)
	for i := from; i < from+n; i++ {
		out = append(out, t0.Add(time.Duration(i)*time.Second).UnixMilli())
	}
	return out
}

func eq(a, b []int64) bool { return fmt.Sprint(a) == fmt.Sprint(b) }

func TestAppendDrainOrder(t *testing.T) {
	now := t0
	s := openAt(t, t.TempDir(), 1<<20, time.Hour, &now)
	defer func() { _ = s.Close() }()
	appendN(t, s, 0, 100)
	if s.Len() != 100 {
		t.Fatalf("Len = %d", s.Len())
	}
	if got := drainAll(t, s); !eq(got, want(0, 100)) {
		t.Fatalf("drained %v", got)
	}
	if s.Len() != 0 {
		t.Fatalf("Len after drain = %d", s.Len())
	}
	// Spool keeps working after a full drain.
	appendN(t, s, 100, 3)
	if got := drainAll(t, s); !eq(got, want(100, 3)) {
		t.Fatalf("second drain %v", got)
	}
}

func TestDrainStopsAtFirstError(t *testing.T) {
	now := t0
	s := openAt(t, t.TempDir(), 1<<20, time.Hour, &now)
	defer func() { _ = s.Close() }()
	appendN(t, s, 0, 10)
	sendErr := errors.New("stream broken")
	var sent []int64
	err := s.Drain(context.Background(), func(b *agentv1.MetricsBatch) error {
		if len(sent) == 4 {
			return sendErr
		}
		sent = append(sent, b.GetTimestampMs())
		return nil
	})
	if !errors.Is(err, sendErr) {
		t.Fatalf("err = %v", err)
	}
	if !eq(sent, want(0, 4)) || s.Len() != 6 {
		t.Fatalf("sent %v, Len %d", sent, s.Len())
	}
	// The failed record is retried first.
	if got := drainAll(t, s); !eq(got, want(4, 6)) {
		t.Fatalf("resumed drain %v", got)
	}
}

func TestDrainContextCanceled(t *testing.T) {
	now := t0
	s := openAt(t, t.TempDir(), 1<<20, time.Hour, &now)
	defer func() { _ = s.Close() }()
	appendN(t, s, 0, 5)
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	err := s.Drain(ctx, func(*agentv1.MetricsBatch) error {
		n++
		if n == 2 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || s.Len() != 3 {
		t.Fatalf("err = %v, Len = %d", err, s.Len())
	}
}

func TestPersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	now := t0
	s := openAt(t, dir, 1<<20, time.Hour, &now)
	appendN(t, s, 0, 50)
	calls := 0
	_ = s.Drain(context.Background(), func(*agentv1.MetricsBatch) error {
		calls++
		if calls > 20 {
			return errors.New("offline")
		}
		return nil
	})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openAt(t, dir, 1<<20, time.Hour, &now)
	defer func() { _ = s.Close() }()
	if s.Len() != 30 {
		t.Fatalf("Len after reopen = %d, want 30", s.Len())
	}
	if got := drainAll(t, s); !eq(got, want(20, 30)) {
		t.Fatalf("drained %v", got)
	}
}

func TestRestartAfterFullDrainKeepsNewData(t *testing.T) {
	dir := t.TempDir()
	now := t0
	s := openAt(t, dir, 1<<20, time.Hour, &now)
	appendN(t, s, 0, 5)
	drainAll(t, s)
	_ = s.Close()
	// Reopen with an empty spool, append, restart again: the stale cursor
	// must not cause the new data to be discarded.
	s = openAt(t, dir, 1<<20, time.Hour, &now)
	appendN(t, s, 5, 2)
	_ = s.Close()
	s = openAt(t, dir, 1<<20, time.Hour, &now)
	defer func() { _ = s.Close() }()
	if got := drainAll(t, s); !eq(got, want(5, 2)) {
		t.Fatalf("drained %v", got)
	}
}

func TestMaxBytes(t *testing.T) {
	dir := t.TempDir()
	now := t0
	const maxBytes = 64 << 10
	s := openAt(t, dir, maxBytes, time.Hour, &now)
	defer func() { _ = s.Close() }()
	appendN(t, s, 0, 2000)
	st := s.Stats()
	if st.Bytes > maxBytes {
		t.Fatalf("spool uses %d bytes > %d", st.Bytes, maxBytes)
	}
	if st.Dropped == 0 || st.Records == 0 || st.Records+int(st.Dropped) != 2000 { //nolint:gosec // test
		t.Fatalf("stats %+v", st)
	}
	var onDisk int64
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), segPrefix) {
			fi, _ := e.Info()
			onDisk += fi.Size()
		}
	}
	if onDisk != st.Bytes {
		t.Fatalf("on disk %d != accounted %d", onDisk, st.Bytes)
	}
	// The newest records survive, oldest first.
	got := drainAll(t, s)
	if !eq(got, want(2000-len(got), len(got))) {
		t.Fatalf("drained wrong records: first %d last %d", got[0], got[len(got)-1])
	}
}

func TestMaxAge(t *testing.T) {
	dir := t.TempDir()
	now := t0
	s := openAt(t, dir, 1<<20, time.Hour, &now)
	defer func() { _ = s.Close() }()
	// 30 records spanning 2 h of batch timestamps (every 4 min).
	for i := range 30 {
		if err := s.Append(batch(t0.Add(time.Duration(i)*4*time.Minute), 10)); err != nil {
			t.Fatal(err)
		}
	}
	now = t0.Add(2 * time.Hour)
	var got []int64
	if err := s.Drain(context.Background(), func(b *agentv1.MetricsBatch) error {
		got = append(got, b.GetTimestampMs())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cutoff := now.Add(-time.Hour).UnixMilli()
	for _, ts := range got {
		if ts < cutoff {
			t.Fatalf("expired record %d drained (cutoff %d)", ts, cutoff)
		}
	}
	if len(got) != 15 || s.Stats().Dropped != 15 {
		t.Fatalf("drained %d, dropped %d", len(got), s.Stats().Dropped)
	}
}

func TestExpiredSegmentsDroppedOnOpen(t *testing.T) {
	dir := t.TempDir()
	now := t0
	s := openAt(t, dir, 64<<10, time.Hour, &now)
	appendN(t, s, 0, 500) // several segments
	_ = s.Close()
	now = t0.Add(48 * time.Hour)
	s, err := Open(dir, 64<<10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	s.now = func() time.Time { return now }
	if got := drainAll(t, s); len(got) != 0 {
		t.Fatalf("drained %d expired records", len(got))
	}
}

func segments(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, segPrefix+"*"+segSuffix))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestTornWrite(t *testing.T) {
	dir := t.TempDir()
	now := t0
	s := openAt(t, dir, 1<<20, time.Hour, &now)
	appendN(t, s, 0, 5)
	_ = s.Close()
	seg := segments(t, dir)[0]
	fi, _ := os.Stat(seg)
	// Simulate power loss in the middle of the last record.
	if err := os.Truncate(seg, fi.Size()-7); err != nil {
		t.Fatal(err)
	}
	s = openAt(t, dir, 1<<20, time.Hour, &now)
	defer func() { _ = s.Close() }()
	if s.Len() != 4 {
		t.Fatalf("Len = %d, want 4", s.Len())
	}
	// The torn tail is truncated so new appends produce a valid file.
	appendN(t, s, 10, 1)
	got := drainAll(t, s)
	if !eq(got, append(want(0, 4), want(10, 1)...)) {
		t.Fatalf("drained %v", got)
	}
}

func TestCorruptRecordSkipped(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(data []byte, recStarts []int)
		want    []int64
	}{
		{"payload bit flip", func(d []byte, r []int) { d[r[2]+headerSize+5] ^= 0xff }, append(want(0, 2), want(3, 2)...)},
		{"bad magic", func(d []byte, r []int) { d[r[1]] = 'X' }, append(want(0, 1), want(2, 3)...)},
		{"huge length", func(d []byte, r []int) { copy(d[r[3]+4:], []byte{0xff, 0xff, 0xff, 0x7f}) }, append(want(0, 3), want(4, 1)...)},
		{"garbage between records", nil, want(0, 5)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			now := t0
			s := openAt(t, dir, 1<<20, time.Hour, &now)
			appendN(t, s, 0, 5)
			_ = s.Close()
			seg := segments(t, dir)[0]
			data, _ := os.ReadFile(seg)
			recs, _, _ := scanRecords(data)
			starts := make([]int, len(recs))
			for i, r := range recs {
				starts[i] = int(r.off)
			}
			if tt.corrupt != nil {
				tt.corrupt(data, starts)
			} else {
				// Insert garbage before record 2.
				data = append(data[:starts[2]:starts[2]], append([]byte("garbage!garbage!SWS"), data[starts[2]:]...)...)
			}
			if err := os.WriteFile(seg, data, 0o600); err != nil {
				t.Fatal(err)
			}
			s = openAt(t, dir, 1<<20, time.Hour, &now)
			defer func() { _ = s.Close() }()
			if got := drainAll(t, s); !eq(got, tt.want) {
				t.Fatalf("drained %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCorruptCursorAndJunkFiles(t *testing.T) {
	dir := t.TempDir()
	now := t0
	s := openAt(t, dir, 1<<20, time.Hour, &now)
	appendN(t, s, 0, 3)
	_ = s.Close()
	for name, content := range map[string]string{
		cursorFile:                        "garbage",
		"seg-notanumber.spool":            "x",
		"README":                          "not a segment",
		segName(999):                      "\x00\x01\x02 complete garbage",
		segName(1000) + ".tmp":            "x",
		filepath.Join("subdir.spool", ""): "",
	} {
		p := filepath.Join(dir, name)
		if strings.HasSuffix(name, "/") || name == "subdir.spool" {
			_ = os.Mkdir(p, 0o700)
			continue
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s = openAt(t, dir, 1<<20, time.Hour, &now)
	defer func() { _ = s.Close() }()
	if got := drainAll(t, s); !eq(got, want(0, 3)) {
		t.Fatalf("drained %v", got)
	}
}

func TestPermissionsAndLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	appendN(t, s, 0, 1)
	fi, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		info, _ := e.Info()
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", e.Name(), info.Mode().Perm())
		}
	}
	if _, err := Open(dir, 0, 0); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open: %v", err)
	}
	if s.maxBytes != DefaultMaxBytes || s.maxAge != DefaultMaxAge {
		t.Fatalf("defaults not applied: %d %s", s.maxBytes, s.maxAge)
	}
}

func TestSymlinkedSegmentNotFollowed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(target, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, segName(1))); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, 1<<20, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	appendN(t, s, 0, 2)
	if data, _ := os.ReadFile(target); string(data) != "precious" {
		t.Fatalf("symlink target modified: %q", data)
	}
}

func TestClosed(t *testing.T) {
	s := openAt(t, t.TempDir(), 0, 0, nil)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("double close:", err)
	}
	if err := s.Append(batch(t0, 1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Append: %v", err)
	}
	if err := s.Drain(context.Background(), func(*agentv1.MetricsBatch) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("Drain: %v", err)
	}
}

func TestTooLargeAndNonReplay(t *testing.T) {
	now := t0
	s := openAt(t, t.TempDir(), minMaxBytes, time.Hour, &now)
	defer func() { _ = s.Close() }()
	if err := s.Append(batch(t0, 2000)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	live := batch(t0, 1)
	live.Replay = false
	if err := s.Append(live); err != nil {
		t.Fatal(err)
	}
	if live.Replay {
		t.Fatal("caller's batch was modified")
	}
	if got := drainAll(t, s); len(got) != 1 {
		t.Fatalf("drained %v", got)
	}
}

func TestConcurrentAppendDuringDrain(t *testing.T) {
	now := t0
	s := openAt(t, t.TempDir(), 64<<10, time.Hour, &now)
	defer func() { _ = s.Close() }()
	appendN(t, s, 0, 50)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1000; i < 1500; i++ {
			_ = s.Append(batch(t0.Add(time.Duration(i)*time.Second), 10))
		}
	}()
	var last int64
	err := s.Drain(context.Background(), func(b *agentv1.MetricsBatch) error {
		if b.GetTimestampMs() <= last {
			t.Errorf("out of order: %d after %d", b.GetTimestampMs(), last)
		}
		last = b.GetTimestampMs()
		time.Sleep(50 * time.Microsecond)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if err := s.Drain(context.Background(), func(*agentv1.MetricsBatch) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 0 {
		t.Fatalf("Len = %d", s.Len())
	}
	if s.Stats().Bytes > 64<<10 {
		t.Fatalf("over budget: %d", s.Stats().Bytes)
	}
}

func TestConcurrentDrainRejected(t *testing.T) {
	now := t0
	s := openAt(t, t.TempDir(), 1<<20, time.Hour, &now)
	defer func() { _ = s.Close() }()
	appendN(t, s, 0, 2)
	err := s.Drain(context.Background(), func(*agentv1.MetricsBatch) error {
		if err := s.Drain(context.Background(), func(*agentv1.MetricsBatch) error { return nil }); !errors.Is(err, ErrBusy) {
			t.Errorf("nested drain: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func FuzzScanRecords(f *testing.F) {
	f.Add(encodeRecord(1, []byte("hello")))
	f.Add(append(encodeRecord(1, []byte("a")), []byte("SWSLtrailing")...))
	f.Add([]byte("SWSL\xff\xff\xff\xff"))
	f.Fuzz(func(t *testing.T, data []byte) {
		recs, end, _ := scanRecords(data)
		if end > int64(len(data)) {
			t.Fatalf("validEnd %d beyond data %d", end, len(data))
		}
		for _, r := range recs {
			if r.off < 0 || r.off+headerSize+int64(r.n) > int64(len(data)) {
				t.Fatalf("record out of bounds: %+v", r)
			}
		}
	})
}

func FuzzOpenCorruptSegment(f *testing.F) {
	f.Add(encodeRecord(1, []byte("x")))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, segName(1)), data, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Open(dir, 1<<20, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		_ = s.Drain(context.Background(), func(*agentv1.MetricsBatch) error { return nil })
		if err := s.Append(batch(time.Now(), 1)); err != nil {
			t.Fatal(err)
		}
	})
}
