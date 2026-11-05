package osutil

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// FSStats is the subset of statfs(2) the agent reports.
type FSStats struct {
	// Type is f_type (filesystem magic).
	Type int64
	// BlockSize is f_frsize (or f_bsize when f_frsize is 0).
	BlockSize uint64
	Blocks    uint64
	Bfree     uint64
	Bavail    uint64
	Files     uint64
	Ffree     uint64
}

// Filesystem magic numbers (linux/magic.h) used to detect shadowed mounts.
const (
	TmpfsMagic = 0x01021994
	RamfsMagic = 0x858458f6
)

// StatfsFunc is statfs(2); injectable for tests.
type StatfsFunc func(path string) (FSStats, error)

// ErrStatfsTimeout is returned for a mount whose statfs did not return in
// time (typically a hung network filesystem).
var ErrStatfsTimeout = errors.New("osutil: statfs timed out")

// ErrStatfsStuck is returned while an earlier statfs on the same path is
// still blocked.
var ErrStatfsStuck = errors.New("osutil: statfs still blocked from an earlier call")

// GuardedStatfs runs statfs in a goroutine with a timeout so a dead NFS
// server cannot block collection. A path whose call timed out is skipped
// until that call returns, so at most one goroutine per path is ever stuck.
type GuardedStatfs struct {
	Fn      StatfsFunc
	Timeout time.Duration

	mu    sync.Mutex
	stuck map[string]bool
}

// Statfs calls Fn(path) with the configured timeout.
func (g *GuardedStatfs) Statfs(ctx context.Context, path string) (FSStats, error) {
	fn := g.Fn
	if fn == nil {
		fn = Statfs
	}
	timeout := g.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	g.mu.Lock()
	if g.stuck[path] {
		g.mu.Unlock()
		return FSStats{}, fmt.Errorf("%s: %w", path, ErrStatfsStuck)
	}
	if g.stuck == nil {
		g.stuck = make(map[string]bool)
	}
	g.stuck[path] = true
	g.mu.Unlock()

	type result struct {
		st  FSStats
		err error
	}
	ch := make(chan result, 1)
	go func() {
		st, err := fn(path)
		g.mu.Lock()
		delete(g.stuck, path)
		g.mu.Unlock()
		ch <- result{st, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.st, r.err
	case <-timer.C:
		return FSStats{}, fmt.Errorf("%s: %w", path, ErrStatfsTimeout)
	case <-ctx.Done():
		return FSStats{}, fmt.Errorf("osutil: statfs %s: %w", path, ctx.Err())
	}
}
