package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nobrain-soft/libremanager/internal/agent/collect"
	"github.com/nobrain-soft/libremanager/internal/agent/inventory"
	"github.com/nobrain-soft/libremanager/internal/agent/spool"
	"google.golang.org/protobuf/proto"
)

// Budget (CLAUDE.md, G7).
const (
	budgetRSSBytes   = 30 << 20
	budgetCPUPercent = 1.0
	nominalInterval  = 15 * time.Second
)

type benchResult struct {
	Rounds           int     `json:"rounds"`
	Samples          int     `json:"samples_per_round"`
	BatchBytes       int     `json:"live_batch_bytes"`
	InventoryBytes   int     `json:"inventory_bytes"`
	CPUSeconds       float64 `json:"cpu_seconds"`
	CPUPercentAt15s  float64 `json:"cpu_percent_at_15s"`
	PeakRSSBytes     int64   `json:"peak_rss_bytes"`
	WithinBudget     bool    `json:"within_budget"`
	BudgetRSSBytes   int64   `json:"budget_rss_bytes"`
	BudgetCPUPercent float64 `json:"budget_cpu_percent"`
}

func cpuSeconds() float64 {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return float64(ru.Utime.Sec+ru.Stime.Sec) + float64(ru.Utime.Usec+ru.Stime.Usec)/1e6
}

func peakRSS() int64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "VmHWM:" {
			kb, _ := strconv.ParseInt(f[1], 10, 64)
			return kb * 1024
		}
	}
	return 0
}

// bench runs the real collection pipeline (collectors, encoder, process
// sampler, inventory, spool) at a fast cadence and normalizes the CPU cost
// to the default 15 s interval. It exits non-zero when over budget.
func bench(ctx context.Context, dur, interval time.Duration) error {
	debug.SetGCPercent(50) // same as production defaults would be tuned
	dir, err := os.MkdirTemp("", "stellwerk-bench")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	sp, err := spool.Open(dir, 10<<20, time.Hour)
	if err != nil {
		return err
	}
	defer sp.Close()
	cs := collect.DefaultCollectors(collect.Options{})
	enc := collect.NewEncoder(10000)
	ps := collect.NewProcSampler("/proc")
	inv := &inventory.Collector{}

	res := benchResult{BudgetRSSBytes: budgetRSSBytes, BudgetCPUPercent: budgetCPUPercent}
	if rep, err := inv.CollectAll(ctx); err == nil {
		res.InventoryBytes = proto.Size(rep)
	}
	start := cpuSeconds()
	deadline := time.Now().Add(dur)
	t := time.NewTicker(interval)
	defer t.Stop()
	for time.Now().Before(deadline) {
		samples, _ := collect.CollectAll(ctx, cs)
		b := enc.Encode(time.Now(), samples)
		if res.Rounds > 0 {
			res.BatchBytes = proto.Size(b)
		}
		res.Samples = len(samples)
		if res.Rounds%4 == 0 {
			_, _ = ps.Sample(ctx, 15)
			_ = sp.Append(enc.EncodeSelfContained(time.Now(), samples))
		}
		res.Rounds++
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	res.CPUSeconds = cpuSeconds() - start
	res.CPUPercentAt15s = 100 * res.CPUSeconds / (float64(res.Rounds) * nominalInterval.Seconds())
	res.PeakRSSBytes = peakRSS()
	res.WithinBudget = res.PeakRSSBytes <= budgetRSSBytes && res.CPUPercentAt15s <= budgetCPUPercent
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	if !res.WithinBudget {
		return fmt.Errorf("agent over budget: rss=%d MiB cpu=%.3f%%", res.PeakRSSBytes>>20, res.CPUPercentAt15s)
	}
	return nil
}
