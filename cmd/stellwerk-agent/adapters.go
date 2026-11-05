package main

import (
	"context"
	"sync"
	"time"

	"github.com/nobrain-soft/libremanager/internal/agent/collect"
	"github.com/nobrain-soft/libremanager/internal/agent/helperclient"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	helperv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/helper/v1"
)

// metricsAdapter implements runtime.MetricsSource over the collectors.
type metricsAdapter struct {
	mu         sync.Mutex
	collectors []collect.Collector
	enc        *collect.Encoder
}

func (m *metricsAdapter) Batch(ctx context.Context, now time.Time, live bool) (*agentv1.MetricsBatch, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	samples, err := collect.CollectAll(cctx, m.collectors)
	if len(samples) == 0 && err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if live {
		return m.enc.Encode(now, samples), nil
	}
	return m.enc.EncodeSelfContained(now, samples), nil
}

func (m *metricsAdapter) NewStream() {
	m.mu.Lock()
	m.enc.Reset()
	m.mu.Unlock()
}

// processAdapter implements runtime.ProcessSource.
type processAdapter struct{ s *collect.ProcSampler }

func (p processAdapter) Snapshot(ctx context.Context) (*agentv1.ProcessSnapshot, error) {
	return p.s.Sample(ctx, 15)
}

// privilegedAdapter exposes helper reads to inventory and checks.
type privilegedAdapter struct{ h *helperclient.Client }

func (p privilegedAdapter) read(ctx context.Context, k helperv1.PrivilegedKind) (*helperv1.PrivilegedData, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return p.h.ReadPrivileged(cctx, k)
}

func (p privilegedAdapter) SudoRules(ctx context.Context) ([]string, error) {
	d, err := p.read(ctx, helperv1.PrivilegedKind_PRIVILEGED_KIND_SUDOERS)
	if err != nil {
		return nil, err
	}
	return d.GetSudoRules(), nil
}

func (p privilegedAdapter) SocketOwners(ctx context.Context) (map[string]string, error) {
	d, err := p.read(ctx, helperv1.PrivilegedKind_PRIVILEGED_KIND_SOCKET_OWNERS)
	if err != nil {
		return nil, err
	}
	return d.GetValues(), nil
}

func (p privilegedAdapter) ShadowFlags(ctx context.Context) ([]string, []string, error) {
	d, err := p.read(ctx, helperv1.PrivilegedKind_PRIVILEGED_KIND_SHADOW_FLAGS)
	if err != nil {
		return nil, nil, err
	}
	return d.GetEmptyPasswordUsers(), d.GetLockedUsers(), nil
}

func (p privilegedAdapter) SshdConfig(ctx context.Context) (map[string]string, error) {
	d, err := p.read(ctx, helperv1.PrivilegedKind_PRIVILEGED_KIND_SSHD_EFFECTIVE_CONFIG)
	if err != nil {
		return nil, err
	}
	return d.GetValues(), nil
}
