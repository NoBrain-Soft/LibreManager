package main

import (
	"context"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/nobrain-soft/libremanager/internal/agent/checks"
	"github.com/nobrain-soft/libremanager/internal/agent/helperclient"
	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	"github.com/nobrain-soft/libremanager/internal/common/version"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// checkSource runs the built-in security checks (internal/agent/checks).
// Privileged data (shadow flags, sshd -T, sudoers) comes from the helper.
type checkSource struct {
	hc *helperclient.Client
	// updates returns the last pending-updates report (PKG-001/002).
	updates atomic.Pointer[func() *agentv1.UpdatesReport]
}

func newChecks(hc *helperclient.Client, _ *policy.Policy) *checkSource {
	return &checkSource{hc: hc}
}

func (c *checkSource) setUpdates(f func() *agentv1.UpdatesReport) { c.updates.Store(&f) }

func (c *checkSource) Run(ctx context.Context, ids []string) *agentv1.CheckReport {
	env := checks.Env{
		Privileged:   checks.HelperPrivileged(c.hc),
		AgentVersion: version.Version,
		// The agent unit allows the read-only adjtimex syscall explicitly.
		Adjtimex: unix.Adjtimex,
	}
	if f := c.updates.Load(); f != nil {
		env.Updates = (*f)()
	}
	return checks.Run(ctx, env, ids)
}
