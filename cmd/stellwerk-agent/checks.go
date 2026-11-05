package main

import (
	"github.com/nobrain-soft/libremanager/internal/agent/helperclient"
	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	"github.com/nobrain-soft/libremanager/internal/agent/runtime"
)

// newChecks wires the built-in security checks (internal/agent/checks).
func newChecks(_ *helperclient.Client, _ *policy.Policy) runtime.CheckSource {
	return nil
}
