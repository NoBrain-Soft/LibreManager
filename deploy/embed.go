// Package deploy embeds deployment templates that the server renders.
package deploy

import _ "embed"

// AgentInstallTemplate is the agent install script template.
//
//go:embed agent-install.sh.tmpl
var AgentInstallTemplate string
