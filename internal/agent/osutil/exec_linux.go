//go:build linux

package osutil

import (
	"os/exec"
	"syscall"
)

// setProcAttr makes sure children die with the agent.
func setProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
