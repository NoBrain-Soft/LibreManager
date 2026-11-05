//go:build !linux

package osutil

import "os/exec"

func setProcAttr(*exec.Cmd) {}
