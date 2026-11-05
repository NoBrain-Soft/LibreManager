package checks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// CommandRunner runs a read-only program and returns its stdout and exit
// code. A non-zero exit is not an error; err is set only when the program
// could not be found (wrapping ErrCommandNotFound), could not be started,
// timed out or produced too much output. Implementations must pass args as
// an argv array — never through a shell.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (stdout []byte, exitCode int, err error)
}

// Errors returned by ExecRunner.
var (
	ErrCommandNotFound   = errors.New("checks: command not found")
	ErrCommandNotAllowed = errors.New("checks: command not allowed")
	ErrOutputTooLarge    = errors.New("checks: command output too large")
)

const (
	defaultCommandTimeout = 5 * time.Second
	defaultMaxOutput      = 1 << 20
)

// readOnlyProgram is the closed set of programs checks may start. All of
// them are invoked with read-only subcommands only (is-active, is-enabled,
// list-units, show, tracking, list ruleset, --enabled).
func readOnlyProgram(name string) bool {
	switch name {
	case "systemctl", "timedatectl", "chronyc", "nft", "getenforce", "aa-status":
		return true
	}
	return false
}

// ExecRunner is the production CommandRunner: programs come from a fixed
// list of system directories and must not be writable by group or others;
// the child gets a minimal environment, no stdin, its own process group
// (killed on timeout) and a capped stdout.
type ExecRunner struct {
	// Dirs defaults to /usr/bin, /usr/sbin, /bin, /sbin.
	Dirs []string
	// Timeout per command (default 5 s).
	Timeout time.Duration
	// MaxOutput caps stdout in bytes (default 1 MiB); more is an error.
	MaxOutput int
}

func (e *ExecRunner) resolve(name string) (string, error) {
	if !readOnlyProgram(name) {
		return "", fmt.Errorf("%w: %q", ErrCommandNotAllowed, name)
	}
	dirs := e.Dirs
	if len(dirs) == 0 {
		dirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"}
	}
	for _, d := range dirs {
		p := filepath.Join(d, name)
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
			continue
		}
		if st.Mode().Perm()&0o022 != 0 {
			return "", fmt.Errorf("checks: refusing %s: writable by group or others", p)
		}
		return p, nil
	}
	return "", fmt.Errorf("%w: %s", ErrCommandNotFound, name)
}

// Run implements CommandRunner.
func (e *ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	path, err := e.resolve(name)
	if err != nil {
		return nil, -1, err
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = defaultCommandTimeout
	}
	maxOut := e.MaxOutput
	if maxOut <= 0 {
		maxOut = defaultMaxOutput
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out := &cappedBuffer{max: maxOut}
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // fixed program set from trusted dirs, argv array
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}
	cmd.Dir = "/"
	cmd.Stdout = out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return unix.Kill(-cmd.Process.Pid, unix.SIGKILL) }
	cmd.WaitDelay = time.Second
	err = cmd.Run()
	if ctx.Err() != nil {
		return nil, -1, fmt.Errorf("checks: %s: %w", name, ctx.Err())
	}
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return nil, -1, fmt.Errorf("checks: %s: %w", name, err)
	}
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	if out.truncated {
		return nil, code, fmt.Errorf("%w: %s", ErrOutputTooLarge, name)
	}
	return out.buf.Bytes(), code, nil
}

// cappedBuffer keeps up to max bytes and drops the rest without failing
// the write, so the child is not killed by EPIPE.
type cappedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room < len(p) {
		b.truncated = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	b.buf.Write(p)
	return len(p), nil
}
