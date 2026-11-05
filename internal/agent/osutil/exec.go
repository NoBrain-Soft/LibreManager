// Package osutil holds small, dependency-free helpers shared by the agent's
// unprivileged collectors: command execution with argument vectors (never a
// shell), bounded file reads, text sanitizing for protobuf string fields, and
// parsers for mountinfo and passwd/group files.
package osutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CommandRunner runs a fixed program with an argument vector. Implementations
// must never pass arguments through a shell. On a non-zero exit status the
// captured stdout is returned together with an error wrapping
// *exec.ExitError, because tools like `systemctl is-active` report their
// answer through both.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Errors returned by ExecRunner.
var (
	ErrOutputTooLarge = errors.New("osutil: command output exceeds limit")
	ErrNotFound       = errors.New("osutil: executable not found")
)

// Defaults for ExecRunner.
const (
	DefaultCommandTimeout = 30 * time.Second
	DefaultMaxOutput      = 16 << 20
	maxStderr             = 4 << 10
)

// DefaultSearchPath is where ExecRunner looks up bare program names. $PATH is
// deliberately ignored.
var DefaultSearchPath = []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"}

// commandEnv is the complete environment for child processes: C locale and
// no colors, pagers or hyperlinks from systemd tools.
var commandEnv = []string{
	"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
	"LANG=C",
	"LC_ALL=C",
	"TERM=dumb",
	"SYSTEMD_COLORS=0",
	"SYSTEMD_PAGER=",
	"SYSTEMD_LESS=",
	"SYSTEMD_URLIFY=0",
	"PAGER=cat",
}

// ExecRunner implements CommandRunner with exec.CommandContext.
type ExecRunner struct {
	// Timeout bounds each command (default DefaultCommandTimeout).
	Timeout time.Duration
	// MaxOutput bounds stdout in bytes (default DefaultMaxOutput). Larger
	// output kills the command and returns ErrOutputTooLarge.
	MaxOutput int
	// SearchPath overrides DefaultSearchPath.
	SearchPath []string
}

// Run implements CommandRunner.
func (r ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	path, err := r.lookPath(name)
	if err != nil {
		return nil, err
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultCommandTimeout
	}
	limit := r.MaxOutput
	if limit <= 0 {
		limit = DefaultMaxOutput
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = commandEnv
	cmd.Dir = "/"
	stdout := &limitWriter{max: limit, onOverflow: cancel}
	stderr := &limitWriter{max: maxStderr}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = 2 * time.Second
	setProcAttr(cmd)

	err = cmd.Run()
	if stdout.overflow {
		return nil, fmt.Errorf("osutil: run %s: %w (%d bytes)", name, ErrOutputTooLarge, limit)
	}
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return stdout.buf.Bytes(), fmt.Errorf("osutil: run %s: timed out after %s: %w", name, timeout, err)
		}
		msg := strings.TrimSpace(Clean(stderr.buf.String(), 512))
		if msg != "" {
			return stdout.buf.Bytes(), fmt.Errorf("osutil: run %s: %w: %s", name, err, msg)
		}
		return stdout.buf.Bytes(), fmt.Errorf("osutil: run %s: %w", name, err)
	}
	return stdout.buf.Bytes(), nil
}

func (r ExecRunner) lookPath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("osutil: empty command: %w", ErrNotFound)
	}
	if strings.ContainsRune(name, '/') {
		if !filepath.IsAbs(name) || filepath.Clean(name) != name {
			return "", fmt.Errorf("osutil: command path %q must be absolute and clean: %w", name, ErrNotFound)
		}
		if isExecutable(name) {
			return name, nil
		}
		return "", fmt.Errorf("osutil: %s: %w", name, ErrNotFound)
	}
	dirs := r.SearchPath
	if dirs == nil {
		dirs = DefaultSearchPath
	}
	for _, d := range dirs {
		p := filepath.Join(d, name)
		if isExecutable(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("osutil: %s: %w", name, ErrNotFound)
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// limitWriter buffers up to max bytes. Excess output is discarded (so the
// child never blocks on a full pipe). With onOverflow set, exceeding the
// limit marks the output as invalid and calls onOverflow once (to kill the
// child); without it the output is silently truncated (used for stderr).
type limitWriter struct {
	buf        bytes.Buffer
	max        int
	full       bool
	overflow   bool
	onOverflow func()
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.full {
		return len(p), nil
	}
	if room := w.max - w.buf.Len(); len(p) > room {
		w.full = true
		if w.onOverflow != nil {
			w.overflow = true
			w.onOverflow()
			return len(p), nil
		}
		w.buf.Write(p[:room])
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}
