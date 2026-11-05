// Package runner is the helper's only way to start external programs
// (CLAUDE.md rule 5): programs are named, not pathed, and resolved from a
// fixed list of system directories; arguments are passed as an array to
// exec (never through a shell); the environment is minimal.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Cmd describes one program invocation.
type Cmd struct {
	// Name is a bare program name such as "apt-get"; never a path.
	Name string
	Args []string
	// Env holds extra KEY=VALUE entries added to the minimal base env.
	Env []string
	// Stdout/Stderr receive output; nil discards it.
	Stdout io.Writer
	Stderr io.Writer
}

// Runner executes commands. Run returns the exit code; a non-zero exit is
// not an error. err is set when the program could not be resolved or
// started, or when ctx ended before the program exited (err wraps ctx.Err()).
type Runner interface {
	Run(ctx context.Context, c Cmd) (exitCode int, err error)
	// Available reports whether the named program can be resolved.
	Available(name string) bool
}

// ErrNotFound is returned when a program is not in any trusted directory.
var ErrNotFound = errors.New("runner: program not found in trusted directories")

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,63}$`)

// DefaultDirs returns the trusted program directories in lookup order.
func DefaultDirs() []string { return []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} }

// basePath is the PATH handed to children (package scripts need one).
const basePath = "PATH=/usr/sbin:/usr/bin:/sbin:/bin"

// Exec is the production Runner.
type Exec struct {
	// Dirs defaults to DefaultDirs().
	Dirs []string
	// KillGrace is the time between SIGTERM (on ctx end) and SIGKILL. Default 30 s.
	KillGrace time.Duration
}

// Resolve returns the absolute path of name. The file (after following
// symlinks) must be a regular executable owned by root and not writable by
// group or others.
func (e *Exec) Resolve(name string) (string, error) {
	if !validName.MatchString(name) {
		return "", fmt.Errorf("runner: invalid program name %q", name)
	}
	dirs := e.Dirs
	if len(dirs) == 0 {
		dirs = DefaultDirs()
	}
	for _, d := range dirs {
		p := filepath.Join(d, name)
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
			continue
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Uid != 0 || st.Mode().Perm()&0o022 != 0 {
			return "", fmt.Errorf("runner: refusing %s: not root-owned or writable by others", p)
		}
		return p, nil
	}
	return "", fmt.Errorf("%w: %s", ErrNotFound, name)
}

// Available implements Runner.
func (e *Exec) Available(name string) bool {
	_, err := e.Resolve(name)
	return err == nil
}

// Run implements Runner.
func (e *Exec) Run(ctx context.Context, c Cmd) (int, error) {
	p, err := e.Resolve(c.Name)
	if err != nil {
		return -1, err
	}
	cmd := exec.CommandContext(ctx, p, c.Args...) //nolint:gosec // resolved from trusted dirs, argv array
	cmd.Env = append([]string{basePath, "LC_ALL=C"}, c.Env...)
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = c.Stdout, c.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// Terminate the whole process group (e.g. apt-get and its dpkg).
		return unix.Kill(-cmd.Process.Pid, unix.SIGTERM)
	}
	cmd.WaitDelay = e.KillGrace
	if cmd.WaitDelay <= 0 {
		cmd.WaitDelay = 30 * time.Second
	}
	err = cmd.Run()
	code := 0
	if st := cmd.ProcessState; st != nil {
		code = st.ExitCode()
		if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			code = 128 + int(ws.Signal())
		}
	}
	if ctx.Err() != nil {
		return code, fmt.Errorf("runner: %s: %w", c.Name, ctx.Err())
	}
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return -1, fmt.Errorf("runner: %s: %w", c.Name, err)
	}
	return code, nil
}

// LimitedBuffer collects up to Max bytes and silently drops the rest. (It
// deliberately does not embed bytes.Buffer: a promoted ReadFrom would let
// io.Copy bypass the limit.)
type LimitedBuffer struct {
	buf       bytes.Buffer
	Max       int
	Truncated bool
}

// Write implements io.Writer; it never fails so the child is not killed by EPIPE.
func (b *LimitedBuffer) Write(p []byte) (int, error) {
	room := b.Max - b.buf.Len()
	if room < len(p) {
		b.Truncated = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	b.buf.Write(p)
	return len(p), nil
}

// Bytes returns the collected data.
func (b *LimitedBuffer) Bytes() []byte { return b.buf.Bytes() }

// Output runs c and returns its stdout (at most max bytes, more is an
// error) and exit code. Stderr goes to c.Stderr (nil discards it).
func Output(ctx context.Context, r Runner, c Cmd, max int) ([]byte, int, error) {
	out := &LimitedBuffer{Max: max}
	c.Stdout = out
	code, err := r.Run(ctx, c)
	if err != nil {
		return nil, code, err
	}
	if out.Truncated {
		return nil, code, fmt.Errorf("runner: %s: output exceeds %d bytes", c.Name, max)
	}
	return out.Bytes(), code, nil
}
