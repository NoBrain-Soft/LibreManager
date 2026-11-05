package checks

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// linkProgram makes an allowed program name point at a real binary (e.g.
// "systemctl" -> /bin/echo), so ExecRunner can be exercised without the
// real tools.
func linkProgram(t *testing.T, name, target string) string {
	t.Helper()
	real, err := exec.LookPath(target)
	if err != nil {
		t.Skipf("%s not available", target)
	}
	// Multi-call binaries (busybox, uutils) dispatch on argv[0] and would
	// not behave like target under another name.
	if resolved, err := filepath.EvalSymlinks(real); err != nil || filepath.Base(resolved) != target {
		t.Skipf("%s is not a standalone binary", target)
	}
	if st, err := os.Stat(real); err != nil || st.Mode().Perm()&0o022 != 0 {
		t.Skipf("%s is writable by group/others", real)
	}
	dir := t.TempDir()
	if err := os.Symlink(real, filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestExecRunner(t *testing.T) {
	ctx := context.Background()

	t.Run("not allowed", func(t *testing.T) {
		for _, name := range []string{"sh", "bash", "rm", "../systemctl", "/usr/bin/systemctl", "sshd"} {
			if _, _, err := (&ExecRunner{}).Run(ctx, name, "-c", "id"); !errors.Is(err, ErrCommandNotAllowed) {
				t.Errorf("%q: %v", name, err)
			}
		}
	})
	t.Run("not found", func(t *testing.T) {
		if _, _, err := (&ExecRunner{Dirs: []string{t.TempDir()}}).Run(ctx, "systemctl", "is-active"); !errors.Is(err, ErrCommandNotFound) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("argv and exit code", func(t *testing.T) {
		dir := linkProgram(t, "systemctl", "echo")
		out, code, err := (&ExecRunner{Dirs: []string{dir}}).Run(ctx, "systemctl", "is-active", "--", "a b.service", "$(id)")
		if err != nil || code != 0 || string(out) != "is-active -- a b.service $(id)\n" {
			t.Fatalf("out=%q code=%d err=%v", out, code, err)
		}
		dir = linkProgram(t, "chronyc", "false")
		if _, code, err := (&ExecRunner{Dirs: []string{dir}}).Run(ctx, "chronyc", "tracking"); err != nil || code == 0 {
			t.Fatalf("non-zero exit: code=%d err=%v", code, err)
		}
	})
	t.Run("minimal environment", func(t *testing.T) {
		t.Setenv("STELLWERK_SECRET_TEST", "leak")
		dir := linkProgram(t, "timedatectl", "env")
		out, _, err := (&ExecRunner{Dirs: []string{dir}}).Run(ctx, "timedatectl")
		if err != nil || strings.Contains(string(out), "STELLWERK_SECRET_TEST") || !strings.Contains(string(out), "LC_ALL=C") {
			t.Fatalf("env: %q %v", out, err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		dir := linkProgram(t, "nft", "sleep")
		start := time.Now()
		_, _, err := (&ExecRunner{Dirs: []string{dir}, Timeout: 100 * time.Millisecond}).Run(ctx, "nft", "10")
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
			t.Fatalf("err = %v after %v", err, time.Since(start))
		}
	})
	t.Run("output cap", func(t *testing.T) {
		dir := linkProgram(t, "getenforce", "seq")
		_, _, err := (&ExecRunner{Dirs: []string{dir}, MaxOutput: 1024}).Run(ctx, "getenforce", "100000")
		if !errors.Is(err, ErrOutputTooLarge) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("writable program refused", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "aa-status")
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, _, err := (&ExecRunner{Dirs: []string{dir}}).Run(ctx, "aa-status"); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Fatalf("err = %v", err)
		}
	})
}
