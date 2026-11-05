package runner

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveRejectsPathsAndBadNames(t *testing.T) {
	e := &Exec{}
	for _, n := range []string{"", "/bin/true", "../true", "bin/true", "-x", "TRUE", "sh -c", "a\x00b", strings.Repeat("a", 65)} {
		if _, err := e.Resolve(n); err == nil {
			t.Errorf("Resolve(%q) succeeded", n)
		}
	}
	if _, err := e.Resolve("definitely-not-a-program"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestResolveRejectsUntrustedBinary(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name  string
		mode  os.FileMode
		chown bool
	}{
		{"groupwritable", 0o775, false},
		{"worldwritable", 0o757, false},
		{"notroot", 0o755, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name)
			if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, tc.mode); err != nil {
				t.Fatal(err)
			}
			if tc.chown && os.Geteuid() == 0 {
				if err := os.Chown(p, 65534, 65534); err != nil {
					t.Skip("cannot chown:", err)
				}
			}
			if !tc.chown && os.Geteuid() != 0 {
				t.Skip("file is not root-owned anyway")
			}
			e := &Exec{Dirs: []string{dir}}
			if _, err := e.Resolve(tc.name); err == nil || errors.Is(err, ErrNotFound) {
				t.Fatalf("err = %v, want refusal", err)
			}
		})
	}
}

func TestRunExitCodesAndOutput(t *testing.T) {
	e := &Exec{}
	if !e.Available("true") {
		t.Skip("no /usr/bin/true")
	}
	ctx := context.Background()
	if code, err := e.Run(ctx, Cmd{Name: "true"}); err != nil || code != 0 {
		t.Fatalf("true: %d %v", code, err)
	}
	if code, err := e.Run(ctx, Cmd{Name: "false"}); err != nil || code != 1 {
		t.Fatalf("false: %d %v", code, err)
	}
	// Arguments are passed verbatim, never interpreted by a shell.
	out, code, err := Output(ctx, e, Cmd{Name: "echo", Args: []string{"$(id)", ";", "|"}}, 1024)
	if err != nil || code != 0 {
		t.Fatalf("echo: %d %v", code, err)
	}
	if got := string(out); got != "$(id) ; |\n" {
		t.Fatalf("echo output %q", got)
	}
	// Environment is minimal.
	out, _, err = Output(ctx, e, Cmd{Name: "env", Env: []string{"DEBIAN_FRONTEND=noninteractive"}}, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(out)); len(got) != 3 || got[2] != "DEBIAN_FRONTEND=noninteractive" {
		t.Fatalf("env = %q", got)
	}
	if _, _, err := Output(ctx, e, Cmd{Name: "echo", Args: []string{strings.Repeat("x", 100)}}, 10); err == nil {
		t.Fatal("expected oversize error")
	}
}

func TestRunCancel(t *testing.T) {
	e := &Exec{KillGrace: time.Second}
	if !e.Available("sleep") {
		t.Skip("no sleep")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := e.Run(ctx, Cmd{Name: "sleep", Args: []string{"30"}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("cancel did not stop the child")
	}
}

func TestLimitedBuffer(t *testing.T) {
	b := &LimitedBuffer{Max: 4}
	n, err := b.Write([]byte("abcdef"))
	if n != 6 || err != nil || !bytes.Equal(b.Bytes(), []byte("abcd")) || !b.Truncated {
		t.Fatalf("n=%d err=%v buf=%q trunc=%v", n, err, b.Bytes(), b.Truncated)
	}
}
