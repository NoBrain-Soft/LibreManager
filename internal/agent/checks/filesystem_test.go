package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// binTree builds a root with files (path -> mode) and a merged-usr /bin
// symlink.
func binTree(t *testing.T, files map[string]os.FileMode) string {
	t.Helper()
	root := t.TempDir()
	for p, mode := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if mode.IsDir() {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(full, []byte("#!/bin/true\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(full)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode()&(os.ModeSetuid|os.ModeSetgid|0o777) != mode&(os.ModeSetuid|os.ModeSetgid|0o777) {
			t.Skipf("file system does not keep mode %v (got %v)", mode, st.Mode())
		}
	}
	if err := os.Symlink("usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestFilePermissions(t *testing.T) {
	base := map[string]os.FileMode{
		"usr/bin/passwd":       os.ModeSetuid | 0o755,
		"usr/bin/sudo":         os.ModeSetuid | 0o755,
		"usr/bin/crontab":      os.ModeSetgid | 0o755,
		"usr/bin/ls":           0o755,
		"usr/sbin/unix_chkpwd": os.ModeSetgid | 0o755,
		"usr/local/bin/tool":   0o755,
	}
	with := func(extra map[string]os.FileMode) map[string]os.FileMode {
		m := map[string]os.FileMode{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	t.Run("clean", func(t *testing.T) {
		r := runCheck(t, Env{Root: binTree(t, base)}, "FS-001")
		expectStatus(t, r, PASS)
		expectEvidence(t, r, "setuid_setgid", "4")
		// /bin -> usr/bin is scanned once.
		expectEvidence(t, r, "entries_scanned", "6")
	})
	t.Run("unexpected setuid", func(t *testing.T) {
		r := runCheck(t, Env{Root: binTree(t, with(map[string]os.FileMode{
			"usr/local/sbin/backdoor": os.ModeSetuid | 0o755,
			"usr/bin/helper":          os.ModeSetgid | 0o750,
		}))}, "FS-001")
		expectStatus(t, r, WARN)
		expectEvidence(t, r, "unexpected_setuid_setgid_paths", "/usr/bin/helper, /usr/local/sbin/backdoor")
		expectEvidence(t, r, "unexpected_setuid_setgid", "2")
	})
	t.Run("world-writable", func(t *testing.T) {
		r := runCheck(t, Env{Root: binTree(t, with(map[string]os.FileMode{
			"usr/local/bin/ww":     0o777,
			"usr/local/bin/sub":    os.ModeDir | 0o777,
			"usr/local/bin/sub/ok": 0o755,
		}))}, "FS-001")
		expectStatus(t, r, FAIL)
		expectEvidence(t, r, "world_writable_paths", "/usr/local/bin/sub, /usr/local/bin/ww")
	})
	t.Run("symlinks are not followed", func(t *testing.T) {
		root := binTree(t, base)
		if err := os.Symlink("/tmp", filepath.Join(root, "usr/bin/tmp-link")); err != nil {
			t.Fatal(err)
		}
		expectStatus(t, runCheck(t, Env{Root: root}, "FS-001"), PASS)
	})
	t.Run("entry cap", func(t *testing.T) {
		root := binTree(t, base)
		for i := range maxFSEntries + 10 {
			if err := os.WriteFile(filepath.Join(root, "usr/bin", fmt.Sprintf("f%05d", i)), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		r := runCheck(t, Env{Root: root}, "FS-001")
		expectEvidence(t, r, "truncated", "true")
		expectEvidence(t, r, "entries_scanned", fmt.Sprint(maxFSEntries))
	})
	t.Run("no system dirs", func(t *testing.T) {
		expectStatus(t, runCheck(t, Env{Root: t.TempDir()}, "FS-001"), ERROR)
	})
}

func TestTmpMounts(t *testing.T) {
	r := runCheck(t, Env{ProcRoot: td(t, "proc/hardened")}, "FS-002")
	expectStatus(t, r, PASS)
	expectEvidence(t, r, "source", "/proc/1/mountinfo")
	expectEvidence(t, r, "/var/tmp", "ext4 rw,nosuid,nodev,noexec,relatime")

	// The topmost /tmp mount lacks nosuid; /var/tmp is not separate.
	r = runCheck(t, Env{ProcRoot: td(t, "proc/weak")}, "FS-002")
	expectStatus(t, r, FAIL)
	if !strings.Contains(r.GetSummary(), "/tmp lacks nosuid") {
		t.Fatalf("summary %q", r.GetSummary())
	}
	expectEvidence(t, r, "/var/tmp", "not a separate mount")

	r = runCheck(t, Env{ProcRoot: td(t, "proc/selfonly")}, "FS-002")
	expectStatus(t, r, WARN)
	expectEvidence(t, r, "source", "/proc/self/mountinfo")

	expectStatus(t, runCheck(t, Env{ProcRoot: t.TempDir()}, "FS-002"), ERROR)
}

func TestParseMountinfo(t *testing.T) {
	data, err := os.ReadFile(td(t, "proc/hardened/1/mountinfo"))
	if err != nil {
		t.Fatal(err)
	}
	ms := parseMountinfo(append(data, []byte("short line\n1 2 3 4 5 6 7 8\n")...))
	if len(ms) != 6 {
		t.Fatalf("%d mounts: %+v", len(ms), ms)
	}
	if m, ok := lastMount(ms, "/mnt/my disk"); !ok || m.fstype != "ext4" {
		t.Fatalf("escaped mount point: %+v %v", m, ok)
	}
	if got := unescapeMount(`a\040b\134c\0`); got != `a b\c\0` {
		t.Fatalf("unescape: %q", got)
	}
}
